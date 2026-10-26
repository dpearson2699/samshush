"""Ensure another TV cannot inherit Frame controls without live validation."""

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_scripts  # noqa: E402
import frame  # noqa: E402
import startup  # noqa: E402


class ProfileTests(unittest.TestCase):
    def test_voice_audit_reports_capture_with_single_operand_readlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "123"
            (process / "fd").mkdir(parents=True)
            (process / "exe").symlink_to("/usr/bin/retained-acr")
            (process / "fd/4").symlink_to("/dev/snd/controlC0")
            (process / "fd/5").symlink_to("/dev/snd/pcmC0D7c")
            capture = root / "asound/card0/pcm7c/sub0"
            capture.mkdir(parents=True)
            (capture / "status").write_text("state: XRUN\nowner_pid   : 123\n")
            script = device_scripts.VOICE_AUDIT.replace("/proc/", str(root) + "/")
            result = subprocess.run(
                ["/bin/bash"],
                input=(
                    "id() { echo 0; }\n"
                    'readlink() { [[ $# == 1 ]] || return 1; command readlink "$@"; }\n'
                    + script
                ),
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "CAPTURE OWNER PID=123 EXE=/usr/bin/retained-acr", result.stdout
            )
            for target in ("/dev/snd/controlC0", "/dev/snd/pcmC0D7c"):
                self.assertIn(
                    "AUDIO_FD PID=123 EXE=/usr/bin/retained-acr TARGET=" + target,
                    result.stdout,
                )

    def test_managed_process_requires_exact_dll_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "123"
            proc.mkdir()
            expected = "/opt/usr/apps/voice/bin/Voice.dll"
            for executable, argument, accepted in (
                (expected, expected, True),
                ("/usr/bin/dotnet-loader", expected, True),
                ("/usr/bin/dotnet-launcher-inhouse", expected, True),
                ("/usr/bin/dotnet-loader", expected + ".other", False),
                ("/usr/bin/dotnet-loader", "/different/Voice.dll", False),
                ("/unrelated/program", expected, False),
            ):
                with self.subTest(executable=executable, argument=argument):
                    (proc / "exe").unlink(missing_ok=True)
                    (proc / "exe").symlink_to(executable)
                    (proc / "cmdline").write_bytes(argument.encode() + b"\0")
                    script = device_scripts.PROCESS_IDENTITY.replace(
                        "/proc/", str(root) + "/"
                    )
                    result = subprocess.run(
                        ["/bin/bash"],
                        input=script + f"matches_process 123 {expected}\n",
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_absence_check_finds_surviving_managed_apps(self):
        start = device_scripts.APP_CONTROL.index("verify_absent() {")
        end = device_scripts.APP_CONTROL.index("\n}\n", start) + 3
        verify_absent = device_scripts.APP_CONTROL[start:end]
        expected = "/opt/usr/apps/art/bin/ArtApp.dll"
        for runtime, survives in (
            ("/usr/bin/dotnet-launcher-inhouse", True),
            ("/usr/bin/dotnet-loader", True),
            ("/unrelated/program", False),
        ):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                proc = root / "proc" / "123"
                proc.mkdir(parents=True)
                (proc / "exe").symlink_to(runtime)
                (proc / "cmdline").write_bytes(expected.encode() + b"\0")
                (root / "before.tsv").write_text(f"art\tfalse\t123\t{expected}\n")
                script = (device_scripts.PROCESS_IDENTITY + verify_absent).replace(
                    "/proc/", str(root / "proc") + "/"
                )
                result = subprocess.run(
                    ["/bin/bash"],
                    input=f"STATE={root}\nstage={root}\n{script}verify_absent\n",
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode != 0, survives, result.stdout)
                self.assertEqual("SURVIVING MANAGED APP" in result.stdout, survives)

    def test_identity_and_preimage_drift_stop_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "os-release"
            product = root / "prd_info.ini"
            component = root / "voice"
            marker = root / "changed"
            component.write_bytes(b"original")
            policy = {
                "build": "tested-build",
                "device_identity": {
                    "firmware_family": "tested-family",
                    "software_version": "tested-version",
                    "architecture": "armv7l",
                },
                "preimages": {str(component): hashlib.sha256(b"original").hexdigest()},
            }
            guard = (
                frame.device_identity(policy)
                .replace("/etc/os-release", str(release))
                .replace("/etc/prd_info.ini", str(product))
            )
            guard += frame.preimages(policy, [str(component)])
            guard += f"touch '{marker}'\n"
            for case in (
                "valid",
                "build",
                "family",
                "version",
                "architecture",
                "hash",
                "missing",
            ):
                with self.subTest(case=case):
                    marker.unlink(missing_ok=True)
                    release.write_text(
                        "BUILD_ID="
                        + ("other" if case == "build" else "tested-build")
                        + "\n"
                    )
                    product.write_text(
                        "Model="
                        + ("other" if case == "family" else "tested-family")
                        + ";\n"
                        + "Version="
                        + ("other" if case == "version" else "tested-version")
                        + ";\n"
                    )
                    component.write_bytes(b"changed" if case == "hash" else b"original")
                    if case == "missing":
                        component.unlink()
                    architecture = "other" if case == "architecture" else "armv7l"
                    result = subprocess.run(
                        ["/bin/bash"],
                        input=f"uname() {{ echo {architecture}; }}\n" + guard,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(
                        result.returncode == 0, case == "valid", result.stderr
                    )
                    self.assertEqual(marker.exists(), case == "valid")

    def test_s95c_trial_is_isolated_and_batch_requires_restoration_evidence(self):
        with patch.object(frame, "ACTIVE_PROFILE", "s95c-2220"):
            policy = frame.policy()
            trial = frame.render_trial()
            batch = frame.render_apps("apply")
            runtime = frame.base64.b64decode(
                frame.render("apply", "voice").split()[2]
            ).decode()
            for script in (trial, batch, runtime):
                subprocess.run(["/bin/bash", "-n"], input=script, text=True, check=True)
                self.assertNotIn("@@", script)
                self.assertIn(policy["build"], script)
            self.assertIn("Trial app must be idle", trial)
            self.assertIn("MODE=restore", trial)
            self.assertIn("restored.tsv", trial)
            self.assertNotIn(
                "STATE=/opt/usr/home/owner/share/frame-voice-apps-v2", trial
            )
            for script in (batch, runtime):
                self.assertIn(
                    policy["validation_trial"]["journal"] + "/verified", script
                )
            self.assertNotIn("virtual-mic-service.service", runtime)
            self.assertNotIn("com.samsung.tv.voiceid-service", batch)

    def test_s95c_rejects_unvalidated_runtime_scopes(self):
        with patch.object(frame, "ACTIVE_PROFILE", "s95c-2220"):
            for scope in ("certificates", "services", "both"):
                with self.subTest(scope=scope), self.assertRaises(ValueError):
                    frame.render("apply", scope)

    def test_s95c_boot_package_contains_only_assessed_scopes(self):
        import io
        import tarfile

        with patch.object(frame, "ACTIVE_PROFILE", "s95c-2220"):
            package = startup.bundle(frame.policy(), frame.render, frame.ASSETS)
            with tarfile.open(fileobj=io.BytesIO(package)) as archive:
                candidates = archive.extractfile("candidates").read().decode()
                script = archive.extractfile("wifi-presence.apply").read().decode()
            self.assertEqual(len(candidates.splitlines()), 3)
            self.assertIn("voice\t/run/frame-runtime-v1\tvoice", candidates)
            self.assertIn(
                "wifi-presence\t/run/frame-services-wifi-presence-v1", candidates
            )
            self.assertIn(
                "shell-preload\t/run/frame-services-shell-preload-v1", candidates
            )
            self.assertNotIn("certificates", candidates)
            decoded = frame.base64.b64decode(script.split()[2]).decode()
            self.assertIn(
                "03caae12e4fe516057da6d919d7e987953c991c5ad5add19e2a73697652bcd34",
                decoded,
            )
            self.assertIn("STATE=/run/frame-services-wifi-presence-v1", decoded)
            subprocess.run(["/bin/bash", "-n"], input=decoded, text=True, check=True)

    def test_service_groups_come_from_the_selected_profile(self):
        def run(profile, group):
            return subprocess.run(
                [
                    sys.executable,
                    str(frame.HERE / "frame.py"),
                    "--profile",
                    profile,
                    "services",
                    group,
                    "status",
                ],
                capture_output=True,
                text=True,
            )

        accepted = run("s95c-2220", "shell-preload")
        self.assertNotIn("invalid choice", accepted.stderr)
        self.assertIn("--tv is required", accepted.stderr)
        self.assertIn("invalid choice", run("frame", "shell-preload").stderr)

    def test_app_groups_come_from_the_selected_profile(self):
        def run(profile, group):
            return subprocess.run(
                [
                    sys.executable,
                    str(frame.HERE / "frame.py"),
                    "--profile",
                    profile,
                    "apps",
                    "status",
                    "--group",
                    group,
                ],
                capture_output=True,
                text=True,
            )

        accepted = run("s95c-2220", "art")
        self.assertIn("--tv is required", accepted.stderr)
        self.assertIn("invalid choice", run("s95c-2220", "gaming").stderr)
        self.assertIn("invalid choice", run("frame", "art").stderr)

    def test_s95c_shell_preload_pins_unit_preimages(self):
        with patch.object(frame, "ACTIVE_PROFILE", "s95c-2220"):
            units = frame.policy()["optional_controls"]["shell-preload"][
                "systemd_units"
            ]
            decoded = frame.base64.b64decode(
                frame.render("apply", "services", unit_group="shell-preload").split()[2]
            ).decode()
            for unit in units:
                self.assertIn(
                    frame.policy()["preimages"]["/usr/lib/systemd/system/" + unit],
                    decoded,
                )
            self.assertIn("STATE=/run/frame-services-shell-preload-v1", decoded)
            self.assertNotIn("org.tizen.menu.service", decoded)
            subprocess.run(["/bin/bash", "-n"], input=decoded, text=True, check=True)

    def test_s95c_art_group_pins_app_preimages_and_spares_ambient_mode(self):
        with patch.object(frame, "ACTIVE_PROFILE", "s95c-2220"):
            policy = frame.policy()
            apps = policy["optional_controls"]["art"]["application_ids"]
            self.assertEqual(apps, ["org.tizen.art-app", "com.samsung.tv.home.art"])
            script = frame.render_apps("apply", group="art")
            for app in apps:
                entry = policy["applications"][app]
                for path in (entry["executable"], entry["manifest"]):
                    self.assertIn(policy["preimages"][path] + "  " + path, script)
            self.assertIn("/opt/usr/home/owner/share/frame-apps-art-v1", script)
            self.assertIn(policy["validation_trial"]["journal"] + "/verified", script)
            self.assertNotIn("ambient-support", script)
            self.assertIn(
                policy["preimages"]["/usr/bin/dotnet-launcher-inhouse"]
                + "  /usr/bin/dotnet-launcher-inhouse",
                script,
            )
            subprocess.run(["/bin/bash", "-n"], input=script, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
