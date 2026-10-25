"""Run boot installation/selection/recovery against isolated host fixtures."""

import hashlib
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import frame  # noqa: E402
import startup  # noqa: E402


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="samshush-startup-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.device = self.root / "device"
        for path in (
            "opt/etc",
            "opt/usr/share",
            "run",
            "usr/lib/systemd/system",
            "proc/sys/kernel/random",
            "etc",
            "stage",
        ):
            (self.device / path).mkdir(parents=True)
        self.original = b"echo original\n"
        self.original_hash = hashlib.sha256(self.original).hexdigest()
        self.hook = self.device / "opt/etc/parseinfo.sh"
        self.hook.write_bytes(self.original)
        self.hook.chmod(0o777)
        self.boot = self.device / startup.ROOT.lstrip("/")
        unit = self.device / "usr/lib/systemd/system/AT-HUB.service"
        unit.write_bytes(b"unit")
        self.unit_hash = hashlib.sha256(b"unit").hexdigest()
        (self.device / "etc/os-release").write_text("BUILD_ID=test\n")
        (self.device / "proc/sys/kernel/random/boot_id").write_text("boot-one\n")
        self.helper = self.root / "commands.py"
        self.helper.write_text("""import sys, pathlib, hashlib, shutil, os
name,args=sys.argv[1],sys.argv[2:]
if name=="id": print(0)
elif name=="stat":
 p=pathlib.Path(args[-1]); mode=p.stat().st_mode & 0o777
 print(f"0:0:{mode:o}" if args[1]=="%u:%g:%a" else f"0:{mode:o}")
elif name=="cp": shutil.copy2(args[-2], args[-1])
elif name=="sha256sum":
 if args and args[0]=="-c":
  for line in pathlib.Path(args[1]).read_text().splitlines():
   digest,name=line.split("  ",1)
   if hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()!=digest: sys.exit(1)
 else:
  data=pathlib.Path(args[-1]).read_bytes() if args else sys.stdin.buffer.read()
  print(hashlib.sha256(data).hexdigest()+"  "+(args[-1] if args else "-"))
elif name=="chsmack":
 if args[0]!="-a": print(args[0]+' access="_"')
elif name=="chown": pass
else: sys.exit(99)
""")
        for name in ("id", "stat", "cp", "sha256sum", "chsmack", "chown"):
            executable = self.bin / name
            executable.write_text(
                f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(self.helper))} {name} "$@"\n'
            )
            executable.chmod(0o700)
        self.policy = {
            "build": "test",
            "certificates": [],
            "voice_privacy": {"systemd_units": ["voice.service"]},
            "optional_controls": {"ads": {"systemd_units": ["ads.service"]}},
        }
        self.package = startup.bundle(
            self.policy, lambda action, scope, **kwargs: "true", BASE / "assets"
        )
        with tarfile.open(fileobj=io.BytesIO(self.package)) as archive:
            files = {
                m.name: self.script(archive.extractfile(m).read().decode()).encode()
                for m in archive.getmembers()
                if m.name != "SHA256SUMS"
            }
        files["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n"
            for name, data in files.items()
        ).encode()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
        self.package = output.getvalue()
        (self.device / "stage/startup.tar.gz").write_bytes(self.package)

    def script(self, text):
        # Redirect every device path, including embedded worker scripts, into the fixture.
        text = re.sub(
            r"/(?:opt|run|etc|usr/lib|proc)/",
            lambda m: str(self.device) + m.group(),
            text,
        )
        text = text.replace(startup.ORIGINAL_HASH, self.original_hash).replace(
            startup.UNIT_HASH, self.unit_hash
        )
        return text.replace(
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            f"export PATH={self.bin}:/usr/bin:/bin",
        )

    def run_shell(self, text):
        return subprocess.run(
            ["/bin/bash"],
            input=self.script(text),
            text=True,
            capture_output=True,
            env=os.environ | {"FRAME_STAGE": str(self.device / "stage")},
        )

    def action(self, action):
        return self.run_shell(
            startup.control(action, "test", hashlib.sha256(self.package).hexdigest())
        )

    def journal(
        self,
        name="frame-runtime-v1",
        scope="voice",
        unit="voice.service",
        complete=True,
    ):
        path = self.device / "run" / name
        path.mkdir(mode=0o700)
        (path / "scope").write_text(scope + "\n")
        (path / "units.tsv").write_text(unit + "\tactive\n")
        if complete:
            (path / "complete").touch()
        return path

    def install(self):
        self.journal()
        result = self.action("install")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_selects_only_applied_controls_and_removes_exact_original(self):
        self.install()
        self.assertEqual((self.boot / "enabled").read_text().split("\t")[0], "voice")
        self.assertNotIn("ads", (self.boot / "enabled").read_text())
        self.assertEqual((self.boot / "original").read_bytes(), self.original)
        result = self.action("remove")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.hook.read_bytes(), self.original)
        self.assertEqual(self.hook.stat().st_mode & 0o777, 0o777)
        self.assertFalse(self.boot.exists())
        self.assertTrue((self.device / "run/frame-runtime-v1/complete").exists())

    def test_rejects_no_applied_controls(self):
        result = self.action("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.hook.read_bytes(), self.original)
        self.assertFalse(self.boot.exists())

    def test_rejects_partial_or_different_scope_without_touching_hook(self):
        for complete, unit in ((False, "voice.service"), (True, "unreviewed.service")):
            with self.subTest(complete=complete):
                journal = self.journal(complete=complete, unit=unit)
                result = self.action("install")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.hook.read_bytes(), self.original)

                shutil.rmtree(journal)

    def test_build_drift_rejects_install(self):
        self.journal()
        (self.device / "etc/os-release").write_text("BUILD_ID=other\n")
        self.assertNotEqual(self.action("install").returncode, 0)
        self.assertEqual(self.hook.read_bytes(), self.original)

    def test_changed_hook_is_not_overwritten_on_remove(self):
        self.install()
        self.hook.write_text("changed")
        self.assertNotEqual(self.action("remove").returncode, 0)
        self.assertEqual(self.hook.read_text(), "changed")
        self.assertTrue((self.boot / "original").exists())

    def test_second_install_preserves_original_backup(self):
        self.install()
        self.assertNotEqual(self.action("install").returncode, 0)
        self.assertEqual((self.boot / "original").read_bytes(), self.original)

    def test_worker_skips_apply_with_complete_journal_and_records_failure(self):
        self.install()
        worker = startup.substitute(startup.COMMON + startup.WORKER, "test")
        result = self.run_shell(worker)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.device / "run/samshush-boot.result").read_text(), "boot-one 0\n"
        )
        (self.device / "etc/os-release").write_text("BUILD_ID=other\n")
        result = self.run_shell(worker)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            (self.device / "run/samshush-boot.result").read_text(), "boot-one 1\n"
        )
        self.assertNotIn(
            "STARTUP COMPLETE", (self.device / "run/samshush-boot.log").read_text()
        )

    def replace_installed(self, name, text):
        (self.boot / name).write_text(text)
        manifest = self.boot / "SHA256SUMS"
        names = [line.split("  ", 1)[1] for line in manifest.read_text().splitlines()]
        manifest.write_text(
            "".join(
                f"{hashlib.sha256((self.boot / name).read_bytes()).hexdigest()}  {name}\n"
                for name in names
            )
        )

    def test_worker_applies_once_after_boot_and_rejects_partial_apply(self):
        self.install()
        journal = self.device / "run/frame-runtime-v1"
        counter = self.root / "applies"
        self.replace_installed(
            "voice.apply",
            f"mkdir -m 700 {journal}\nprintf 'voice\\n' > {journal}/scope\nprintf 'voice.service\\tactive\\n' > {journal}/units.tsv\ntouch {journal}/complete\necho applied >> {counter}\n",
        )
        shutil.rmtree(journal)
        worker = startup.substitute(startup.COMMON + startup.WORKER, "test")
        for _ in range(2):
            result = self.run_shell(worker)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(counter.read_text(), "applied\n")
        shutil.rmtree(journal)
        self.replace_installed("voice.apply", "exit 7\n")
        result = self.run_shell(worker)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(
            (self.device / "run/samshush-boot.result").read_text(), "boot-one 7\n"
        )
        self.assertNotIn(
            "STARTUP COMPLETE", (self.device / "run/samshush-boot.log").read_text()
        )

    def test_bundle_scripts_have_valid_shell_and_short_interpreter_line(self):
        package = startup.bundle(frame.policy(), frame.render, frame.ASSETS)
        with tarfile.open(fileobj=io.BytesIO(package)) as archive:
            for member in archive.getmembers():
                if member.name in ("worker", "launch") or member.name.endswith(
                    (".apply", ".status")
                ):
                    subprocess.run(
                        ["/bin/bash", "-n"],
                        input=archive.extractfile(member).read(),
                        check=True,
                    )
        self.assertLess(len(startup.WRAPPER.encode()), 128)
        for action in ("install", "remove", "status", "run"):
            subprocess.run(
                ["/bin/bash", "-n"],
                input=startup.control(action, "test"),
                text=True,
                check=True,
            )
