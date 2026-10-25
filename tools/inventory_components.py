#!/usr/bin/env python3
"""Inventory inert firmware extraction; never contacts or modifies a TV."""

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "firmware/filesystems/T-RSMFAKUC-0090"
PLATFORM = BASE / "pltf_t/root"
DATA = BASE / "data_backup/root"


def relative(p):
    return str(p.resolve())


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, default=BASE)
    parser.add_argument(
        "--output", type=Path, default=ROOT / ".local/reports/components"
    )
    args = parser.parse_args()
    base_path = args.firmware_root.resolve()
    platform, data = base_path / "pltf_t/root", base_path / "data_backup/root"
    if not platform.is_dir() or not data.is_dir():
        parser.error("Platform and factory-data filesystem extractions are required")
    args.output.mkdir(parents=True, exist_ok=True)
    units = []
    for base in [
        platform / "usr/lib/systemd",
        platform / "etc/systemd",
        data / "usr/share/systemd",
        data / "share/systemd",
    ]:
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            row = {"path": relative(p), "name": p.name, "sha256": sha(p)}
            text = p.read_text(errors="replace")
            if p.name.endswith(".symlink-target"):
                row["link_target"] = text
            else:
                section = ""
                row["directives"] = []
                for number, raw in enumerate(text.splitlines(), 1):
                    line = raw.strip()
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1]
                    elif line and not line.startswith(("#", ";")) and "=" in line:
                        key, value = line.split("=", 1)
                        row["directives"].append(
                            {
                                "section": section,
                                "key": key.strip(),
                                "value": value.strip(),
                                "line": number,
                            }
                        )
            units.append(row)

    packages = []
    for base in [platform / "usr/share/packages", data / "share/packages"]:
        for p in sorted(base.glob("*.xml")):
            try:
                root = ET.parse(p).getroot()
            except ET.ParseError as error:
                raise ValueError(f"Invalid package XML: {p}") from error
            apps = []
            dependencies = []
            for node in root.iter():
                kind = node.tag.split("}")[-1]
                if kind in ("ui-application", "service-application"):
                    apps.append(dict(node.attrib))
                if kind == "dependency":
                    dependencies.append(
                        {
                            "kind": "dependency",
                            **node.attrib,
                            "value": (node.text or "").strip(),
                        }
                    )
                if kind == "requires":
                    dependencies.extend({"kind": "requires", **n.attrib} for n in node)
            packages.append(
                {
                    "path": relative(p),
                    "sha256": sha(p),
                    **root.attrib,
                    "applications": apps,
                    "dependencies": dependencies,
                }
            )

    inventory = {
        "firmware": "T-RSMFAKUC-0090 1301.0",
        "scope": "Offline static evidence; presence does not prove enabled or installed on the TV",
        "units_and_links": units,
        "packages": packages,
    }
    (args.output / "component-inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n"
    )

    selected = [
        "adagent-service.service",
        "pisa-service.service",
        "pisa-service.socket",
        "pisa-service.path",
        "media-analytics-service.service",
        "org.tizen.tv.media.analytics.service.busname",
        "issue_report_agent.service",
        "devicetracker.service",
        "abnormal_user_behavior.service",
        "emergency-log-transmitter.service",
        "data-service.service",
        "com.samsung.tv.context-aware-service.service",
        "reporterCA.service",
        "reporterCA.timer",
        "scs-agent.service",
        "ambient-ua-agent.service",
        "com.samsung.tv.farfieldvoice.service",
        "slive-provider-daemon.service",
        "slive-provider-daemon.path",
        "com.samsung.FCCallListener.busname",
        "bms.service",
    ]
    lines = [
        "# Firmware component evidence",
        "",
        "Generated from extracted files. Line numbers refer to original extracted files.",
        "",
    ]
    for name in selected:
        p = platform / "usr/lib/systemd/system" / name
        lines += ["## " + name, "", f"`{relative(p)}`", "", "```ini"]
        lines += [
            f"{i}: {line}"
            for i, line in enumerate(p.read_text().splitlines(), 1)
            if not line.startswith("#RPAC=")
        ]
        lines += ["```", "", "References in inventoried systemd files:", ""]
        for u in units:
            if u["name"] == name:
                continue
            if name in u.get("link_target", ""):
                lines.append(f"- `{u['path']}` → `{u['link_target']}`")
            for d in u.get("directives", []):
                if name in d["value"]:
                    lines.append(
                        f"- `{u['path']}:{d['line']}` — `{d['key']}={d['value']}`"
                    )
        lines += [""]

    for p in [
        data / "usr/apps/com.samsung.tv.pisa-service/bin/adagent-service",
        platform / "usr/bin/media-analytics-service",
        platform / "usr/bin/emergencyLogTransmitter",
        platform / "usr/bin/devicetracker",
    ]:
        if not p.exists():
            continue
        strings = re.findall(rb"[\x20-\x7e]{8,}", p.read_bytes())
        hits = [
            s.decode()
            for s in strings
            if not s.startswith(b"_Z")
            and re.search(
                rb"https?://|ClickTracking|AdEventTracking|uploadPeriod|upload request|loggingpolicy|AnalyticsServer",
                s,
            )
        ]
        lines += (
            [
                "## Binary evidence: " + p.name,
                "",
                f"`{relative(p)}`",
                "",
                f"SHA-256: `{sha(p)}`",
                "",
                "```text",
            ]
            + hits[:35]
            + ["```", ""]
        )
    (args.output / "component-evidence.md").write_text("\n".join(lines))
    print(
        json.dumps(
            {
                "unit_entries": len(units),
                "package_manifests": len(packages),
                "evidence_file": str(args.output / "component-evidence.md"),
            }
        )
    )


if __name__ == "__main__":
    main()
