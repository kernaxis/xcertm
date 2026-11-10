#!/usr/bin/env python3
"""Collect runtime dependency licenses in a build directory."""

import argparse
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = "./cmd/xcertm"
ALLOWED = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}


def run(*args):
    return subprocess.check_output(
        args, cwd=ROOT, env={**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"}, text=True
    )


def json_stream(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        yield value


def is_notice(path):
    return path.is_file() and path.name.lower().startswith(
        ("license", "licence", "notice", "copying", "copyright", "authors", "patents")
    )


def generate(output, go, scanner):
    output = output.resolve()
    if output == ROOT or output in ROOT.parents:
        raise ValueError("Output must be a build directory, not the repository or an ancestor")
    output.mkdir(parents=True, exist_ok=True)
    run(go, "mod", "verify")
    packages = list(json_stream(run(go, "list", "-deps", "-json", ENTRYPOINT)))
    modules = {p["Module"]["Path"]: p["Module"] for p in packages if p.get("Module", {}).get("Version")}
    own = next(p["Module"]["Path"] for p in packages if p.get("Module", {}).get("Main"))
    with tempfile.TemporaryDirectory(prefix=".legal-", dir=output) as scratch:
        stage = Path(scratch)
        template = stage / "report.tmpl"
        template.write_text("{{range .}}{{.Name}}\t{{.LicenseName}}\t{{.LicensePath}}\n{{end}}")
        report = run(scanner, "report", ENTRYPOINT, "--ignore", own, "--template", str(template))
        families = {name: set() for name in modules}
        texts = {}
        for package, license_id, filename in csv.reader(io.StringIO(report), delimiter="\t"):
            name = max(
                (name for name in modules if package == name or package.startswith(name + "/")), key=len
            )
            if license_id not in ALLOWED:
                raise ValueError(f"License compatibility requires review: {package}: {license_id}")
            module = modules[name]
            path = Path(filename)
            relative = path.relative_to(module["Dir"])
            texts[f"{name}@{module['Version']}/{relative}"] = path.read_text()
            families[name].add(license_id)
        missing = [name for name, ids in families.items() if not ids]
        if missing:
            raise ValueError(f"Incomplete runtime license inventory: {missing}")

        # Include module and compiled-package notices even when the classifier
        # selected a different file. In particular, YAML v3 includes MIT ports,
        # Apache-2.0 Go files and a separate NOTICE.
        for package in packages:
            module = package.get("Module", {})
            if not module.get("Version"):
                continue
            directory, base = Path(package["Dir"]), Path(module["Dir"])
            while True:
                for path in directory.iterdir():
                    if is_notice(path):
                        text = path.read_text()
                        texts[f"{module['Path']}@{module['Version']}/{path.relative_to(base)}"] = text
                        if module["Path"] == "go.yaml.in/yaml/v3" and "MIT License" in text and "Apache License" in text:
                            families[module["Path"]].update({"MIT", "Apache-2.0"})
                if directory == base:
                    break
                if base not in directory.parents:
                    raise ValueError(f"Package escaped module directory: {package['ImportPath']}")
                directory = directory.parent

        goroot = Path(run(go, "env", "GOROOT").strip())
        for filename in ("LICENSE", "PATENTS"):
            if (goroot / filename).is_file():
                texts[f"Go/{filename}"] = (goroot / filename).read_text()
        # Reviewed notices and complete license terms are shipped alongside
        # this generated inventory in the self-contained Markdown document.
        lines = ["Third-party redistribution materials", "Go toolchain: " + run(go, "env", "GOVERSION").strip(), "", "Additional terms and notices: THIRD_PARTY_NOTICES.md", "", "Runtime module inventory:"]
        for name, module in sorted(modules.items()):
            lines.append(f"{name}@{module['Version']} — {', '.join(sorted(families[name]))}")
        for label, text in sorted(texts.items()):
            lines.extend(["", "=" * 72, label, "=" * 72, text])
        (stage / "THIRD_PARTY_LICENSES.txt").write_text("\n".join(lines) + "\n")
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(ROOT / filename, stage / filename)
        for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_LICENSES.txt"):
            os.replace(stage / filename, output / filename)
    print(f"Generated redistribution notices for {len(modules)} runtime modules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--scanner", default="go-licenses")
    args = parser.parse_args()
    try:
        generate(args.output, args.go, args.scanner)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"License packaging failed: {error}\n")
