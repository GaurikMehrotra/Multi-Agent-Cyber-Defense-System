"""Audit tracked paths and reachable history for prohibited artifacts and obvious secrets."""

import re
import shutil
import subprocess  # nosec B404
from pathlib import PurePosixPath

GIT = shutil.which("git")
if GIT is None:
    raise SystemExit("git is required")

BAD_DIRS = {"data", "runtime", "artifacts", ".venv"}
BAD_SUFFIXES = {".pcap", ".pcapng", ".db", ".sqlite", ".sqlite3", ".pt", ".pkl", ".joblib"}


def git_output(args):
    return subprocess.check_output(args)  # nosec B603


def git_run(args, **kwargs):
    return subprocess.run(args, **kwargs)  # nosec B603


def verify():
    paths = git_output([GIT, "ls-files", "-z"]).decode().split("\0")
    history = git_run(
        [GIT, "rev-list", "--all"], text=True, capture_output=True, check=True
    ).stdout.splitlines()
    for commit in history:
        paths += git_output([GIT, "ls-tree", "-r", "--name-only", commit]).decode().splitlines()
    bad = []
    for name in set(paths):
        if not name:
            continue
        path = PurePosixPath(name)
        if (
            set(path.parts) & BAD_DIRS
            or path.suffix in BAD_SUFFIXES
            or (path.name.startswith(".env") and path.name != ".env.example")
        ):
            bad.append(name)
    if bad:
        raise SystemExit("Forbidden tracked paths: " + ", ".join(sorted(bad)))
    patterns = re.compile(
        rb"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----)"
    )
    objects = set()
    for commit in history:
        tree = git_output([GIT, "ls-tree", "-r", commit]).decode().splitlines()
        objects.update(line.split()[2] for line in tree if line.split()[1] == "blob")
    for name in paths:
        if name:
            from pathlib import Path

            if Path(name).is_file() and patterns.search(Path(name).read_bytes()):
                raise SystemExit("Possible secret in " + name)
    for obj in objects:
        if patterns.search(git_output([GIT, "cat-file", "blob", obj])):
            raise SystemExit("Possible secret in history object " + obj)
    print(
        f"Artifact and common-token checks passed ({len(set(paths))} paths, {len(history)} commits). This is not an exhaustive secret detector."
    )


if __name__ == "__main__":
    verify()
