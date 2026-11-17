"""Build the program archive and the two-part course submission."""

from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "submission"
PROJECT_NAME = "netsec-message-integrity-lab"


def build_submission() -> Path:
    sources = [ROOT / "main.py", ROOT / "README.md", ROOT / ".gitignore"]
    for directory in ("lab", "tests", "docs", "scripts"):
        sources.extend(
            path for path in (ROOT / directory).rglob("*")
            if path.is_file() and path.suffix in (".py", ".md", ".txt")
            and "__pycache__" not in path.parts
        )
    snapshot = {path.relative_to(ROOT).as_posix(): path.read_bytes() for path in sorted(sources)}
    report = snapshot["docs/experiment-report.md"]

    program_buffer = BytesIO()
    with ZipFile(program_buffer, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in snapshot.items():
            archive.writestr(f"{PROJECT_NAME}/{name}", content)
    program = program_buffer.getvalue()
    with ZipFile(BytesIO(program)) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("program archive integrity check failed")
        for name, expected in snapshot.items():
            if archive.read(f"{PROJECT_NAME}/{name}") != expected:
                raise RuntimeError(f"program archive content mismatch: {name}")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="build-", dir=OUTPUT) as temporary:
        staging = Path(temporary)
        (staging / "program.zip").write_bytes(program)
        (staging / "experiment-report.md").write_bytes(report)
        submission = staging / "netsec-message-integrity-submission.zip"
        with ZipFile(submission, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("program.zip", program)
            archive.writestr("experiment-report.md", report)
        with ZipFile(submission) as archive:
            if archive.testzip() is not None:
                raise RuntimeError("submission archive integrity check failed")
            if archive.read("program.zip") != program or archive.read("experiment-report.md") != report:
                raise RuntimeError("submission archive content mismatch")
        # Publish the self-contained submission last, after every check succeeds.
        for name in ("program.zip", "experiment-report.md", submission.name):
            (staging / name).replace(OUTPUT / name)
    return OUTPUT / submission.name


if __name__ == "__main__":
    result = build_submission()
    print(f"Created {result}")
