"""PyInstaller entry point for the DWI Desktop application."""

from dwi.desktop import run_desktop


if __name__ == "__main__":
    raise SystemExit(run_desktop())
