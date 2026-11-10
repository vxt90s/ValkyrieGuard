"""Command-line entry point: GUI by default, --selftest runs the unit tests."""

import os
import sys
import unittest


def run_selftest() -> int:
    tests_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    if not os.path.isdir(tests_dir):
        print("The tests are only included in the source download (git clone or the project zip).")
        return 1
    suite = unittest.defaultTestLoader.discover(tests_dir, top_level_dir=os.path.dirname(tests_dir))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


def main() -> None:
    if "--selftest" in sys.argv:
        sys.exit(run_selftest())
    try:
        from .gui.main_window import App
    except ImportError as e:
        print(f"Tkinter is not available ({e}).\nOn Windows, re-run the Python installer and tick 'tcl/tk and IDLE'.")
        sys.exit(1)
    App().mainloop()
