"""Windows helpers: Administrator check and UAC elevation."""

import ctypes
import os
import sys

from .config import IS_WIN


def is_admin() -> bool:
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def relaunch_as_admin() -> bool:
    """Asks Windows (UAC) to start this program again with Administrator rights."""
    args = [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)
    exe = sys.executable
    windowed = os.path.join(os.path.dirname(exe), "pythonw.exe")  # no extra black console window
    if os.path.isfile(windowed):
        exe = windowed
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32  # type: ignore[attr-defined]
