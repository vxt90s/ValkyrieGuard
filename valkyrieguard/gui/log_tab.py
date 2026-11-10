"""Log tab: timestamped messages from every part of the app."""

from datetime import datetime
from tkinter import ttk

from .base import AppBase
from .theme import make_text


class LogTab(AppBase):
    def _tab_log(self):
        t = ttk.Frame(self.nb)
        self.nb.add(t, text="  Log  ")
        fr, self.log_text = make_text(t, 10)
        fr.pack(fill="both", expand=True, padx=12, pady=12)

    def log(self, msg: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{datetime.now():%H:%M:%S}  {msg}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
