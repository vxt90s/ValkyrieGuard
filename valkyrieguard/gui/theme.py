"""Dark theme, colours and small widget factories shared by every tab."""

import tkinter as tk
from tkinter import ttk

BG, PANEL, LINE, TXT, MUT, ACC = "#0b0f19", "#111b2e", "#1e293b", "#f1f5f9", "#94a3b8", "#38bdf8"
COL = {"ALERT": "#f43f5e", "WARNING": "#f97316", "INFO": "#3b82f6", "OK": "#10b981",
       "CRITICAL": "#f43f5e", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "-": "#10b981"}


def set_text(w: tk.Text, text: str) -> None:
    w.configure(state="normal")
    w.delete("1.0", "end")
    w.insert("1.0", text)
    w.configure(state="disabled")


def apply_style(root: tk.Misc) -> None:
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=BG, foreground=TXT, fieldbackground=PANEL, bordercolor=LINE,
                 lightcolor=LINE, darkcolor=LINE, troughcolor=PANEL, font=("Segoe UI", 10))
    st.configure("TNotebook", background=BG, borderwidth=0)
    st.configure("TNotebook.Tab", background=PANEL, foreground=MUT, padding=(18, 8))
    st.map("TNotebook.Tab", background=[("selected", LINE)], foreground=[("selected", ACC)])
    st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TXT, rowheight=27, borderwidth=0)
    st.configure("Treeview.Heading", background=BG, foreground=ACC, relief="flat", font=("Segoe UI", 10, "bold"))
    st.map("Treeview", background=[("selected", "#1e3a5f")])
    st.configure("TButton", background=LINE, foreground=TXT, padding=(12, 6), borderwidth=0)
    st.map("TButton", background=[("active", "#2b3b55"), ("disabled", "#141c2b")], foreground=[("disabled", "#475569")])
    st.configure("Accent.TButton", background="#0ea5e9", foreground="#04121f", font=("Segoe UI", 10, "bold"))
    st.map("Accent.TButton", background=[("active", ACC), ("disabled", "#164e63")], foreground=[("disabled", "#0b2a3a")])
    st.configure("Horizontal.TProgressbar", background=ACC, troughcolor=PANEL, thickness=10, borderwidth=0)
    st.configure("TCheckbutton", background=BG, foreground=TXT)
    st.map("TCheckbutton", background=[("active", BG)])
    st.configure("TLabel", background=BG, foreground=TXT)
    st.configure("Muted.TLabel", foreground=MUT)


def make_text(parent, height: int = 8):
    fr = tk.Frame(parent, bg=PANEL)
    t = tk.Text(fr, height=height, bg=PANEL, fg=TXT, insertbackground=TXT, relief="flat", wrap="word",
                font=("Consolas", 10), padx=10, pady=8, state="disabled", borderwidth=0)
    sb = ttk.Scrollbar(fr, command=t.yview)
    t.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    t.pack(side="left", fill="both", expand=True)
    return fr, t


def make_tree(parent, cols, widths):
    fr = tk.Frame(parent, bg=PANEL)
    tv = ttk.Treeview(fr, columns=[c for c, _ in cols], show="headings", selectmode="browse")
    for (c, label), w in zip(cols, widths):
        tv.heading(c, text=label)
        tv.column(c, width=w, anchor="w", stretch=(w >= 200))
    sb = ttk.Scrollbar(fr, command=tv.yview)
    tv.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    tv.pack(side="left", fill="both", expand=True)
    for k, c in COL.items():
        tv.tag_configure(k, foreground=c)
    return fr, tv
