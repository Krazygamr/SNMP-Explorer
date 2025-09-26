# common/notify.py
import tkinter as tk
from tkinter import ttk

# common/notify.py
import tkinter as tk
from tkinter import ttk

def toast(parent, title, message, ok=True, timeout_ms=None):
    win = tk.Toplevel(parent)
    win.title(title)
    win.attributes("-topmost", True)
    win.resizable(False, False)

    bg = "#e7f7ee" if ok else "#fdeaea"
    fg = "#0b6b3a" if ok else "#8a0a0a"

    frm = ttk.Frame(win, padding=10)
    frm.pack(fill=tk.BOTH, expand=True)

    lbl = ttk.Label(frm, text=("✓ " if ok else "✗ ") + title, foreground=fg)
    lbl.pack(anchor="w", pady=(0,6))

    txt = tk.Text(frm, height=10, wrap=tk.WORD, bg=bg, relief="flat")
    txt.insert("1.0", message.strip() or "(no output)")
    txt.configure(state=tk.DISABLED)
    txt.pack(fill=tk.BOTH, expand=True)

    # Close button row
    btns = ttk.Frame(frm)
    btns.pack(fill=tk.X, pady=(8,0))
    ttk.Button(btns, text="Close", command=win.destroy).pack(side=tk.RIGHT)

    # place near bottom-right of parent
    parent.update_idletasks()
    x = parent.winfo_rootx() + parent.winfo_width() - 420
    y = parent.winfo_rooty() + parent.winfo_height() - 260
    win.geometry(f"400x260+{x}+{y}")

    if timeout_ms:
        win.after(timeout_ms, win.destroy)

    return win
