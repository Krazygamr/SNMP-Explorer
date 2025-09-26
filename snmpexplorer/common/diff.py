import tkinter as tk
from tkinter import ttk
import difflib

def show_diff_window(parent, title: str, old_text: str, new_text: str, fromfile: str, tofile: str = "Edited"):
    win = tk.Toplevel(parent)
    win.title(title)
    win.geometry("1000x700")
    txt = tk.Text(win, wrap=tk.NONE, font=("Consolas", 10))
    vs = ttk.Scrollbar(win, orient='vertical', command=txt.yview)
    hs = ttk.Scrollbar(win, orient='horizontal', command=txt.xview)
    txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
    txt.grid(row=0, column=0, sticky='nsew')
    vs.grid(row=0, column=1, sticky='ns')
    hs.grid(row=1, column=0, sticky='ew')
    win.columnconfigure(0, weight=1)
    win.rowconfigure(0, weight=1)
    diff = difflib.unified_diff(
        old_text.splitlines(True),
        new_text.splitlines(True),
        fromfile=fromfile,
        tofile=tofile
    )
    txt.insert(tk.END, ''.join(diff) or "(No differences)\n")
