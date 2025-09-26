# tabs/dashboard/tooltips.py
import tkinter as tk

class Tooltip:
    """Simple, safe cross-widget tooltip (no bbox('insert') usage)."""
    def __init__(self, widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id = None
        self._tip = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _schedule(self, _evt=None):
        self._unschedule()
        if not self.text:
            return
        self._after_id = self.widget.after(self.delay, self._show)

    def _unschedule(self):
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self):
        if self._tip or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + min(20, max(8, self.widget.winfo_width() // 4))
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        except Exception:
            x, y = 100, 100

        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#FFFFE0", relief=tk.SOLID, borderwidth=1,
            font=("Segoe UI", 9),
        )
        lbl.pack(ipadx=6, ipady=3)
        self._tip = tw

    def _hide(self, _evt=None):
        self._unschedule()
        if self._tip:
            try: self._tip.destroy()
            except Exception: pass
            self._tip = None
