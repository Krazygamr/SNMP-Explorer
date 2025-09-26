# tabs/dashboard/selection.py

class SelectionState:
    """
    Tracks the per-module selected metrics, and supports simple operations.
    selected = { module: set(metric, ...) }
    """
    def __init__(self):
        self.selected = {}

    def clear_all(self):
        self.selected.clear()

    def add_to_modules(self, modules: list[str], metrics: list[str]):
        for mod in modules:
            bucket = self.selected.setdefault(mod, set())
            for m in metrics:
                bucket.add(m)

    def remove_from_modules(self, modules: list[str], metrics: list[str]):
        for mod in modules:
            if mod in self.selected:
                for m in metrics:
                    self.selected[mod].discard(m)
                if not self.selected[mod]:
                    del self.selected[mod]

    def total_counts(self) -> tuple[int, int]:
        total = sum(len(v) for v in self.selected.values())
        mods = len(self.selected)
        return total, mods
