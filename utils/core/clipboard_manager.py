import pyperclip
from typing import Any, Optional
import time

class ClipboardManager:
    def __init__(self):
        self._last_content = None
        self._callbacks = []

    def start_monitoring(self):
        """Start monitoring clipboard changes."""
        while True:
            current_content = pyperclip.paste()
            if current_content != self._last_content:
                self._last_content = current_content
                self._notify_changes(current_content)
            time.sleep(0.1)  # Check every 100ms

    def register_callback(self, callback):
        """Register a callback for clipboard changes."""
        self._callbacks.append(callback)

    def _notify_changes(self, content: Any):
        """Notify all registered callbacks of changes."""
        for callback in self._callbacks:
            callback(content)

    def set_content(self, content: str):
        """Set clipboard content."""
        pyperclip.copy(content)
        self._last_content = content
