"""
Status management utilities for UniPaste
Provides consistent status display and logging
"""

import asyncio
import sys
import time
from typing import Callable, Dict, Optional

from utils.constants import ConnectionStatus, STATUS_INDICATORS


class StatusManager:
    """
    Manages status display and updates
    """
    
    def __init__(self):
        self.current_status = ConnectionStatus.DISCONNECTED
        self.last_status_time = 0
        self.status_line = ""
        self.running = True
    
    def update_status(self, new_status: ConnectionStatus, message: Optional[str] = None):
        """Update the current status"""
        if new_status != self.current_status:
            self.current_status = new_status
            self.last_status_time = time.time()
            
            # Use custom message or default indicator
            status_text = message or STATUS_INDICATORS.get(new_status, "⚪ 未知状态")
            
            # Clear previous status line
            if self.status_line:
                sys.stdout.write("\r" + " " * len(self.status_line) + "\r")
            
            # Display new status
            self.status_line = status_text
            sys.stdout.write(f"\r{self.status_line}")
            sys.stdout.flush()
    
    async def start_status_monitor(self, status_getter: Callable[[], ConnectionStatus]):
        """Start monitoring status changes"""
        last_status = None
        
        while self.running:
            try:
                current_status = status_getter()
                if current_status != last_status:
                    self.update_status(current_status)
                    last_status = current_status
                
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                # Clear status line on exit
                if self.status_line:
                    sys.stdout.write("\r" + " " * len(self.status_line) + "\r")
                    sys.stdout.flush()
                break
            except Exception as e:
                print(f"\n⚠️ 状态显示错误: {e}")
                last_status = None
                await asyncio.sleep(2)
    
    def stop(self):
        """Stop the status manager"""
        self.running = False
        # Clear status line
        if self.status_line:
            sys.stdout.write("\r" + " " * len(self.status_line) + "\r")
            sys.stdout.flush()


class ProgressTracker:
    """
    Tracks and displays progress for long operations
    """
    
    def __init__(self, total: int, operation: str = "操作", bar_length: int = 20):
        self.total = total
        self.current = 0
        self.operation = operation
        self.bar_length = bar_length
        self.start_time = time.time()
    
    def update(self, current: int):
        """Update progress"""
        self.current = min(current, self.total)
        self._display_progress()
    
    def increment(self):
        """Increment progress by 1"""
        self.update(self.current + 1)
    
    def _display_progress(self):
        """Display current progress"""
        if self.total <= 0:
            return
        
        percentage = (self.current * 100) // self.total
        filled = min(self.bar_length, (percentage * self.bar_length) // 100)
        bar = '█' * filled + '░' * (self.bar_length - filled)
        
        elapsed = time.time() - self.start_time
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            eta = (self.total - self.current) / rate if rate > 0 else 0
            eta_str = f", ETA: {eta:.1f}s"
        else:
            eta_str = ""
        
        status = f"\r{self.operation}: [{bar}] {percentage}% ({self.current}/{self.total}){eta_str}"
        sys.stdout.write(status)
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()
    
    def complete(self):
        """Mark as complete"""
        self.update(self.total)