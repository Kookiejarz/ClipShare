"""
Base class for UniPaste clients
Contains common functionality shared between Windows client and Mac server
"""

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from pathlib import Path

from config import ClipboardConfig
from utils.connection_utils import ConnectionManager, ConnectionStatus
from utils.security.crypto import SecurityManager


class BaseClipboardClient(ABC):
    """
    Abstract base class for clipboard clients/servers
    Provides common functionality for authentication, encryption, and messaging
    """
    
    def __init__(self):
        # Core components
        self.security_mgr = SecurityManager()
        self.connection_mgr = ConnectionManager()
        
        # State management
        self.running = True
        self.last_content_hash = None
        self.last_update_time = 0
        self.last_remote_content_hash = None
        self.last_remote_update_time = 0
        self.ignore_clipboard_until = 0
        
    # ================== Common Authentication ==================
    
    async def perform_key_exchange(self, websocket):
        """Perform cryptographic key exchange with peer"""
        try:
            if not hasattr(self.security_mgr, 'private_key') or not self.security_mgr.private_key:
                self.security_mgr.generate_key_pair()
            
            # Implementation depends on whether this is client or server
            return await self._do_key_exchange(websocket)
            
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            return False
    
    @abstractmethod
    async def _do_key_exchange(self, websocket):
        """Subclass-specific key exchange implementation"""
        pass
    
    # ================== Common Message Handling ==================
    
    def _calculate_content_hash(self, content: str) -> str:
        """Calculate hash for content deduplication"""
        return hashlib.md5(content.encode()).hexdigest()
    
    def _should_ignore_content(self, content_hash: str) -> bool:
        """Check if content should be ignored due to recent activity"""
        current_time = time.time()
        
        # Skip if we're in the ignore window
        if current_time < self.ignore_clipboard_until:
            return True
            
        # Skip if this is the same content we just processed
        if content_hash == self.last_content_hash:
            return True
            
        # Skip if this matches recent remote content
        if (content_hash == self.last_remote_content_hash and 
            current_time - self.last_remote_update_time < ClipboardConfig.UPDATE_DELAY * 2):
            return True
            
        return False
    
    def _update_content_state(self, content_hash: str, is_remote: bool = False):
        """Update internal state after processing content"""
        current_time = time.time()
        self.last_content_hash = content_hash
        self.last_update_time = current_time
        
        if is_remote:
            self.last_remote_content_hash = content_hash
            self.last_remote_update_time = current_time
            self.ignore_clipboard_until = current_time + ClipboardConfig.UPDATE_DELAY
    
    # ================== Common Utilities ==================
    
    def _format_display_text(self, text: str, max_length: int = None) -> str:
        """Format text for display with length limit"""
        if max_length is None:
            max_length = ClipboardConfig.MAX_DISPLAY_LENGTH
        return text[:max_length] + ("..." if len(text) > max_length else "")
    
    def stop(self):
        """Stop the client/server"""
        print("🛑 正在停止...")
        self.running = False
    
    # ================== Abstract Methods ==================
    
    @abstractmethod
    async def start(self):
        """Start the client/server"""
        pass
        
    @abstractmethod
    async def handle_text_content(self, content: str):
        """Handle text clipboard content"""
        pass
        
    @abstractmethod
    async def handle_file_content(self, file_paths: list):
        """Handle file clipboard content"""
        pass