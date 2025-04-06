import AppKit
import asyncio
import websockets
import json 
import signal
import time
import base64
import os  # 添加 os 模块导入
from utils.security.crypto import SecurityManager
from utils.security.auth import DeviceAuthManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
import tempfile
from pathlib import Path
import hashlib

class ClipboardListener:
    """剪贴板监听和同步服务器"""
    
    def __init__(self):
        # 基础组件初始化
        self._init_basic_components()
        # 状态标志初始化
        self._init_state_flags()
        # 文件处理相关初始化
        self._init_file_handling()
        
    def _init_basic_components(self):
        """初始化基础组件"""
        self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
        self.security_mgr = SecurityManager()
        self.auth_mgr = DeviceAuthManager()
        self.discovery = DeviceDiscovery()
        self.connected_clients = set()
        
    def _init_state_flags(self):
        """初始化状态标志"""
        self.last_change_count = self.pasteboard.changeCount()
        self.last_content_hash = None
        self.is_receiving = False
        self.last_update_time = 0
        self.running = True
        self.server = None
        
    def _init_file_handling(self):
        """初始化文件处理相关"""
        self.temp_dir = Path(tempfile.gettempdir()) / "unipaste_files"
        self.temp_dir.mkdir(exist_ok=True)
        self.file_transfers = {}
        self.file_cache = {}
        self.load_file_cache()