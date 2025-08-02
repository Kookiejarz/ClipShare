"""
UniPaste Windows Client
Handles clipboard synchronization and file transfer for Windows systems
"""

import asyncio
import base64
import hashlib
import json
import os
import struct
import sys
import time
import traceback
from pathlib import Path

import websockets
from ctypes import Structure, c_uint, sizeof

from config import ClipboardConfig
from handlers.file_handler import FileHandler
from utils.connection_utils import ConnectionManager
from utils.constants import ConnectionStatus
from utils.message_format import ClipMessage, MessageType
from utils.network.discovery import DeviceDiscovery
from utils.platform_config import verify_platform, IS_WINDOWS
from utils.security.crypto import SecurityManager


# Verify platform at startup
verify_platform('windows')

if IS_WINDOWS:
    import win32clipboard
    import win32con
    from ctypes import Structure, c_uint, sizeof
    import pyperclip

# Define DROPFILES structure for CF_HDROP
class DROPFILES(Structure):
    _fields_ = [
        ('pFiles', c_uint),
        ('pt', c_uint * 2),
        ('fNC', c_uint),
        ('fWide', c_uint),
    ]

class WindowsClipboardClient:
    """
    Windows clipboard client for UniPaste
    Handles clipboard synchronization, file transfers, and server communication
    """
    
    def __init__(self):
        # Core components
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self.connection_mgr = ConnectionManager()
        
        # Device identification
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        
        # Connection state
        self.ws_url = None
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.running = True
        
        # Clipboard state
        self.is_receiving = False
        self.last_content_hash = None
        self.last_update_time = 0
        self.last_remote_content_hash = None
        self.last_remote_update_time = 0
        self.ignore_clipboard_until = 0
        self._last_processed_content = None
        
        # Binary transfer state
        self._pending_binary_chunks = {}  # Track binary chunks waiting for data
        
        # Multi-file batch handling
        self._pending_file_batches = {}  # Track files that are part of the same batch
        self._completed_files = {}  # Store completed files waiting to be added to clipboard

        # Initialize file handler - 修复：使用正确的构造函数
        try:
            self.file_handler = FileHandler(
                temp_dir=ClipboardConfig.get_temp_dir(),
                security_mgr=self.security_mgr
            )
        except Exception as e:
            print(f"❌ 初始化 FileHandler 失败: {e}")
            # 创建一个最小的备用对象
            class MinimalFileHandler:
                def __init__(self):
                    self.temp_dir = ClipboardConfig.get_temp_dir()
                    self.temp_dir.mkdir(exist_ok=True)
                    
                def load_file_cache(self):
                    pass
                    
                async def handle_text_message(self, message, set_clipboard_func, last_content_hash):
                    try:
                        text = message.get("content", "")
                        if not text:
                            return last_content_hash, 0
                        
                        import hashlib
                        content_hash = hashlib.md5(text.encode()).hexdigest()
                        
                        if content_hash == last_content_hash:
                            return last_content_hash, 0
                        
                        if await set_clipboard_func(text):
                            display_text = text[:50] + ("..." if len(text) > 50 else "")
                            print(f"📥 已复制文本: \"{display_text}\"")
                            return content_hash, time.time()
                        else:
                            return last_content_hash, 0
                            
                    except Exception as e:
                        print(f"❌ 处理文本消息时出错: {e}")
                        return last_content_hash, 0
                        
                def handle_received_chunk(self, message):
                    return False, None
                    
                def get_files_content_hash(self, files):
                    return None
            
            self.file_handler = MinimalFileHandler()

        # Load file cache if available
        try:
            if hasattr(self.file_handler, 'load_file_cache'):
                self.file_handler.load_file_cache()
        except Exception as e:
            print(f"⚠️ 加载文件缓存失败: {e}")

    # ================== Device Management ==================
    
    def _get_device_id(self):
        """获取唯一设备ID"""
        import socket
        import uuid
        import random
        try:
            hostname = socket.gethostname()
            mac_num = uuid.getnode()
            mac = ':'.join(('%012X' % mac_num)[i:i+2] for i in range(0, 12, 2))
            mac_part = mac.replace(':', '')[-6:]
            return f"{hostname}-{mac_part}"
        except Exception as e:
            print(f"⚠️ 无法获取MAC地址 ({e})，将生成随机ID。")
            return f"windows-{random.randint(10000, 99999)}"

    def _get_token_path(self):
        """获取令牌存储路径"""
        home_dir = Path.home()
        token_dir = home_dir / ".clipshare"
        token_dir.mkdir(parents=True, exist_ok=True)
        return token_dir / "device_token.txt"

    def _load_device_token(self):
        """加载设备令牌"""
        token_path = self._get_token_path()
        if token_path.exists():
            try:
                with open(token_path, "r") as f:
                    return f.read().strip()
            except Exception as e:
                print(f"❌ 加载设备令牌失败: {e}")
        return None

    def _save_device_token(self, token):
        """保存设备令牌"""
        token_path = self._get_token_path()
        try:
            with open(token_path, "w") as f:
                f.write(token)
            print(f"💾 设备令牌已保存到 {token_path}")
        except Exception as e:
            print(f"❌ 保存设备令牌失败: {e}")

    # ================== Discovery & Connection ==================

    def on_service_found(self, url):
        """服务发现回调"""
        if url != self.ws_url:
            print(f"✅ 发现剪贴板服务: {url}")
            self.ws_url = url
            self.connection_mgr.last_discovery_time = time.time()

    def stop(self):
        """停止客户端"""
        print("🛑 正在停止客户端...")
        self.running = False
        if hasattr(self.discovery, 'close'):
            self.discovery.close()

    # ================== Authentication & Security ==================

    def _generate_signature(self):
        """生成签名"""
        if not self.device_token:
            return ""
        try:
            import hmac
            import hashlib
            return hmac.new(
                self.device_token.encode(),
                self.device_id.encode(),
                hashlib.sha256
            ).hexdigest()
        except Exception as e:
            print(f"❌ 生成签名失败: {e}")
            return ""

    async def perform_key_exchange(self, websocket):
        """执行密钥交换"""
        try:
            print("🔑 开始密钥交换...")
            
            # Generate client's key pair if not already done
            if not hasattr(self.security_mgr, 'private_key') or not self.security_mgr.private_key:
                self.security_mgr.generate_key_pair()
            
            # Wait for server's public key
            print("⏳ 等待服务器公钥...")
            server_message = await asyncio.wait_for(websocket.recv(), timeout=15.0)
            
            if isinstance(server_message, bytes):
                server_message = server_message.decode('utf-8')
            
            server_data = json.loads(server_message)
            print(f"📨 收到服务器消息类型: {server_data.get('type')}")
            
            if server_data.get('type') != 'key_exchange_server':
                print(f"❌ 收到无效的服务器密钥交换消息类型: {server_data.get('type')}")
                return False
            
            server_public_key_pem = server_data.get('public_key')
            if not server_public_key_pem:
                print("❌ 服务器未提供公钥")
                return False
            
            # Store server's public key
            if not self.security_mgr.set_peer_public_key(server_public_key_pem):
                print("❌ 无法设置服务器公钥")
                return False
            
            print("✅ 已接收并设置服务器公钥")
            
            # Send client's public key to server
            client_public_key = self.security_mgr.get_public_key_pem()
            key_exchange_response = {
                'type': 'key_exchange_client',
                'public_key': client_public_key
            }
            
            print("📤 发送客户端公钥给服务器...")
            await websocket.send(json.dumps(key_exchange_response))
            
            # Wait for server confirmation
            print("⏳ 等待服务器确认...")
            confirmation_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            
            if isinstance(confirmation_message, bytes):
                confirmation_message = confirmation_message.decode('utf-8')
            
            confirmation_data = json.loads(confirmation_message)
            print(f"📨 收到确认消息: {confirmation_data}")
            
            if (confirmation_data.get('type') == 'key_exchange_complete' and 
                confirmation_data.get('status') == 'success'):
                print("🔑 密钥交换成功完成!")
                return True
            else:
                print(f"❌ 密钥交换失败: {confirmation_data}")
                return False
                
        except asyncio.TimeoutError:
            print("❌ 密钥交换超时")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ 密钥交换响应JSON解析失败: {e}")
            return False
        except Exception as e:
            print(f"❌ 密钥交换过程中出错: {e}")
            import traceback
            traceback.print_exc()
            return False

    # ================== Clipboard Operations ==================

    def _get_clipboard_files(self):
        """检测Windows剪贴板中的文件路径"""
        try:
            win32clipboard.OpenClipboard()
            try:
                # Check if clipboard contains files (CF_HDROP format)
                if not win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                    # print("🔍 剪贴板中没有文件数据 (CF_HDROP)")  # Debug info
                    return None
                
                # Get the clipboard data - CF_HDROP returns a tuple of file paths
                hdrop_data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                
                # Handle tuple format returned by CF_HDROP
                file_paths = []
                try:
                    if isinstance(hdrop_data, tuple):
                        # CF_HDROP returns a tuple of file paths
                        file_paths = list(hdrop_data)
                    elif isinstance(hdrop_data, (bytes, bytearray)):
                        # If we get binary data, parse DROPFILES structure
                        if len(hdrop_data) >= 20:
                            # Read DROPFILES header
                            pFiles, pt_x, pt_y, fNC, fWide = struct.unpack('5I', hdrop_data[:20])
                            
                            print(f"🔍 DROPFILES结构: pFiles={pFiles}, fWide={fWide}")
                            
                            # Extract file paths starting from offset pFiles
                            if pFiles < len(hdrop_data):
                                file_data = hdrop_data[pFiles:]
                                
                                if fWide:  # Unicode (UTF-16LE)
                                    file_string = file_data.decode('utf-16le', errors='ignore')
                                    paths = file_string.split('\0')
                                    file_paths = [path for path in paths if path.strip()]
                                else:  # ANSI
                                    file_string = file_data.decode('ascii', errors='ignore')
                                    paths = file_string.split('\0')
                                    file_paths = [path for path in paths if path.strip()]
                                    
                    elif isinstance(hdrop_data, str):
                        # Single file path as string
                        file_paths = [hdrop_data]
                    else:
                        print(f"❌ 未知的剪贴板数据格式: {type(hdrop_data)}")
                        
                except Exception as parse_error:
                    print(f"❌ 解析剪贴板文件数据失败: {parse_error}")
                    import traceback
                    traceback.print_exc()
                
                # Validate file paths exist and handle both files and folders
                # But filter out temp files to avoid infinite loops
                valid_paths = []
                temp_dir_str = str(self.file_handler.temp_dir)
                
                for path in file_paths:
                    if os.path.exists(path):
                        path_obj = Path(path)
                        
                        # Skip temp files to avoid sending back files we just received
                        if temp_dir_str in str(path_obj):
                            # Create a unique key for this specific temp file to avoid repeated messages
                            temp_file_key = f"temp_skip_{path_obj.name}"
                            if not hasattr(self, '_temp_skip_tracker'):
                                self._temp_skip_tracker = {}
                            
                            # Only print message once per file per session, or every 30 seconds
                            current_time = time.time()
                            if (temp_file_key not in self._temp_skip_tracker or 
                                current_time - self._temp_skip_tracker[temp_file_key] > 30):
                                print(f"⏭️ 跳过临时文件（避免循环发送）: {path_obj.name}")
                                self._temp_skip_tracker[temp_file_key] = current_time
                            continue
                            
                        if path_obj.is_file():
                            valid_paths.append(path)
                        elif path_obj.is_dir():
                            print(f"📁 检测到文件夹: {path_obj.name}")
                            # 收集文件夹中的所有文件
                            try:
                                folder_files = []
                                for item in path_obj.rglob('*'):
                                    if item.is_file():
                                        # Also skip temp files in folders
                                        if temp_dir_str not in str(item):
                                            folder_files.append(str(item))
                                if folder_files:
                                    valid_paths.extend(folder_files)
                                    print(f"📁 从文件夹 {path_obj.name} 中找到 {len(folder_files)} 个文件")
                                else:
                                    print(f"⚠️ 文件夹 {path_obj.name} 中没有文件（或都是临时文件）")
                            except Exception as e:
                                print(f"❌ 读取文件夹 {path_obj.name} 时出错: {e}")
                
                if valid_paths:
                    # Only print this message occasionally to avoid spam for the same files
                    files_hash = hashlib.md5(str(sorted(valid_paths)).encode()).hexdigest()
                    if not hasattr(self, '_last_files_hash') or self._last_files_hash != files_hash:
                        print(f"✅ Windows剪贴板检测到 {len(valid_paths)} 个有效文件")
                        self._last_files_hash = files_hash
                return valid_paths if valid_paths else None
                
            finally:
                win32clipboard.CloseClipboard()
                
        except Exception as e:
            # Clipboard access can fail if another app is using it
            print(f"⚠️ Windows剪贴板文件检测失败: {e}")
            return None

    async def _send_files_to_server(self, websocket, file_paths):
        """发送文件到服务器（支持批量文件）"""
        try:
            if not file_paths:
                return
            
            print(f"📤 准备发送 {len(file_paths)} 个文件...")
            
            # Send file info message first
            file_info_list = []
            total_size = 0
            
            for file_path in file_paths:
                path_obj = Path(file_path)
                if path_obj.exists() and path_obj.is_file():
                    file_size = path_obj.stat().st_size
                    file_info = {
                        'filename': path_obj.name,
                        'size': file_size,
                        'path': str(path_obj),
                        'hash': ClipMessage.calculate_file_hash(str(path_obj))
                    }
                    file_info_list.append(file_info)
                    total_size += file_size
            
            if not file_info_list:
                print("⚠️ 没有有效文件可发送")
                return
            
            # Send file info message
            message = {
                'type': 'file',
                'files': file_info_list,
                'timestamp': time.time()
            }
            
            message_json = json.dumps(message)
            encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
            await websocket.send(encrypted_data)
            
            # Display file info
            file_names = [info['filename'] for info in file_info_list]
            print(f"📤 已发送文件信息: {', '.join(file_names)} (总大小: {total_size/1024/1024:.1f}MB)")
            
            # Send each file using the file handler
            async def send_encrypted_fn(data):
                if isinstance(data, bytes):
                    encrypted = self.security_mgr.encrypt_message(data)
                else:
                    encrypted = self.security_mgr.encrypt_message(data.encode('utf-8'))
                await websocket.send(encrypted)
            
            # Send files one by one (or implement concurrent sending for better performance)
            for file_path in file_paths:
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    print(f"📤 开始传输文件: {Path(file_path).name}")
                    success = await self.file_handler.handle_file_transfer(file_path, send_encrypted_fn)
                    if success:
                        print(f"✅ 文件传输成功: {Path(file_path).name}")
                    else:
                        print(f"❌ 文件传输失败: {Path(file_path).name}")
            
            print(f"🎉 批量文件传输完成: {len(file_paths)} 个文件")
            
        except Exception as e:
            print(f"❌ 发送文件到服务器失败: {e}")
            import traceback
            traceback.print_exc()

    def _set_windows_clipboard_files(self, file_paths):
        """设置Windows剪贴板文件（支持多个文件）"""
        try:
            if not file_paths:
                return False
                
            # Convert single file to list for consistency
            if not isinstance(file_paths, list):
                file_paths = [file_paths]
            
            # Build null-terminated string list of file paths
            files_str = ''
            for file_path in file_paths:
                path_str = str(Path(file_path).resolve())
                files_str += path_str + '\0'
            files_str += '\0'  # Double null terminator at the end
            
            file_bytes = files_str.encode('utf-16le')

            df = DROPFILES()
            df.pFiles = sizeof(df)
            df.pt[0] = df.pt[1] = 0
            df.fNC = 0
            df.fWide = 1

            data = bytes(df) + file_bytes

            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32con.CF_HDROP, data)
                
                if len(file_paths) == 1:
                    print(f"📎 已将文件添加到剪贴板: {Path(file_paths[0]).name}")
                else:
                    file_names = [Path(p).name for p in file_paths]
                    print(f"📎 已将 {len(file_paths)} 个文件添加到剪贴板: {', '.join(file_names)}")
                return True
            finally:
                win32clipboard.CloseClipboard()

        except Exception as e:
            print(f"❌ 设置剪贴板文件失败: {e}")
            return False

    def _set_windows_clipboard_file(self, file_path):
        """设置Windows剪贴板文件（单个文件，向后兼容）"""
        return self._set_windows_clipboard_files([file_path])

    # ================== Message Handling ==================

    async def send_clipboard_changes(self, websocket):
        """发送剪贴板变化"""
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                # 这里需要实现剪贴板监控逻辑
                await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ 发送剪贴板变化时出错: {e}")
                break

    async def receive_clipboard_changes(self, websocket):
        """接收剪贴板变化"""
        try:
            while self.running and self.connection_status == ConnectionStatus.CONNECTED:
                try:
                    message = await websocket.recv()
                    if isinstance(message, bytes):
                        # 处理二进制消息
                        pass
                    else:
                        # 处理文本消息
                        data = json.loads(message)
                        if data.get('type') == 'text':
                            await self._handle_text_message(data)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print(f"❌ 接收消息时出错: {e}")
                    break
        finally:
            self.is_receiving = False

    async def authenticate(self, websocket):
        """与服务器进行身份验证"""
        try:
            is_first_time = self.device_token is None

            auth_info = {
                'identity': self.device_id,
                'signature': self._generate_signature(),
                'first_time': is_first_time,
                'device_name': os.environ.get('COMPUTERNAME', 'Windows设备'),
                'platform': 'windows'
            }

            print(f"🔑 {'首次连接' if is_first_time else '已注册设备'} ID: {self.device_id}")
            await websocket.send(json.dumps(auth_info))

            # Wait for response with timeout
            auth_response_raw = await asyncio.wait_for(websocket.recv(), timeout=10.0)

            if isinstance(auth_response_raw, bytes):
                auth_response = auth_response_raw.decode('utf-8')
            else:
                auth_response = auth_response_raw

            response_data = json.loads(auth_response)
            status = response_data.get('status')

            if status == 'authorized':
                print(f"✅ 身份验证成功! 服务器: {response_data.get('server_id', '未知')}")
                return True
            elif status == 'first_authorized':
                token = response_data.get('token')
                if token:
                    self._save_device_token(token)
                    self.device_token = token
                    print(f"🆕 设备已授权并获取令牌")
                    return True
                else:
                    print(f"❌ 服务器在首次授权时未提供令牌")
                    return False
            else:
                reason = response_data.get('reason', '未知原因')
                print(f"❌ 身份验证失败: {reason}")
                # 修复：如果令牌无效，完全重置身份验证状态
                if not is_first_time and 'signature' in reason.lower():
                    print("ℹ️ 本地令牌可能已失效，将尝试清除并重新注册...")
                    try:
                        token_path = self._get_token_path()
                        if token_path.exists():
                            token_path.unlink()
                            print(f"🗑️ 已删除本地令牌文件: {token_path}")
                        self.device_token = None  # 重置内存中的令牌
                        print("🔄 下次连接将作为新设备重新注册")
                    except Exception as e:
                        print(f"⚠️ 删除本地令牌文件失败: {e}")
                return False
        except asyncio.TimeoutError:
            print("❌ 等待身份验证响应超时")
            return False
        except json.JSONDecodeError:
            print("❌ 无效的身份验证响应格式")
            return False
        except Exception as e:
            print(f"❌ 身份验证过程中出错: {e}")
            traceback.print_exc()
            return False

    async def _handle_text_message(self, message):
        """处理收到的文本消息"""
        async def set_clipboard_text(text):
            try:
                pyperclip.copy(text)
                return True
            except Exception as e:
                print(f"❌ 更新剪贴板失败: {e}")
                return False
        
        new_hash, new_time = await self.file_handler.handle_text_message(
            message, set_clipboard_text, self.last_content_hash
        )
        
        if new_time > 0:  # Successfully processed
            self.last_content_hash = new_hash
            self.last_update_time = new_time
            self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY
            self.last_remote_content_hash = new_hash
            self.last_remote_update_time = time.time()

    async def _handle_file_info(self, message):
        """处理文件信息消息"""
        try:
            files = message.get('files', [])
            if not files:
                print("⚠️ 收到空文件列表")
                return
            
            print(f"📁 收到文件信息: {len(files)} 个文件")
            
            # Create a batch for this file group
            batch_id = message.get('timestamp', time.time())
            expected_files = []
            
            for file_info in files:
                filename = file_info.get('filename', '未知文件')
                size = file_info.get('size', 0)
                print(f"  📄 {filename} ({size/1024/1024:.1f}MB)")
                expected_files.append(filename)
            
            # Track this batch of files
            self._pending_file_batches[batch_id] = {
                'expected_files': expected_files,
                'completed_files': [],
                'total_count': len(expected_files)
            }
            
            print(f"🔄 等待接收 {len(expected_files)} 个文件...")
            
        except Exception as e:
            print(f"❌ 处理文件信息时出错: {e}")

    async def _handle_binary_file_metadata(self, metadata):
        """处理二进制模式的文件元数据"""
        try:
            filename = metadata.get('filename', '未知文件')
            chunk_index = metadata.get('chunk_index', 0)
            chunk_size = metadata.get('chunk_size', 0)
            
            # Store metadata for when binary data arrives
            key = f"{filename}_{chunk_index}"
            self._pending_binary_chunks[key] = metadata
            
            print(f"📦 等待二进制数据: {filename} 块 {chunk_index+1}, 大小 {chunk_size} 字节")
            
        except Exception as e:
            print(f"❌ 处理二进制文件元数据时出错: {e}")

    async def _handle_raw_binary_data(self, binary_data):
        """处理原始二进制文件数据"""
        try:
            # Find the most recent pending binary chunk
            # In a proper implementation, we'd match by chunk order or other identifier
            if not self._pending_binary_chunks:
                print("⚠️ 收到二进制数据但没有等待的元数据")
                return
            
            # Get the latest pending chunk (FIFO approach)
            key = next(iter(self._pending_binary_chunks))
            metadata = self._pending_binary_chunks.pop(key)
            
            # Create a complete message for the file handler
            complete_message = {
                'type': 'file_response',
                'filename': metadata.get('filename'),
                'chunk_index': metadata.get('chunk_index'),
                'total_chunks': metadata.get('total_chunks'),
                'chunk_data': base64.b64encode(binary_data).decode('utf-8'),
                'chunk_hash': metadata.get('chunk_hash'),
                'file_hash': metadata.get('file_hash'),
                'exists': True
            }
            
            # Process as normal file response
            await self._handle_file_response(complete_message)
            
        except Exception as e:
            print(f"❌ 处理原始二进制数据时出错: {e}")

    # ================== Connection Management ==================

    async def show_connection_status(self):
        """显示连接状态"""
        last_status = None
        status_messages = {
            ConnectionStatus.DISCONNECTED: "🔴 已断开连接 - 等待服务器",
            ConnectionStatus.CONNECTING: "🟡 正在连接...",
            ConnectionStatus.CONNECTED: "🟢 已连接 - 剪贴板同步已激活"
        }

        status_line = ""
        while self.running:
            try:
                current_status = self.connection_status
                if current_status != last_status:
                    # Clear previous status line
                    if status_line:
                        sys.stdout.write("\r" + " " * len(status_line) + "\r")

                    # Display new status
                    status_line = status_messages.get(current_status, "⚪ 未知状态")
                    sys.stdout.write(f"\r{status_line}")
                    sys.stdout.flush()
                    last_status = current_status

                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                # Clear status line on exit
                if status_line:
                     sys.stdout.write("\r" + " " * len(status_line) + "\r")
                     sys.stdout.flush()
                break
            except Exception as e:
                 print(f"\n⚠️ 状态显示错误: {e}")
                 last_status = None
                 await asyncio.sleep(2)

    async def _handle_file_response(self, message):
        """处理接收到的文件响应"""
        try:
            is_complete, completed_path = self.file_handler.handle_received_chunk(message)

            if is_complete and completed_path:
                filename = completed_path.name
                print(f"✅ 文件接收完成: {filename}")
                
                # Find which batch this file belongs to
                batch_found = False
                for batch_id, batch_info in self._pending_file_batches.items():
                    if filename in batch_info['expected_files']:
                        batch_info['completed_files'].append(completed_path)
                        batch_found = True
                        
                        print(f"📦 批次进度: {len(batch_info['completed_files'])}/{batch_info['total_count']} 个文件")
                        
                        # Check if all files in this batch are complete
                        if len(batch_info['completed_files']) >= batch_info['total_count']:
                            print(f"🎉 文件批次完成: {len(batch_info['completed_files'])} 个文件")
                            
                            # Set all files to clipboard at once
                            if self._set_windows_clipboard_files(batch_info['completed_files']):
                                print(f"✅ 已将 {len(batch_info['completed_files'])} 个文件添加到剪贴板")
                            else:
                                print(f"❌ 未能将文件批次设置到剪贴板")
                            
                            # Clean up completed batch
                            del self._pending_file_batches[batch_id]
                        break
                
                # If no batch found, handle as single file (fallback)
                if not batch_found:
                    print(f"📄 处理单个文件: {filename}")
                    if self._set_windows_clipboard_file(completed_path):
                        print(f"✅ 已将单个文件添加到剪贴板: {filename}")
                    else:
                        print(f"❌ 未能将单个文件设置到剪贴板: {filename}")

        except Exception as e:
            print(f"❌ 处理文件响应时出错: {e}")
            traceback.print_exc()
    

    # 添加其他缺失的方法...
    async def sync_clipboard(self):
        """主同步循环"""
        print("🔍 搜索剪贴板服务...")
        print("🔄 无限重试模式已启用 - 将持续尝试连接直到成功")
        self.discovery.start_discovery(self.on_service_found)

        while self.running:
            try:
                if self.connection_status == ConnectionStatus.DISCONNECTED:
                    if not self.ws_url:
                        await asyncio.sleep(1.0)
                        continue

                    self.connection_status = ConnectionStatus.CONNECTING
                    print(f"🔌 正在连接到服务器: {self.ws_url}")

                    try:
                        result = await self.connect_and_sync()
                        if result:
                            print("ℹ️ 连接已关闭，将尝试重新连接")
                        else:
                            print("❌ 连接失败")
                        
                        # Always trigger reconnection logic for any disconnection
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        self.ws_url = None
                        await self.wait_for_reconnect()
                    except Exception as e:
                        print(f"❌ 连接错误: {e}")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        await self.wait_for_reconnect()
                else:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)

            except asyncio.CancelledError:
                print("🛑 同步任务被取消")
                break
            except Exception as e:
                print(f"❌ 主同步循环出错: {e}")
                await asyncio.sleep(5)

    async def wait_for_reconnect(self):
        """等待重连"""
        print("🔄 启动自动重连机制...")
        await self.connection_mgr.wait_for_reconnect(lambda: self.running)

        if self.running:
            self.ws_url = None
            print("🔍 重新搜索剪贴板服务...")
            self.discovery.start_discovery(self.on_service_found)

    async def connect_and_sync(self):
        """连接到服务器并开始同步"""
        if not self.ws_url:
            print("❌ 未找到服务器URL")
            return False

        try:
            print(f"🔗 正在连接到 {self.ws_url}")
            self.connection_status = ConnectionStatus.CONNECTING
            
            async with websockets.connect(
                self.ws_url,
                subprotocols=["binary"],
                ping_interval=60,  # Ping every minute
                ping_timeout=30,   # Wait 30s for pong
                close_timeout=30   # Wait 30s for close
            ) as websocket:
                print("✅ WebSocket 连接已建立")
                
                # 1. Authentication
                if not await self.authenticate(websocket):
                    print("❌ 身份验证失败")
                    return False
                
                # 2. Key Exchange  
                if not await self.perform_key_exchange(websocket):
                    print("❌ 密钥交换失败")
                    return False
                
                print("🎉 连接建立成功，开始同步...")
                self.connection_status = ConnectionStatus.CONNECTED
                self.connection_mgr.reset_reconnect_delay()  # Reset reconnect delay on successful connection
                
                # Start clipboard monitoring and message handling
                clipboard_task = asyncio.create_task(self.monitor_clipboard(websocket))
                receive_task = asyncio.create_task(self.receive_messages(websocket))
                
                try:
                    # Wait for either task to complete (usually due to error or disconnect)
                    done, pending = await asyncio.wait(
                        [clipboard_task, receive_task], 
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # Cancel remaining tasks
                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    
                    # Check if any task had an exception
                    for task in done:
                        if task.exception():
                            print(f"❌ 任务异常: {task.exception()}")
                    
                except Exception as e:
                    print(f"❌ 连接处理过程中出错: {e}")
                
                return True
                
        except asyncio.TimeoutError:
            print("❌ 连接超时")
            return False
        except websockets.exceptions.ConnectionClosed as e:
            print(f"📴 连接已关闭: {e}")
            return False
        except websockets.exceptions.InvalidURI:
            print(f"❌ 无效的服务器地址: {self.ws_url}")
            return False
        except Exception as e:
            print(f"❌ 连接失败: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.connection_status = ConnectionStatus.DISCONNECTED

    async def monitor_clipboard(self, websocket):
        """监控剪贴板变化并发送到服务器（支持文本和文件）"""
        last_clipboard_data = None
        last_file_paths = None
        
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                # 检查剪贴板是否有变化
                if time.time() < self.ignore_clipboard_until:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue
                
                # First check for files in clipboard
                file_paths = self._get_clipboard_files()
                if file_paths and file_paths != last_file_paths:
                    # Handle file content
                    await self._send_files_to_server(websocket, file_paths)
                    last_file_paths = file_paths
                    # Set ignore period to avoid rapid re-sending
                    self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY
                    continue
                elif file_paths is None and last_file_paths is not None:
                    # Files were removed from clipboard, reset state
                    last_file_paths = None
                
                # If no files, check for text content
                current_clipboard = None
                try:
                    # 尝试获取剪贴板文本内容
                    current_clipboard = pyperclip.paste()
                except Exception as e:
                    # 如果获取失败，继续等待
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue
                
                # 检查文本内容是否有变化
                if current_clipboard != last_clipboard_data and current_clipboard:
                    # 计算内容哈希
                    import hashlib
                    content_hash = hashlib.md5(current_clipboard.encode()).hexdigest()
                    
                    # 避免发送刚接收到的内容
                    if (content_hash != self.last_remote_content_hash and 
                        content_hash != self.last_content_hash):
                        
                        print(f"📤 检测到文本剪贴板变化，发送到服务器...")
                        
                        # 创建文本消息
                        message = {
                            'type': 'text',
                            'content': current_clipboard,
                            'timestamp': time.time(),
                            'hash': content_hash
                        }
                        
                        try:
                            # 加密并发送到服务器
                            message_json = json.dumps(message)
                            encrypted_data = self.security_mgr.encrypt_message(message_json.encode('utf-8'))
                            await websocket.send(encrypted_data)
                            
                            # 更新本地状态
                            self.last_content_hash = content_hash
                            self.last_update_time = time.time()
                            last_clipboard_data = current_clipboard
                            
                            # 显示发送的内容预览
                            display_text = current_clipboard[:50] + ("..." if len(current_clipboard) > 50 else "")
                            print(f"📤 已发送文本: \"{display_text}\"")
                            
                        except Exception as e:
                            print(f"❌ 发送剪贴板内容失败: {e}")
                            break
                
                await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                
            except asyncio.CancelledError:
                print("🛑 剪贴板监控任务被取消")
                break
            except Exception as e:
                print(f"❌ 监控剪贴板时出错: {e}")
                break

    async def receive_messages(self, websocket):
        """接收来自服务器的消息"""
        try:
            while self.running and self.connection_status == ConnectionStatus.CONNECTED:
                try:
                    # 接收消息
                    message = await websocket.recv()
                    
                    if isinstance(message, bytes):
                        # 所有二进制数据都应该是加密的，先解密
                        try:
                            decrypted_data = self.security_mgr.decrypt_message(message)
                            
                            # 尝试作为JSON解析
                            try:
                                decrypted_text = decrypted_data.decode('utf-8')
                                data = json.loads(decrypted_text)
                                await self._handle_json_message(data)
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                # 如果不是JSON，可能是二进制文件数据
                                await self._handle_raw_binary_data(decrypted_data)
                                
                        except Exception as e:
                            print(f"❌ 解密二进制消息失败: {e}")
                            # 如果解密失败，可能是真正的文件数据，尝试原来的处理方式
                            await self._handle_binary_message(message)
                    else:
                        # 处理文本消息（通常是认证和密钥交换）
                        try:
                            data = json.loads(message)
                            await self._handle_json_message(data)
                        except json.JSONDecodeError as e:
                            print(f"❌ 解析JSON消息失败: {e}")
                            
                except asyncio.CancelledError:
                    print("🛑 消息接收任务被取消")
                    break
                except websockets.exceptions.ConnectionClosed:
                    print("📴 WebSocket连接已关闭")
                    break
                except Exception as e:
                    print(f"❌ 接收消息时出错: {e}")
                    break
                
        except Exception as e:
            print(f"❌ 消息接收循环出错: {e}")
        finally:
            self.connection_status = ConnectionStatus.DISCONNECTED

    async def _handle_json_message(self, data):
        """处理JSON消息"""
        try:
            message_type = data.get('type')
            
            if message_type == 'text':
                await self._handle_text_message(data)
            elif message_type == 'file':
                await self._handle_file_info(data)
            elif message_type == 'file_response':
                # Check if this is binary mode
                if data.get('binary_mode', False):
                    await self._handle_binary_file_metadata(data)
                else:
                    await self._handle_file_response(data)
            elif message_type == 'file_chunk':
                await self._handle_file_response(data)
            elif message_type == 'file_complete':
                await self._handle_file_complete(data)
            else:
                print(f"⚠️ 收到未知消息类型: {message_type}")
                
        except Exception as e:
            print(f"❌ 处理JSON消息时出错: {e}")

    async def _handle_binary_message(self, message):
        """处理二进制消息"""
        try:
            # 假设二进制消息是文件数据
            print(f"📦 收到二进制数据，大小: {len(message)} 字节")
            # 这里可以添加文件数据处理逻辑
        except Exception as e:
            print(f"❌ 处理二进制消息时出错: {e}")

    async def _handle_file_complete(self, data):
        """处理文件传输完成消息"""
        try:
            file_name = data.get('filename', '未知文件')
            print(f"✅ 文件传输完成: {file_name}")
        except Exception as e:
            print(f"❌ 处理文件完成消息时出错: {e}")


async def main():
    client = WindowsClipboardClient()
    main_task = None
    status_task = None

    async def run_client():
        nonlocal status_task
        status_task = asyncio.create_task(client.show_connection_status())
        try:
            await client.sync_clipboard()
        finally:
            if status_task and not status_task.done():
                status_task.cancel()

    try:
        print("🚀 UniPaste Windows 客户端已启动")
        print(f"📂 临时文件目录: {client.file_handler.temp_dir}")
        print("📋 按 Ctrl+C 退出程序")

        main_task = asyncio.create_task(run_client())
        await main_task

    except KeyboardInterrupt:
        print("\n👋 检测到 Ctrl+C，正在关闭...")
    except asyncio.CancelledError:
         print("\nℹ️ 主任务被取消")
    except Exception as e:
        print(f"\n❌ 发生未处理的错误: {e}")
        traceback.print_exc()
    finally:
        print("⏳ 正在清理资源...")
        client.stop()

        tasks_to_cancel = [t for t in [status_task, main_task] if t and not t.done()]
        if tasks_to_cancel:
            for task in tasks_to_cancel:
                task.cancel()
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        print("🚪 程序退出")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as e:
         if "Event loop is closed" in str(e):
              print("ℹ️ Event loop closed.")
         else:
              raise