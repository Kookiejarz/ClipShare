import asyncio
import websockets
import pyperclip
import json
import os
import hmac
import hashlib
import sys
import base64
import time
import time
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
from handlers.file_handler import FileHandler
from utils.platform_config import verify_platform, IS_WINDOWS
from config import ClipboardConfig
from handlers.file_handler import FileHandler
from utils.platform_config import verify_platform, IS_WINDOWS
from config import ClipboardConfig
import tempfile
import traceback # Import traceback

# Verify platform at startup
verify_platform('windows')

if IS_WINDOWS:
    import win32clipboard
    import win32con
    from ctypes import Structure, c_uint, sizeof # For CF_HDROP
    # Attempt to import optional COM libraries for fallback clipboard setting
    try:
        import pythoncom
        from win32com.shell import shell, shellcon
        HAS_WIN32COM = True
    except ImportError:
        HAS_WIN32COM = False
        print("⚠️ 未找到 'pywin32' 的 COM 组件，文件剪贴板设置可能受限。")

else:
    # This should not happen due to verify_platform, but as a safeguard
    raise RuntimeError("This script requires Windows")


# Define DROPFILES structure for CF_HDROP
class DROPFILES(Structure):
    _fields_ = [
        ('pFiles', c_uint),  # offset of file list
        ('pt', c_uint * 2),  # drop point (usually 0,0)
        ('fNC', c_uint),     # is it on non-client area (usually 0)
        ('fWide', c_uint),   # WIDE character flag (1 for Unicode)
    ]

class ConnectionStatus:
    """连接状态枚举"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self.ws_url = None
        # self.last_clipboard_content = pyperclip.paste() # Less reliable, check dynamically
        self.is_receiving = False
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        self.running = True
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.reconnect_delay = 3
        self.max_reconnect_delay = 30
        self.last_discovery_time = 0
        self.last_content_hash = None # Hash of last content *sent* or *set* by this client
        self.last_update_time = 0 # Timestamp of last update *initiated* by this client
        self.last_format_log = set()
        # self.last_file_content_hash = None # Combined into last_content_hash
        self.last_remote_content_hash = None # Hash of last content *received* from remote
        self.last_remote_update_time = 0 # Timestamp of last *received* remote update
        self.ignore_clipboard_until = 0 # Timestamp until which local clipboard changes are ignored
        self._last_processed_content = None # Store last successfully processed text content

        # Initialize file handler
        self.file_handler = FileHandler(
            ClipboardConfig.get_temp_dir(), # Use config
            self.security_mgr
        )
        self.file_handler.load_file_cache() # Load cache

    def _get_device_id(self):
        """获取唯一设备ID"""
        # ... existing code ...
        import socket
        try:
            hostname = socket.gethostname()
            import uuid
            mac_num = uuid.getnode()
            mac = ':'.join(('%012X' % mac_num)[i:i+2] for i in range(0, 12, 2))
            # Use a portion of the MAC to keep it shorter but still unique
            mac_part = mac.replace(':', '')[-6:]
            return f"{hostname}-{mac_part}"
        except Exception as e:
            print(f"⚠️ 无法获取MAC地址 ({e})，将生成随机ID。")
            import random
            return f"windows-{random.randint(10000, 99999)}"


    def _get_token_path(self):
        """获取令牌存储路径"""
        # ... existing code ...
        home_dir = Path.home()
        token_dir = home_dir / ".clipshare"
        token_dir.mkdir(parents=True, exist_ok=True)
        return token_dir / "device_token.txt"

    def _load_device_token(self):
        """加载设备令牌"""
        # ... existing code ...
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
        # ... existing code ...
        token_path = self._get_token_path()
        try:
            with open(token_path, "w") as f:
                f.write(token)
            print(f"💾 设备令牌已保存到 {token_path}")
        except Exception as e:
             print(f"❌ 保存设备令牌失败: {e}")

    def _generate_signature(self):
        """生成签名"""
        # ... existing code ...
        if not self.device_token:
            return ""
        try:
            return hmac.new(
                self.device_token.encode(),
                self.device_id.encode(),
                hashlib.sha256
            ).hexdigest()
        except Exception as e:
             print(f"❌ 生成签名失败: {e}")
             return ""

    # Removed _init_encryption (handled by SecurityManager)

    def stop(self):
        """停止客户端运行"""
        if not self.running: return
        print("\n⏹️ 正在停止客户端...")
        self.running = False
        # Close discovery
        if hasattr(self, 'discovery'):
            self.discovery.close()
        # Save file cache
        if hasattr(self, 'file_handler'):
            self.file_handler.save_file_cache()
        # Cancel running tasks (handled in main loop)
        print("👋 感谢使用 UniPaste!")

    def on_service_found(self, ws_url):
        """服务发现回调"""
        # ... existing code ...
        self.last_discovery_time = time.time()
        print(f"✅ 发现剪贴板服务: {ws_url}")
        self.ws_url = ws_url

    async def sync_clipboard(self):
        """主同步循环，处理连接和重连"""
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)

        while self.running:
            # Log loop start state
            print(f"DEBUG: Main loop - Status: {self.connection_status}, URL: {self.ws_url}")
            try:
                if self.connection_status == ConnectionStatus.DISCONNECTED:
                    if not self.ws_url:
                        # print("DEBUG: No URL, waiting for discovery...") # Optional more verbose log
                        await asyncio.sleep(1.0) # Longer sleep when waiting for discovery
                        continue

                    self.connection_status = ConnectionStatus.CONNECTING
                    print(f"🔌 正在连接到服务器: {self.ws_url}")

                    try:
                        # REMOVED: async with asyncio.timeout(15):
                        # Call connect_and_sync directly without the outer timeout
                        await self.connect_and_sync()

                        # If connect_and_sync returns normally, it means connection closed gracefully
                        print("ℹ️ 连接已关闭，将尝试重新发现和连接。")
                        # Status is already set to DISCONNECTED inside connect_and_sync
                        # self.connection_status = ConnectionStatus.DISCONNECTED
                        self.ws_url = None # Reset URL to trigger rediscovery
                        print("DEBUG: Restarting discovery after normal close.") # Add log
                        self.discovery.stop_browser() # Stop browser, don't close zeroconf yet
                        self.discovery.start_discovery(self.on_service_found) # Start new discovery
                        await asyncio.sleep(1) # Brief pause before rediscovery

                    except asyncio.TimeoutError:
                         # ... existing code ...
                         print(f"❌ 连接或初始握手超时: {self.ws_url}")
                         self.connection_status = ConnectionStatus.DISCONNECTED
                         self.ws_url = None # Reset URL
                         print("DEBUG: Stopping browser before wait_for_reconnect (TimeoutError).") # Add log
                         self.discovery.stop_browser() # Stop browser before waiting
                         print("DEBUG: Triggering wait_for_reconnect due to TimeoutError.") # Add log
                         await self.wait_for_reconnect() # wait_for_reconnect will restart discovery
                    except websockets.exceptions.InvalidURI:
                         print(f"❌ 无效的服务地址: {self.ws_url}")
                         self.connection_status = ConnectionStatus.DISCONNECTED
                         self.ws_url = None
                         # No reconnect wait here, just sleep and retry discovery
                         print("DEBUG: Restarting discovery after InvalidURI.") # Add log
                         self.discovery.stop_browser() # Stop browser
                         self.discovery.start_discovery(self.on_service_found) # Start new discovery
                         await asyncio.sleep(2) # Wait before rediscovery
                    except websockets.exceptions.WebSocketException as e:
                         # Catches connection failures (e.g., ConnectionRefusedError)
                         print(f"❌ WebSocket 连接错误: {e}")
                         self.connection_status = ConnectionStatus.DISCONNECTED
                         self.ws_url = None
                         print(f"DEBUG: Stopping browser before wait_for_reconnect (WebSocketException: {e})") # Add log
                         self.discovery.stop_browser() # Stop browser before waiting
                         print(f"DEBUG: Triggering wait_for_reconnect due to WebSocketException: {e}") # Add log
                         await self.wait_for_reconnect() # wait_for_reconnect will restart discovery
                    except Exception as e:
                        # Catch other unexpected errors during the connection attempt/management phase
                        print(f"❌ 连接或同步时发生意外错误: {e}")
                        traceback.print_exc()
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        self.ws_url = None
                        print(f"DEBUG: Stopping browser before wait_for_reconnect (Exception: {e})") # Add log
                        self.discovery.stop_browser() # Stop browser before waiting
                        print(f"DEBUG: Triggering wait_for_reconnect due to Exception: {e}") # Add log
                        await self.wait_for_reconnect() # wait_for_reconnect will restart discovery
                else:
                    # Still connected or connecting, short sleep
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)

            except asyncio.CancelledError:
                print("🛑 同步任务被取消")
                break
            except Exception as e:
                print(f"❌ 主同步循环出错: {e}")
                traceback.print_exc()
                # Avoid tight loop on unexpected error
                await asyncio.sleep(5)

    async def wait_for_reconnect(self):
        """等待重连，使用指数退避策略"""
        # ... existing code ...
        current_time = time.time()
        # Reset delay if discovery was recent
        if current_time - self.last_discovery_time < 10:
            self.reconnect_delay = 3 # Reset to base delay
            delay = self.reconnect_delay
        else:
            # Exponential backoff
            delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
            self.reconnect_delay = delay

        print(f"⏱️ {int(delay)}秒后重新尝试连接...")

        # Wait in segments to allow faster exit
        wait_start = time.time()
        while self.running and time.time() - wait_start < delay:
            await asyncio.sleep(0.5)

        if self.running:
             # Reset URL to force rediscovery if needed
             self.ws_url = None
             print("🔄 重新搜索剪贴板服务...")
             # Explicitly restart discovery here (start_discovery now handles stopping previous browser)
             self.discovery.start_discovery(self.on_service_found)


    async def connect_and_sync(self):
        """连接到服务器并同步剪贴板"""
        # Specify binary subprotocol and increase max message size
        async with websockets.connect(
            self.ws_url,
            subprotocols=["binary"],
            max_size=10 * 1024 * 1024, # Allow larger messages (e.g., 10MB) for file chunks
            ping_interval=20,
            ping_timeout=20
        ) as websocket:
            # --- Authentication ---
            if not await self.authenticate(websocket):
                print("❌ 身份验证失败，断开连接")
                return # Close connection

            # --- Key Exchange ---
            if not await self.perform_key_exchange(websocket):
                print("❌ 密钥交换失败，断开连接")
                return # Close connection

            # --- Connection Successful ---
            self.reconnect_delay = 3 # Reset reconnect delay on success
            self.connection_status = ConnectionStatus.CONNECTED
            print("✅ 连接和密钥交换成功，开始同步剪贴板")

            # --- Start Send/Receive Tasks ---
            send_task = asyncio.create_task(self.send_clipboard_changes(websocket))
            receive_task = asyncio.create_task(self.receive_clipboard_changes(websocket))

            # Monitor tasks until one exits or client stops
            done, pending = await asyncio.wait(
                [send_task, receive_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            # --- Cleanup ---
            print("ℹ️ 同步任务结束，正在取消其他任务...")
            for task in pending:
                task.cancel()
            # Wait for pending tasks to cancel
            if pending:
                 await asyncio.wait(pending)

            # Check for exceptions in completed tasks
            for task in done:
                 if task.exception():
                      print(f"❌ 同步任务异常退出: {task.exception()}")
                      traceback.print_exc()

            print("ℹ️ 同步会话结束")
            # Always set status to DISCONNECTED before returning
            self.connection_status = ConnectionStatus.DISCONNECTED
            # Connection will close automatically when 'async with' block exits


    async def authenticate(self, websocket):
        """与服务器进行身份验证"""
        # ... existing code ...
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
                 auth_response = auth_response_raw # Assume string

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
                # If we weren't connecting for the first time, our token might be invalid.
                if not is_first_time:
                    print("ℹ️ 本地令牌可能已失效，将尝试清除并重新注册...")
                    try:
                        token_path = self._get_token_path()
                        if token_path.exists():
                            token_path.unlink()
                            print(f"🗑️ 已删除本地令牌文件: {token_path}")
                        self.device_token = None # Clear token in memory
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

    def _get_clipboard_file_paths(self):
        """从剪贴板获取文件路径列表 (Windows specific)"""
        try:
            win32clipboard.OpenClipboard()
            try:
                if (win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP)):
                    data = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                    if data:
                        # Data is a tuple of file paths
                        paths = [str(p) for p in data if Path(p).exists()] # Ensure paths exist
                        if paths:
                             # Simple logging, hash check done in send_clipboard_changes
                             # print(f"📎 剪贴板中包含 {len(paths)} 个文件")
                             return paths
                # else: # Less verbose logging for non-file formats
                #     # ... (optional logging of other formats) ...
                #     pass
            finally:
                win32clipboard.CloseClipboard()
                
        except Exception as e:
            # Handle specific pywintypes.error if needed
            if "OpenClipboard" in str(e) or "GetClipboardData" in str(e):
                 print(f"⚠️ 无法访问剪贴板: {e} (可能被其他应用占用)")
                 # Avoid flooding logs if clipboard is busy
                 time.sleep(0.5)
            else:
                 print(f"❌ 读取剪贴板文件失败: {e}")
                 traceback.print_exc()
        return None # Return None if no files or error

    # Removed _set_clipboard_file_paths (logic moved to _handle_file_response)
    # Removed _normalize_path (Path() handles this)

    async def _send_encrypted(self, data: bytes, websocket):
        """Helper to encrypt and send data via the websocket."""
        try:
            encrypted = self.security_mgr.encrypt_message(data)
            await websocket.send(encrypted)
        except websockets.exceptions.ConnectionClosed:
             print("❌ 发送数据失败：连接已关闭")
             self.connection_status = ConnectionStatus.DISCONNECTED # Update status
             raise # Re-raise to stop the sending loop
        except Exception as e:
            print(f"❌ 发送加密数据失败: {e}")
            traceback.print_exc()
            # Consider updating connection status on other errors too
            # self.connection_status = ConnectionStatus.DISCONNECTED
            raise # Re-raise


    async def send_clipboard_changes(self, websocket):
        """监控并发送剪贴板变化"""
        last_send_attempt_time = 0

        # Wrapper function for FileHandler
        async def send_encrypted_wrapper(data_to_encrypt: bytes):
            await self._send_encrypted(data_to_encrypt, websocket)

        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                current_time = time.time()

                # Ignore if we are currently processing a received update
                if self.is_receiving:
                    await asyncio.sleep(0.1)
                    continue

                # Ignore if we recently updated the clipboard locally
                if current_time < self.ignore_clipboard_until:
                    await asyncio.sleep(0.1)
                    continue

                # Limit check frequency
                if current_time - last_send_attempt_time < ClipboardConfig.CLIPBOARD_CHECK_INTERVAL:
                    await asyncio.sleep(0.1)
                    continue

                last_send_attempt_time = current_time
                sent_update_this_cycle = False

                # --- Check for Files ---
                file_paths = self._get_clipboard_file_paths()
                if file_paths:
                    # Calculate hash of current file paths *content*
                    content_hash = self.file_handler.get_files_content_hash(file_paths)

                    # Check if content hash is valid and different from last sent hash
                    if content_hash and content_hash != self.last_content_hash:
                        #print(f"📋 检测到剪贴板文件变化 (Hash: {content_hash[:8]}...)")
                        # Send file info message
                        new_hash, update_sent = await self.file_handler.handle_clipboard_files(
                            file_paths,
                            self.last_content_hash,
                            send_encrypted_wrapper # Pass the wrapper
                        )
                        if update_sent:
                            self.last_content_hash = new_hash # Update hash after sending info
                            self.last_update_time = time.time()
                            sent_update_this_cycle = True
                            # Initiate file transfer after sending info
                            print("🔄 准备主动传输文件内容...")
                            try:
                                for file_path in file_paths:
                                    await self.file_handler.handle_file_transfer(
                                        file_path, send_encrypted_wrapper # Pass wrapper
                                    )
                            except Exception as transfer_err:
                                 print(f"❌ 文件传输过程中断: {transfer_err}")
                                 # Connection status likely updated in _send_encrypted
                                 break # Exit send loop

                    # If files handled, skip text check for this cycle
                    if sent_update_this_cycle:
                         await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL) # Wait before next check
                         continue


                # --- Check for Text (if no files were sent) ---
                try:
                    current_content = pyperclip.paste()
                except pyperclip.PyperclipException as e:
                     print(f"⚠️ 无法读取剪贴板文本: {e}")
                     current_content = None # Treat as no text content

                # Process only if text content exists and is different from last processed
                if current_content and current_content != self._last_processed_content:
                    # Anti-loop check: Compare with last received remote hash
                    content_hash = hashlib.md5(current_content.encode()).hexdigest()
                    if (self.last_remote_content_hash == content_hash and
                        current_time - self.last_remote_update_time < ClipboardConfig.UPDATE_DELAY * 2):
                        # print("⏭️ 跳过发送回环文本内容") # Less verbose
                        pass # Don't send back recently received content
                    # Check if different from last *sent* content or enough time passed
                    elif content_hash != self.last_content_hash or current_time - self.last_update_time > ClipboardConfig.UPDATE_DELAY:
                        print(f"📋 检测到剪贴板文本变化 (Hash: {content_hash[:8]}...)")
                        # Process and send text message
                        new_hash, new_time, update_sent = await self.file_handler.process_clipboard_content(
                            current_content,
                            current_time,
                            self.last_content_hash,
                            self.last_update_time,
                            send_encrypted_wrapper # Pass the wrapper
                        )
                        if update_sent:
                            self.last_content_hash = new_hash
                            self.last_update_time = new_time
                            self._last_processed_content = current_content # Update last processed text
                            sent_update_this_cycle = True

                # Regular sleep interval if nothing was sent
                if not sent_update_this_cycle:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)

            except websockets.exceptions.ConnectionClosed:
                 print("ℹ️ 发送循环检测到连接关闭")
                 break # Exit loop naturally
            except asyncio.CancelledError:
                print("⏹️ 发送任务被取消")
                break
            except Exception as e:
                print(f"❌ 发送剪贴板变化时出错: {e}")
                traceback.print_exc()
                # Check connection status and potentially break
                if self.connection_status != ConnectionStatus.CONNECTED:
                     print("❌ 连接丢失，停止发送循环")
                     break
                await asyncio.sleep(1) # Avoid tight loop on error


    async def receive_clipboard_changes(self, websocket):
        """接收来自服务器的剪贴板变化"""
        # Wrapper function for FileHandler to send requests back to server
        async def send_encrypted_wrapper(data_to_encrypt: bytes):
            await self._send_encrypted(data_to_encrypt, websocket)

        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            try:
                # Receive data with timeout
                received_data = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                self.is_receiving = True # Set flag

                # Decrypt and process
                decrypted_data = self.security_mgr.decrypt_message(received_data)
                message_json = decrypted_data.decode('utf-8')
                message = ClipMessage.deserialize(message_json)

                if not message or "type" not in message:
                     print("⚠️ 收到的消息格式无效或无法解析")
                     continue # Skip this message

                msg_type = message["type"]
                print(f"📬 收到消息类型: {msg_type}")

                if msg_type == MessageType.TEXT:
                    await self._handle_text_message(message)
                elif msg_type == MessageType.FILE:
                    # Handle file info - request missing files via wrapper
                    await self.file_handler.handle_received_files(
                         message, send_encrypted_wrapper, sender_websocket=websocket
                    )
                elif msg_type == MessageType.FILE_RESPONSE:
                    # Handle incoming file chunk
                    await self._handle_file_response(message)
                elif msg_type == MessageType.FILE_REQUEST:
                     # Server is requesting a file from us
                     file_path_requested = message.get("path")
                     if file_path_requested:
                          print(f"📤 收到文件请求: {Path(file_path_requested).name}")
                          # Send file chunks back to server via wrapper
                          await self.file_handler.handle_file_transfer(
                               file_path_requested,
                               send_encrypted_wrapper
                          )
                     else:
                          print("⚠️ 收到的文件请求缺少路径")
                else:
                     print(f"⚠️ 未知消息类型: {msg_type}")


            except asyncio.TimeoutError:
                 # No message received, check connection with ping
                 try:
                      pong_waiter = await websocket.ping()
                      await asyncio.wait_for(pong_waiter, timeout=5)
                 except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                      print("⌛ 与服务器的连接超时或关闭，断开")
                      self.connection_status = ConnectionStatus.DISCONNECTED
                      break # Exit receive loop
                 continue # Continue loop after successful ping/pong
            except websockets.exceptions.ConnectionClosedOK:
                 print("ℹ️ 接收循环检测到连接正常关闭")
                 self.connection_status = ConnectionStatus.DISCONNECTED
                 break
            except websockets.exceptions.ConnectionClosedError as e:
                 print(f"🔌 接收循环检测到连接异常关闭: {e}")
                 self.connection_status = ConnectionStatus.DISCONNECTED
                 break
            except asyncio.CancelledError:
                print("⏹️ 接收任务被取消")
                break
            except json.JSONDecodeError:
                 print("❌ 收到的消息不是有效的JSON")
            except UnicodeDecodeError:
                 print("❌ 无法将收到的消息解码为UTF-8")
            except Exception as e:
                print(f"❌ 处理接收数据时出错: {e}")
                traceback.print_exc()
                # Avoid tight loop on error, check connection
                if self.connection_status != ConnectionStatus.CONNECTED:
                     break
                await asyncio.sleep(1)
            finally:
                 self.is_receiving = False # Reset flag


    async def perform_key_exchange(self, websocket):
        """Execute key exchange with server"""
        # ... existing code ...
        try:
            # Generate keys if needed
            if not self.security_mgr.private_key:
                self.security_mgr.generate_key_pair()

            # Wait for server's public key with timeout
            server_key_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            server_data = json.loads(server_key_message)

            if server_data.get("type") != "key_exchange":
                print("❌ 服务器未按预期发送公钥")
                return False

            # Deserialize server's public key
            server_key_data = server_data.get("public_key")
            server_public_key = self.security_mgr.deserialize_public_key(server_key_data)

            # Send our public key
            client_public_key = self.security_mgr.serialize_public_key()
            await websocket.send(json.dumps({
                "type": "key_exchange",
                "public_key": client_public_key
            }))
            print("📤 已发送客户端公钥")

            # Generate shared key
            self.security_mgr.generate_shared_key(server_public_key)
            print("🔒 密钥交换完成，已建立共享密钥")

            # Wait for confirmation with timeout
            confirmation = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            confirm_data = json.loads(confirmation)

            if confirm_data.get("type") == "key_exchange_complete" and confirm_data.get("status") == "success":
                print("✅ 服务器确认密钥交换成功")
                return True
            else:
                print("⚠️ 未收到服务器的密钥交换成功确认")
                return False

        except asyncio.TimeoutError:
             print("❌ 密钥交换步骤超时")
             return False
        except json.JSONDecodeError:
             print("❌ 密钥交换消息格式无效")
             return False
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            traceback.print_exc()
            return False

    # Removed request_file_retry (handled by standard file request mechanism)

    async def show_connection_status(self):
        """显示连接状态"""
        # ... existing code ...
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
                 print(f"\n⚠️ 状态显示错误: {e}") # Avoid crashing status display
                 last_status = None # Force redraw on next iteration
                 await asyncio.sleep(2)


    # Removed _looks_like_temp_file_path (moved to FileHandler)
    # Removed _display_progress (moved to FileHandler)

    async def _handle_text_message(self, message):
        """处理收到的文本消息"""
        try:
            text = message.get("content", "")
            if not text:
                print("⚠️ 收到空文本消息")
                return

            # Use FileHandler's check
            if self.file_handler._looks_like_temp_file_path(text):
                return

            # Calculate hash *before* setting clipboard
            content_hash = hashlib.md5(text.encode()).hexdigest()

            # Check if this content hash was the last one *we* sent or set
            if content_hash == self.last_content_hash:
                print("⏭️ 跳过重复内容 (与本地最后发送/设置一致)")
                return

            # Update clipboard
            try:
                pyperclip.copy(text)
                # Update state *after* successful clipboard operation
                self.last_content_hash = content_hash # Mark this hash as processed locally
                self.last_update_time = time.time() # Mark time of local update
                self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY # Ignore local changes briefly
                self._last_processed_content = text # Store last processed text

                # Record hash and time from remote sender for loop detection
                self.last_remote_content_hash = content_hash
                self.last_remote_update_time = time.time()

                # Display received text
                display_text = text[:ClipboardConfig.MAX_DISPLAY_LENGTH] + ("..." if len(text) > ClipboardConfig.MAX_DISPLAY_LENGTH else "")
                print(f"📥 已复制文本: \"{display_text}\"")

            except pyperclip.PyperclipException as e:
                 print(f"❌ 更新剪贴板失败: {e}")
                 # Potentially retry or log more details

        except Exception as e:
            print(f"❌ 处理文本消息时出错: {e}")
            traceback.print_exc()
        # finally: # Moved finally block to receive_clipboard_changes
        #     self.is_receiving = False


    def _set_windows_clipboard_file(self, file_path: Path) -> bool:
         """Sets a file path to the Windows clipboard using CF_HDROP."""
         try:
              path_str = str(file_path.resolve()) # Use resolved absolute path
              files = path_str + '\0' # Needs double null termination for list
              file_bytes = files.encode('utf-16le') + b'\0\0'

              # Create DROPFILES structure
              df = DROPFILES()
              df.pFiles = sizeof(df) # Offset to the path list
              df.pt[0] = df.pt[1] = 0 # Drop point (not relevant here)
              df.fNC = 0
              df.fWide = 1 # Using Unicode

              # Combine structure and path data
              data = bytes(df) + file_bytes

              # Set to clipboard
              win32clipboard.OpenClipboard()
              try:
                   win32clipboard.EmptyClipboard()
                   win32clipboard.SetClipboardData(win32con.CF_HDROP, data)
                   print(f"📎 已将文件添加到剪贴板: {file_path.name}")
                   return True
              finally:
                   win32clipboard.CloseClipboard()

         except Exception as e:
              print(f"❌ 使用 CF_HDROP 设置剪贴板文件失败: {e}")
              traceback.print_exc()

              # --- Fallback using COM (if available) ---
              if HAS_WIN32COM:
                   print("ℹ️ 尝试使用 COM 备用方法设置剪贴板...")
                   try:
                        pythoncom.CoInitialize() # Ensure COM is initialized
                        data_obj = pythoncom.OleGetClipboard()
                        # This part is complex and might not be the correct way
                        # to *set* CF_HDROP via COM easily.
                        # Setting clipboard data via COM usually involves IDataObject.
                        # For simplicity, we'll fall back to text path.
                        print("⚠️ COM 备用方法设置 CF_HDROP 较复杂，将回退到文本路径。")
                        # Fall through to text fallback
                   except Exception as com_err:
                        print(f"❌ COM 备用方法失败: {com_err}")
                        # Fall through to text fallback
                   finally:
                        # pythoncom.CoUninitialize() # Careful with uninit if used elsewhere

                # --- Final Fallback: Set as text ---
                    try:
                        pyperclip.copy(path_str)
                        print(f"📎 已将文件路径作为文本复制到剪贴板: {file_path.name}")
                        # Return True even for text fallback, as *something* was set
                        return True
                    except Exception as text_err:
                        print(f"❌ 将文件路径作为文本复制也失败了: {text_err}")
                        return False # All methods failed

         return False # Should not be reached unless initial try fails weirdly


    async def _handle_file_response(self, message):
        """处理接收到的文件响应 (块)"""
        try:
            # Use FileHandler to process the chunk
            is_complete, completed_path = self.file_handler.handle_received_chunk(message)

            # If file transfer is complete
            if is_complete and completed_path:
                print(f"✅ 文件接收完成: {completed_path}")

                # Calculate hash of the completed file
                content_hash = self.file_handler.get_files_content_hash([str(completed_path)])

                # Check if this file content hash was the last one *we* sent or set
                if content_hash and content_hash == self.last_content_hash:
                    print("⏭️ 跳过重复文件内容 (与本地最后发送/设置一致)")
                    return # Don't update clipboard

                # Set the completed file to the Windows clipboard
                if self._set_windows_clipboard_file(completed_path):
                     # Update state *after* successful clipboard operation
                     self.last_content_hash = content_hash # Mark this hash as processed locally
                     self.last_update_time = time.time() # Mark time of local update
                     self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY * 1.5 # Longer ignore for files
                     # Record hash and time from remote sender for loop detection
                     self.last_remote_content_hash = content_hash
                     self.last_remote_update_time = time.time()
                else:
                     print(f"❌ 未能将文件 {completed_path.name} 设置到剪贴板")


        except Exception as e:
            print(f"❌ 处理文件响应时出错: {e}")
            traceback.print_exc()
        # finally: # Moved finally block to receive_clipboard_changes
        #     self.is_receiving = False

    # Removed handle_file_transfer (now uses FileHandler's method via wrapper)
    # Removed get_files_content_hash (moved to FileHandler)


async def main(): # Make main async
    client = WindowsClipboardClient()
    main_task = None
    status_task = None

    # This inner async function might not be strictly necessary anymore,
    # but we can keep it for structure or integrate its logic directly.
    async def run_client():
        nonlocal status_task # Allow modification
        # Create status task within the running loop
        status_task = asyncio.create_task(client.show_connection_status())
        try:
            await client.sync_clipboard() # Run main sync loop
        finally:
            # Ensure status task is cancelled if sync_clipboard finishes/errors
            if status_task and not status_task.done():
                status_task.cancel()

    try:
        print("🚀 UniPaste Windows 客户端已启动")
        print(f"📂 临时文件目录: {client.file_handler.temp_dir}")
        print("📋 按 Ctrl+C 退出程序")

        # Run the client logic directly
        main_task = asyncio.create_task(run_client())
        await main_task # Wait for the main client task to complete

    except KeyboardInterrupt:
        print("\n👋 检测到 Ctrl+C，正在关闭...")
    except asyncio.CancelledError:
         print("\nℹ️ 主任务被取消") # Expected during shutdown
    except Exception as e:
        print(f"\n❌ 发生未处理的错误: {e}")
        traceback.print_exc()
    finally:
        print("⏳ 正在清理资源...")
        # Initiate stop sequence (ensure client.stop() is called)
        client.stop()

        # Cancel tasks if they are still running (main_task should be done or cancelled)
        tasks_to_cancel = [t for t in [status_task, main_task] if t and not t.done()]
        if tasks_to_cancel:
            for task in tasks_to_cancel:
                task.cancel()
            # Wait briefly for tasks to cancel
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        print("🚪 程序退出")


if __name__ == "__main__":
    # Set event loop policy for Windows if needed (usually not required for basic asyncio)
    # if sys.platform == 'win32':
    #     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main()) # Use asyncio.run()
    except RuntimeError as e:
         # Catch potential loop-related errors during shutdown
         if "Event loop is closed" in str(e):
              print("ℹ️ Event loop closed.")
         else:
              raise