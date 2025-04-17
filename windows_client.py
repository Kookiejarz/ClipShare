import asyncio
import os
import websockets
import pyperclip
import json
import hmac
import hashlib
import time
import base64
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
from handlers.file_handler import FileHandler
from utils.platform_config import verify_platform, IS_WINDOWS
from config import ClipboardConfig
import tempfile

verify_platform('windows')

if IS_WINDOWS:
    import win32clipboard
    import win32con
else:
    raise RuntimeError("This script requires Windows")

class ConnectionStatus:
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

class WindowsClipboardClient:
    def __init__(self):
        print("DEBUG: Initializing WindowsClipboardClient...")
        try:
            self.security_mgr = SecurityManager()
            print("DEBUG: SecurityManager OK")
            self.discovery = DeviceDiscovery()
            print("DEBUG: DeviceDiscovery OK")
            self.ws_url = None
            self.is_receiving = False
            self.device_id = self._get_device_id()
            print(f"DEBUG: Device ID: {self.device_id}")
            self.device_token = self._load_device_token()
            print(f"DEBUG: Device Token Loaded: {'Yes' if self.device_token else 'No'}")
            self.running = True
            self.connection_status = ConnectionStatus.DISCONNECTED
            self.reconnect_delay = 3
            self.max_reconnect_delay = 30
            self.last_discovery_time = 0
            self.last_content_hash = None
            self.last_update_time = 0
            self.last_format_log = set()
            self.file_handler = FileHandler(
                Path(tempfile.gettempdir()) / "clipshare_files",
                self.security_mgr
            )
            print("DEBUG: FileHandler OK")
            self.ignore_clipboard_until = 2
            self.last_remote_hash = None
            self.last_clipboard_text = None
            self.last_clipboard_files = None
            print("DEBUG: Initialization complete.")
        except Exception as e:
            print(f"FATAL ERROR during __init__: {e}")
            import traceback
            traceback.print_exc()
            raise

    def _get_device_id(self):
        import socket, uuid
        try:
            hostname = socket.gethostname()
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 8*6, 8)][::-1])
            return f"{hostname}-{mac}"
        except:
            import random
            return f"windows-{random.randint(10000, 99999)}"

    def _get_token_path(self):
        home_dir = Path.home()
        token_dir = home_dir / ".clipshare"
        token_dir.mkdir(parents=True, exist_ok=True)
        return token_dir / "device_token.txt"

    def _load_device_token(self):
        token_path = self._get_token_path()
        if (token_path.exists()):
            with open(token_path, "r") as f:
                return f.read().strip()
        return None

    def _save_device_token(self, token):
        token_path = self._get_token_path()
        with open(token_path, "w") as f:
            f.write(token)
        print(f"💾 设备令牌已保存到 {token_path}")

    def _generate_signature(self):
        if not self.device_token:
            return ""
        return hmac.new(
            self.device_token.encode(), 
            self.device_id.encode(), 
            hashlib.sha256
        ).hexdigest()

    def stop(self):
        print("\n⏹️ 正在停止客户端...")
        self.running = False
        if hasattr(self, 'discovery'):
            self.discovery.close()
        print("👋 感谢使用 UniPaste!")

    def on_service_found(self, ws_url):
        self.last_discovery_time = time.time()
        print(f"发现剪贴板服务: {ws_url}")
        self.ws_url = ws_url

    async def sync_clipboard(self):
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        while self.running:
            try:
                if self.connection_status == ConnectionStatus.DISCONNECTED:
                    if not self.ws_url:
                        await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                        continue
                    self.connection_status = ConnectionStatus.CONNECTING
                    print(f"🔌 连接到服务器: {self.ws_url}")
                    try:
                        await self.connect_and_sync()
                    except Exception as e:
                        print(f"❌ 连接失败: {e}")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        await self.wait_for_reconnect()
                else:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ 同步过程出错: {e}")
                await asyncio.sleep(1)

    async def wait_for_reconnect(self):
        current_time = time.time()
        delay = self.reconnect_delay if current_time - self.last_discovery_time < 10 else min(self.reconnect_delay * 2, self.max_reconnect_delay)
        self.reconnect_delay = delay
        print(f"⏱️ {delay}秒后重新尝试连接...")
        for _ in range(int(delay * 2)):
            if not self.running:
                break
            await asyncio.sleep(0.5)
        self.ws_url = None
        print("🔄 重新搜索剪贴板服务...")

    async def connect_and_sync(self):
        # Use locals to track task creation for cancellation in except blocks
        send_task = None
        receive_task = None
        async with websockets.connect(self.ws_url, subprotocols=["binary"]) as websocket:
            try:
                if not await self.authenticate(websocket):
                    return
                if not await self.perform_key_exchange(websocket):
                    print("❌ 密钥交换失败，断开连接")
                    return

                self.reconnect_delay = 3
                self.connection_status = ConnectionStatus.CONNECTED
                print("✅ 连接和密钥交换成功，开始同步剪贴板")

                send_task = asyncio.create_task(self.send_clipboard_changes(websocket), name="SendTask")
                receive_task = asyncio.create_task(self.receive_clipboard_changes(websocket), name="ReceiveTask")
                print("DEBUG: Send/Receive tasks created in connect_and_sync")

                print("DEBUG: About to await asyncio.wait...") # Add this line
                # Wait for either task to complete (normally or with error)
                done, pending = await asyncio.wait(
                    [send_task, receive_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                print(f"DEBUG: asyncio.wait completed. One task finished. Done: {len(done)}, Pending: {len(pending)}")

                # Cancel the pending task(s)
                for task in pending:
                    print(f"DEBUG: Cancelling pending task: {task.get_name()}")
                    task.cancel()
                # Await cancellation if there were pending tasks
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                    print("DEBUG: Pending tasks cancelled.")

                # Check the result of the completed task(s) for errors
                for task in done:
                    try:
                        task.result() # This will raise an exception if the task failed
                        print(f"DEBUG: Task {task.get_name()} completed normally.")
                    except asyncio.CancelledError:
                        print(f"DEBUG: Task {task.get_name()} was cancelled.")
                    except Exception as e:
                        print(f"❌ Task {task.get_name()} failed with exception: {e}")
                        # Consider if this should trigger disconnect or be handled differently

            except websockets.exceptions.ConnectionClosed as e:
                print(f"📴 与服务器的连接已关闭: {e}")
                self.connection_status = ConnectionStatus.DISCONNECTED
            except asyncio.CancelledError:
                print("DEBUG: connect_and_sync task was cancelled.")
                self.connection_status = ConnectionStatus.DISCONNECTED
                # Ensure tasks are cancelled if connect_and_sync itself is cancelled
                if send_task and not send_task.done(): send_task.cancel()
                if receive_task and not receive_task.done(): receive_task.cancel()
                if send_task and receive_task:
                     await asyncio.gather(send_task, receive_task, return_exceptions=True)
                # Do not re-raise CancelledError here, let sync_clipboard handle it if needed
            except Exception as e:
                print(f"❌ 连接过程中发生意外错误: {e}")
                import traceback
                traceback.print_exc() # Print stack trace for unexpected errors
                self.connection_status = ConnectionStatus.DISCONNECTED
            finally:
                # Ensure tasks are cancelled if they haven't been already when exiting the try block
                print("DEBUG: Entering finally block in connect_and_sync")
                if send_task and not send_task.done():
                    print(f"DEBUG: Final cancellation check: Cancelling {send_task.get_name()}")
                    send_task.cancel()
                if receive_task and not send_task.done():
                    print(f"DEBUG: Final cancellation check: Cancelling {receive_task.get_name()}")
                    receive_task.cancel()
                # Await final cancellations
                tasks_to_await = []
                if send_task: tasks_to_await.append(send_task)
                if receive_task: tasks_to_await.append(receive_task)
                if tasks_to_await:
                    await asyncio.gather(*tasks_to_await, return_exceptions=True)
                    print("DEBUG: Final task cleanup complete.")

        # This print executes after the 'async with' block finishes (connection closed)
        print(f"DEBUG: connect_and_sync finished. Status is now: {self.connection_status}")

    async def authenticate(self, websocket):
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
            auth_response = await websocket.recv()
            if isinstance(auth_response, bytes):
                auth_response = auth_response.decode('utf-8')
            response_data = json.loads(auth_response)
            status = response_data.get('status')
            if status == 'authorized':
                print(f"✅ 身份验证成功! 服务器: {response_data.get('server_id', '未知')}")
                return True
            elif status == 'first_authorized':
                token = response_data.get('token')
                if (token):
                    self._save_device_token(token)
                    self.device_token = token
                    print(f"🆕 设备已授权并获取令牌")
                    return True
                else:
                    print(f"❌ 服务器未提供令牌")
                    return False
            else:
                print(f"❌ 身份验证失败: {response_data.get('reason', '未知原因')}")
                return False
        except Exception as e:
            print(f"❌ 身份验证过程出错: {e}")
            return False

    async def send_clipboard_changes(self, websocket):
        last_send_attempt = 0
        min_interval = 3
        async def broadcast_fn(data):
            try:
                await websocket.send(data)
            except Exception as e:
                print(f"❌ 发送数据失败: {e}")
        print("DEBUG: send_clipboard_changes task started.") # Add this line
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            print("DEBUG: send_clipboard_changes loop iteration.") # Add this line
            try:
                # 新增：严格忽略窗口
                if time.time() < getattr(self, "ignore_clipboard_until", 0):
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue
                if self.is_receiving:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue
                current_time = time.time()
                if current_time - last_send_attempt < min_interval:
                    await asyncio.sleep(0.1)
                    continue

                # 检查文件
                file_paths = self.file_handler.get_clipboard_files()
                if file_paths and file_paths != self.last_clipboard_files:
                    content_hash = hashlib.md5(str(file_paths).encode()).hexdigest()
                    if content_hash == self.last_remote_hash:
                        await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                        continue
                    file_msg = ClipMessage.file_message(file_paths)
                    message_json = ClipMessage.serialize(file_msg)
                    if content_hash != self.last_content_hash:
                        encrypted_data = self.security_mgr.encrypt_message(
                            message_json.encode('utf-8')
                        )
                        await broadcast_fn(encrypted_data)
                        for file_path in file_paths:
                            await self.handle_file_transfer(file_path, broadcast_fn)
                        self.last_content_hash = content_hash
                        self.last_update_time = current_time
                        self.last_clipboard_files = file_paths  # 记录本次内容
                else:
                    # 检查文本
                    current_content = self.file_handler.get_clipboard_text()
                    if current_content and current_content != self.last_clipboard_text:
                        content_hash = hashlib.md5(current_content.encode()).hexdigest()
                        if content_hash == self.last_remote_hash:
                            await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                            continue
                        if (content_hash != self.last_content_hash or 
                            current_time - self.last_update_time > 1.0):
                            text_msg = ClipMessage.text_message(current_content)
                            message_json = ClipMessage.serialize(text_msg)
                            encrypted_data = self.security_mgr.encrypt_message(
                                message_json.encode('utf-8')
                            )
                            await broadcast_fn(encrypted_data)
                            self.last_content_hash = content_hash
                            self.last_update_time = current_time
                            self.last_clipboard_text = current_content  # 记录本次内容
                            max_display = 50
                            display_text = current_content[:max_display] + ("..." if len(current_content) > max_display else "")
                            print(f"📤 已发送文本: \"{display_text}\"")
                last_send_attempt = current_time
                await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
            except asyncio.CancelledError:
                print("DEBUG: send_clipboard_changes cancelled.") # Add this line
                break
            except Exception as e:
                if self.running and self.connection_status == ConnectionStatus.CONNECTED:
                    print(f"❌ 发送错误: {e}")
                    if "connection" in str(e).lower():
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        break
                await asyncio.sleep(1)
        print("DEBUG: send_clipboard_changes task finished.") # Add this line

    async def receive_clipboard_changes(self, websocket):
        print("DEBUG: ENTERING receive_clipboard_changes function.") # <--- ADD THIS LINE
        async def broadcast_fn(data):
            try:
                await websocket.send(data)
            except Exception as e:
                print(f"❌ 发送数据失败: {e}")
        print("DEBUG: receive_clipboard_changes task started.") # Existing debug print
        while self.running and self.connection_status == ConnectionStatus.CONNECTED:
            # print("DEBUG: receive_clipboard_changes loop iteration.") # Keep this commented for now to reduce noise unless needed
            try:
                # print("DEBUG: receive_clipboard_changes trying to recv...") # Keep commented unless needed
                received_data = await websocket.recv()
                # print(f"DEBUG: receive_clipboard_changes received {len(received_data)} bytes.") # Keep commented unless needed

                self.is_receiving = True # Set flag only after successful receive
                decrypted_data = self.security_mgr.decrypt_message(received_data)
                message_json = decrypted_data.decode('utf-8')
                message = ClipMessage.deserialize(message_json)

                if message["type"] == MessageType.TEXT:
                    await self._handle_text_message(message)
                elif message["type"] == MessageType.FILE:
                    await self.file_handler.handle_received_files(message, websocket, broadcast_fn)
                elif message["type"] == MessageType.FILE_RESPONSE:
                    await self._handle_file_response(message)
                # Note: is_receiving is reset within the _handle_* methods upon completion/error

            # --- Explicitly catch websocket closure exceptions ---
            except websockets.exceptions.ConnectionClosedOK:
                print("DEBUG: receive_clipboard_changes: Connection closed normally by server.")
                self.connection_status = ConnectionStatus.DISCONNECTED # Ensure status update
                break # Exit the loop
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"DEBUG: receive_clipboard_changes: Connection closed with error: {e}")
                self.connection_status = ConnectionStatus.DISCONNECTED # Ensure status update
                break # Exit the loop
            # --- End explicit closure handling ---

            except asyncio.CancelledError:
                print("DEBUG: receive_clipboard_changes cancelled.") # Existing debug print
                break
            except Exception as e:
                # Catch other potential errors during receive/decrypt/process
                print(f"❌ receive_clipboard_changes error in loop: {e}") # Modify existing print
                import traceback
                traceback.print_exc() # Add traceback for unexpected errors
                # Decide if connection should be considered broken
                if "connection" in str(e).lower() or isinstance(e, websockets.exceptions.WebSocketException):
                    self.connection_status = ConnectionStatus.DISCONNECTED
                    break
                self.is_receiving = False # Reset flag on non-connection errors
                await asyncio.sleep(1) # Avoid tight loop on non-connection errors

        print("DEBUG: receive_clipboard_changes task finished.") # Existing debug print

    async def perform_key_exchange(self, websocket):
        try:
            if not self.security_mgr.public_key:
                self.security_mgr.generate_key_pair()
            server_key_message = await websocket.recv()
            server_data = json.loads(server_key_message)
            if server_data.get("type") != "key_exchange":
                print("❌ 服务器未发送公钥")
                return False
            server_key_data = server_data.get("public_key")
            server_public_key = self.security_mgr.deserialize_public_key(server_key_data)
            client_public_key = self.security_mgr.serialize_public_key()
            await websocket.send(json.dumps({
                "type": "key_exchange",
                "public_key": client_public_key
            }))
            print("📤 已发送客户端公钥")
            self.security_mgr.generate_shared_key(server_public_key)
            print("🔒 密钥交换完成，已建立共享密钥")
            confirmation = await websocket.recv()
            confirm_data = json.loads(confirmation)
            if confirm_data.get("type") == "key_exchange_complete":
                print("✅ 服务器确认密钥交换成功")
                return True
            else:
                print("⚠️ 没有收到服务器的密钥交换确认")
                return False
        except Exception as e:
            print(f"❌ 密钥交换失败: {e}")
            return False

    def _looks_like_temp_file_path(self, text):
        temp_indicators = [
            "\\AppData\\Local\\Temp\\clipshare_files\\",
            "/var/folders/",
            "/tmp/clipshare_files/",
            "C:\\Users\\\\AppData\\Local\\Temp\\clipshare_files\\"
        ]
        for indicator in text:
            if indicator in text:
                print(f"⏭️ 跳过临时文件路径: \"{text[:40]}...\"")
                return True
        return False

    def _display_progress(self, current, total, length=30):
        if total == 0:
            return
        percent = float(current) / total
        filled_length = int(length * percent)
        bar = '█' * filled_length + '░' * (length - filled_length)
        percent_str = f"{int(percent*100):3}%"
        return f"|{bar}| {current}/{total} ({percent_str})"

    async def _handle_text_message(self, message):
        try:
            text = message.get("content", "")
            if not text or self._looks_like_temp_file_path(text):
                return
            content_hash = hashlib.md5(text.encode()).hexdigest()
            if content_hash == self.last_content_hash:
                return
            # 统一通过 FileHandler 设置剪贴板文本
            self.file_handler.set_clipboard_text(text)
            self.last_content_hash = content_hash
            self.last_remote_hash = content_hash
            self.last_update_time = time.time()
            self.ignore_clipboard_until = time.time() + 2.5  # 延长忽略时间
            max_display = 50
            display_text = text[:max_display] + ("..." if len(text) > max_display else "")
            print(f"📥 已复制文本: \"{display_text}\"")
        except Exception as e:
            print(f"❌ 处理文本消息失败: {e}")
        finally:
            self.is_receiving = False

    async def _handle_file_response(self, message):
        try:
            filename = message.get("filename")
            # chunk_data = base64.b64decode(message.get("chunk_data", ""))
            if not filename:
                return
            is_complete = self.file_handler.handle_received_chunk(message)
            if is_complete:
                file_path = self.file_handler.file_transfers[filename]["path"]
                print(f"✅ 文件接收完成: {file_path}")
                try:
                    # 统一通过 FileHandler 设置剪贴板文件
                    self.file_handler.set_clipboard_file(file_path)
                    print(f"📎 已将文件添加到剪贴板: {filename}")
                    self.last_content_hash = hashlib.md5(str(file_path).encode()).hexdigest()
                    self.last_remote_hash = self.last_content_hash  # 新增：防止回环
                    self.last_update_time = time.time()
                    self.ignore_clipboard_until = time.time() + 2.0  # 文件也延长忽略时间
                except Exception as e:
                    print(f"❌ 设置剪贴板文件失败: {e}")
        except Exception as e:
            print(f"❌ 处理文件响应失败: {e}")
        finally:
            self.is_receiving = False

    async def handle_file_transfer(self, file_path: str, broadcast_fn):
        path_obj = Path(file_path)
        MAX_CHUNK_SIZE = 500 * 1024
        if not path_obj.exists() or not path_obj.is_file():
            print(f"⚠️ 文件不存在或无效: {file_path}")
            return False
        try:
            file_size = path_obj.stat().st_size
            total_chunks = (file_size + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE
            print(f"📤 开始传输文件: {path_obj.name} ({file_size/1024/1024:.1f}MB, {total_chunks}块)")
            for chunk_index in range(total_chunks):
                with open(path_obj, 'rb') as f:
                    f.seek(chunk_index * MAX_CHUNK_SIZE)
                    chunk_data = f.read(MAX_CHUNK_SIZE)
                    if not chunk_data:
                        break
                    chunk_msg = {
                        'type': MessageType.FILE_RESPONSE,
                        'filename': path_obj.name,
                        'exists': True,
                        'chunk_data': base64.b64encode(chunk_data).decode('utf-8'),
                        'chunk_index': chunk_index,
                        'total_chunks': total_chunks,
                        'chunk_hash': hashlib.md5(chunk_data).hexdigest()
                    }
                    encrypted_chunk = self.security_mgr.encrypt_message(
                        json.dumps(chunk_msg).encode('utf-8')
                    )
                    progress = self._display_progress(chunk_index + 1, total_chunks)
                    print(f"\r📤 传输文件 {path_obj.name}: {progress}", end="", flush=True)
                    await broadcast_fn(encrypted_chunk)
                    await asyncio.sleep(0.1)
            print(f"\n✅ 文件 {path_obj.name} 传输完成")
            return True
        except Exception as e:
            print(f"\n❌ 文件传输失败: {e}")
            return False

    async def show_connection_status(self):
        last_status = None
        status_messages = {
            ConnectionStatus.DISCONNECTED: "🔴 已断开连接 - 等待服务器",
            ConnectionStatus.CONNECTING: "🟡 正在连接...",
            ConnectionStatus.CONNECTED: "🟢 已连接 - 剪贴板同步已激活"
        }
        status_line = ""
        while self.running:
            try:
                if self.connection_status != last_status:
                    if (status_line):
                        import sys
                        sys.stdout.write("\r" + " " * len(status_line) + "\r")
                    status_line = status_messages.get(self.connection_status, "⚪ 未知状态")
                    import sys
                    sys.stdout.write(f"\r{status_line}")
                    sys.stdout.flush()
                    last_status = self.connection_status
                await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                break

def main():
    print("DEBUG: Starting main function...")
    client = WindowsClipboardClient()
    print("DEBUG: Client object created.")
    try:
        print("🚀 ClipShare Windows 客户端已启动")
        print("📋 按 Ctrl+C 退出程序")
        async def run_client():
            print("DEBUG: Starting run_client async function...")
            status_task = asyncio.create_task(client.show_connection_status())
            sync_task = asyncio.create_task(client.sync_clipboard())
            print("DEBUG: Async tasks created.")
            try:
                await asyncio.gather(sync_task, status_task)
            except asyncio.CancelledError:
                print("DEBUG: Main tasks cancelled.")
                if not status_task.done():
                    status_task.cancel()
                if not sync_task.done():
                    sync_task.cancel()
                await asyncio.gather(status_task, sync_task, return_exceptions=True)
        print("DEBUG: Running asyncio loop...")
        asyncio.run(run_client())
    except KeyboardInterrupt:
        print("\n👋 正在关闭 ClipShare...")
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("DEBUG: Entering finally block...")
        client.stop()
        print("DEBUG: main function finished.")

if __name__ == "__main__":
    print("DEBUG: Script execution started.")
    main()