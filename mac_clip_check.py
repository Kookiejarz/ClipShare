import AppKit
import asyncio
import websockets
import json
import signal
import time
from utils.security.crypto import SecurityManager
from utils.security.auth import DeviceAuthManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
import tempfile
from pathlib import Path
import hashlib
from handlers.file_handler import FileHandler
from config import ClipboardConfig # Import config
from utils.security.pairing import PairingManager, PairingStatus
import threading

class ClipboardListener:
    """剪贴板监听和同步服务器"""

    def __init__(self):
        """初始化剪贴板监听器"""
        self._init_basic_components()
        self._init_state_flags()
        self._init_file_handling()
        self._init_encryption()
        self.last_remote_content_hash = None
        self.last_remote_update_time = 0
        self.ignore_clipboard_until = 0 # Timestamp until which local clipboard changes are ignored
        self.pairing_mgr = PairingManager(timeout_seconds=60)
        self.pairing_mgr.set_pairing_callback(self._on_pairing_request)

    def _init_basic_components(self):
        """初始化基础组件"""
        try:
            self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
            self.security_mgr = SecurityManager()
            self.auth_mgr = DeviceAuthManager()
            self.discovery = DeviceDiscovery()
            self.connected_clients = set()
            print("✅ 基础组件初始化成功")
        except Exception as e:
            print(f"❌ 基础组件初始化失败: {e}")
            raise

    def _init_state_flags(self):
        """初始化状态标志"""
        self.last_change_count = self.pasteboard.changeCount()
        self.last_content_hash = None # Hash of the last content *sent* or *set* by this instance
        self.is_receiving = False # Flag to prevent processing while receiving
        self.last_update_time = 0 # Timestamp of the last clipboard update *initiated by this instance*
        self.running = True
        self.server = None

    def _init_file_handling(self):
        """初始化文件处理相关"""
        try:
            # Use ClipboardConfig for temp dir
            self.temp_dir = ClipboardConfig.get_temp_dir()
            self.file_handler = FileHandler(self.temp_dir, self.security_mgr)
            # Load cache during init
            self.file_handler.load_file_cache()
        except Exception as e:
            print(f"❌ 文件处理初始化失败: {e}")
            raise

    def _init_encryption(self):
        """初始化加密系统"""
        try:
            # Key pair generation might be better done just before exchange
            self.security_mgr.generate_key_pair()
            print("✅ 加密系统准备就绪")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")
            raise

    # Removed load_file_cache as it's called in _init_file_handling

    def _on_pairing_request(self, request):
        """Handle pairing request - show notification to user"""
        print(f"\n{'='*60}")
        print(f"🔗 新设备请求配对:")
        print(f"   设备名称: {request.device_name}")
        print(f"   平台: {request.platform}")
        print(f"   IP地址: {request.ip_address}")
        print(f"   设备ID: {request.device_id}")
        print(f"{'='*60}")
        print(f"是否允许此设备连接? (输入 'y' 接受, 'n' 拒绝)")
        
        # Start input thread to not block async operations
        def get_user_input():
            try:
                choice = input().strip().lower()
                if choice in ['y', 'yes', 'accept', '是', '接受']:
                    self.pairing_mgr.accept_pairing(request.device_id)
                else:
                    self.pairing_mgr.reject_pairing(request.device_id)
            except:
                self.pairing_mgr.reject_pairing(request.device_id)
                
        threading.Thread(target=get_user_input, daemon=True).start()

    async def handle_client(self, websocket):
        """处理 WebSocket 客户端连接"""
        device_id = None
        client_ip = websocket.remote_address[0] if websocket.remote_address else "未知IP"
        try:
            # --- Authentication / Pairing ---
            auth_message = await websocket.recv()
            try:
                if isinstance(auth_message, str):
                    message_data = json.loads(auth_message)
                else:
                    message_data = json.loads(auth_message.decode('utf-8'))

                device_id = message_data.get('identity', f'unknown-{client_ip}')
                signature = message_data.get('signature', '')
                is_first_time = message_data.get('first_time', False)

                print(f"📱 设备 {device_id} ({client_ip}) 尝试连接")

                if is_first_time:
                    print(f"🆕 设备 {device_id} 首次连接，需要配对...")
                    
                    # Request pairing
                    pairing_request = await self.pairing_mgr.request_pairing(
                        device_id, message_data, client_ip
                    )
                    
                    # Wait for user decision
                    pairing_result = await self.pairing_mgr.wait_for_pairing_result(device_id)
                    
                    if pairing_result == PairingStatus.ACCEPTED:
                        # Generate and send token
                        token = self.auth_mgr.authorize_device(device_id, {
                            "name": message_data.get("device_name", "未命名设备"),
                            "platform": message_data.get("platform", "未知平台"),
                            "ip": client_ip
                        })
                        await websocket.send(json.dumps({
                            'status': 'pairing_accepted',
                            'server_id': 'mac-server',
                            'token': token
                        }))
                        print(f"✅ 设备 {device_id} 配对成功并已授权")
                    elif pairing_result == PairingStatus.REJECTED:
                        await websocket.send(json.dumps({
                            'status': 'pairing_rejected',
                            'reason': 'User rejected pairing request'
                        }))
                        print(f"❌ 设备 {device_id} 配对被拒绝")
                        return
                    else:  # EXPIRED
                        await websocket.send(json.dumps({
                            'status': 'pairing_expired',
                            'reason': 'Pairing request timed out'
                        }))
                        print(f"⏰ 设备 {device_id} 配对请求超时")
                        return
                else:
                    # Existing device authentication
                    print(f"🔐 验证设备 {device_id} 的签名")
                    is_valid = self.auth_mgr.validate_device(device_id, signature)
                    if not is_valid:
                        print(f"❌ 设备 {device_id} 验证失败")
                        await websocket.send(json.dumps({
                            'status': 'unauthorized',
                            'reason': 'Invalid signature or unknown device'
                        }))
                        return # Close connection
                    await websocket.send(json.dumps({
                        'status': 'authorized',
                        'server_id': 'mac-server'
                    }))
                    print(f"✅ 设备 {device_id} 验证成功")

            except json.JSONDecodeError:
                print(f"❌ 来自 {client_ip} 的无效消息格式")
                await websocket.send(json.dumps({
                    'status': 'error',
                    'reason': 'Invalid message format'
                }))
                return
            except Exception as auth_err:
                 print(f"❌ 处理消息错误 for {device_id or client_ip}: {auth_err}")
                 await websocket.send(json.dumps({
                    'status': 'error',
                    'reason': f'Message processing failed: {auth_err}'
                 }))
                 return

            # --- Key Exchange ---
            if not await self.perform_key_exchange(websocket):
                print(f"❌ 与 {device_id} 的密钥交换失败，断开连接")
                return

            # --- Add Client and Start Receiving ---
            self.connected_clients.add(websocket)
            print(f"✅ 设备 {device_id} 已连接并完成密钥交换")

            while self.running: # Rely on exceptions inside the loop to detect closure
                try:
                    # Use longer timeout or rely on keepalive if implemented
                    encrypted_data = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    # Pass the specific client's websocket for potential direct replies
                    await self.process_received_data(encrypted_data, sender_websocket=websocket)
                except asyncio.TimeoutError:
                    # Send keepalive ping or check connection status
                    try:
                        pong_waiter = await websocket.ping()
                        await asyncio.wait_for(pong_waiter, timeout=5)
                    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                        print(f"⌛ 与 {device_id} 的连接超时或关闭，断开")
                        break # Exit loop on timeout/close during ping
                    continue # Continue loop after successful ping/pong
                except asyncio.CancelledError:
                    print(f"⏹️ {device_id} 的连接处理已取消")
                    break # Exit loop on cancellation
                except websockets.exceptions.ConnectionClosedOK:
                     print(f"ℹ️ 设备 {device_id} 正常断开连接")
                     break # Exit loop on normal closure
                except websockets.exceptions.ConnectionClosedError as e:
                     print(f"🔌 设备 {device_id} 异常断开连接: {e}")
                     break # Exit loop on error closure
                except Exception as e:
                    print(f"❌ 处理来自 {device_id} 的数据时出错: {e}")
                    import traceback
                    traceback.print_exc()
                    # Simply sleep without trying to check connection state
                    # The ConnectionClosed exceptions will catch closed connections
                    await asyncio.sleep(1) # Avoid tight loop on other errors

        except websockets.exceptions.ConnectionClosed as e:
            # This might catch cases where connection closes before loop starts
            print(f"📴 设备 {device_id or client_ip} 连接已关闭: {e}")
        except Exception as e:
            print(f"❌ 处理客户端 {device_id or client_ip} 时发生意外错误: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if websocket in self.connected_clients:
                self.connected_clients.remove(websocket)
            print(f"➖ 设备 {device_id or client_ip} 已断开")


    async def _send_encrypted(self, data: bytes, websocket):
        """Helper to encrypt and send data to a specific websocket."""
        try:
            encrypted = self.security_mgr.encrypt_message(data)
            await websocket.send(encrypted)
        except Exception as e:
            print(f"❌ 发送加密数据失败: {e}")
            # Handle potential connection closure
            if websocket in self.connected_clients:
                self.connected_clients.remove(websocket)


    async def process_received_data(self, encrypted_data, sender_websocket=None):
        """处理从客户端接收到的加密数据"""
        if not sender_websocket: # Should always have a sender
             print("⚠️ process_received_data called without sender_websocket")
             return

        try:
            self.is_receiving = True # Set flag to pause local clipboard monitoring
            decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
            message_json = decrypted_data.decode('utf-8')
            message = ClipMessage.deserialize(message_json)

            if not message or "type" not in message:
                 print("⚠️ 收到的消息格式无效或无法解析")
                 return

            msg_type = message["type"]
            print(f"📬 收到消息类型: {msg_type}") # Log received type

            if msg_type == MessageType.TEXT:
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
                self.pasteboard.clearContents()
                success = self.pasteboard.setString_forType_(text, AppKit.NSPasteboardTypeString)

                if success:
                    # Update state *after* successful clipboard operation
                    self.last_change_count = self.pasteboard.changeCount()
                    self.last_content_hash = content_hash # Mark this hash as processed locally
                    self.last_update_time = time.time() # Mark time of local update
                    self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY # Ignore local changes briefly

                    # Record hash and time from remote sender for loop detection
                    self.last_remote_content_hash = content_hash
                    self.last_remote_update_time = time.time()

                    # Display received text
                    display_text = text[:ClipboardConfig.MAX_DISPLAY_LENGTH] + ("..." if len(text) > ClipboardConfig.MAX_DISPLAY_LENGTH else "")
                    print(f"📥 已复制文本: \"{display_text}\"")
                else:
                    print("❌ 更新Mac剪贴板失败")


            elif msg_type == MessageType.FILE:
                # Handle file info message - request missing files
                # Pass a function to encrypt and send data back to the *sender*
                await self.file_handler.handle_received_files(
                    message,
                    lambda data: self._send_encrypted(data, sender_websocket), # Send request back to sender
                    sender_websocket=sender_websocket # Pass sender for context if needed by handler
                )

            elif msg_type == MessageType.FILE_RESPONSE:
                # Handle incoming file chunk
                is_complete, completed_path = self.file_handler.handle_received_chunk(message)
                if is_complete and completed_path:
                    print(f"✅ 文件接收完成: {completed_path}")

                    # Calculate hash of the completed file
                    content_hash = self.file_handler.get_files_content_hash([str(completed_path)])

                    # Check if this file content hash was the last one *we* sent or set
                    if content_hash and content_hash == self.last_content_hash:
                         print("⏭️ 跳过重复文件内容 (与本地最后发送/设置一致)")
                         return

                    # Store info but delay clipboard setting until after all logging
                    file_to_set = completed_path
                    content_hash_to_use = content_hash
                    
                    # Set file to clipboard AFTER all processing/logging
                    await asyncio.sleep(0.1)  # Let any pending logs flush
                    change_count = self.file_handler.set_clipboard_file(file_to_set)
                    if change_count is not None:
                        # Update change count to track the clipboard state
                        self.last_change_count = change_count
                        
                        # Mark this specific content as processed to prevent re-broadcast
                        self.last_content_hash = content_hash_to_use  # Mark as processed
                        self.last_update_time = time.time()
                        
                        # Completely stop clipboard monitoring temporarily
                        self.ignore_clipboard_until = time.time() + 10.0  # 10 second ignore period
                        
                        # Record remote hash for loop detection
                        self.last_remote_content_hash = content_hash_to_use
                        self.last_remote_update_time = time.time()
                        
                        print("✅ 文件已设置到剪贴板并可用于粘贴")
                        print("🔄 文件已标记为已处理，防止重复广播")
                        print("⏳ 暂停监控10秒以确保文件可访问")
                        print("💡 在接下来10秒内，您可以自由粘贴文件而不受监控干扰")

                        # No delay needed since monitoring is paused
                        # await asyncio.sleep(0.05)

                    else:
                         print(f"❌ 将文件 {completed_path.name} 设置到剪贴板失败")

            elif msg_type == MessageType.FILE_REQUEST:
                 # Handle request from a client to send a file
                 file_path_requested = message.get("path")
                 if file_path_requested:
                      # Normalize path separators for cross-platform compatibility
                      normalized_path = file_path_requested.replace('\\', '/')
                      print(f"📤 收到文件请求: {Path(normalized_path).name}")
                      print(f"🔍 原始路径: {file_path_requested}")
                      print(f"🔍 标准化路径: {normalized_path}")
                      # Pass a function to encrypt and send data back to the *requester*
                      await self.file_handler.handle_file_transfer(
                           normalized_path,
                           lambda data: self._send_encrypted(data, sender_websocket) # Send file chunks back to sender
                      )
                 else:
                      print("⚠️ 收到的文件请求缺少路径")

            else:
                 print(f"⚠️ 未知消息类型: {msg_type}")


        except json.JSONDecodeError:
             print("❌ 收到的消息不是有效的JSON")
        except UnicodeDecodeError:
             print("❌ 无法将收到的消息解码为UTF-8")
        except Exception as e:
            print(f"❌ 处理接收数据时出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_receiving = False # Release lock


    async def broadcast_encrypted_data(self, data_to_encrypt: bytes, exclude_client=None):
        """Encrypts and broadcasts data to all connected clients, excluding one if specified."""
        if not self.connected_clients:
            return

        try:
            encrypted_data = self.security_mgr.encrypt_message(data_to_encrypt)
        except Exception as e:
             print(f"❌ 加密广播数据失败: {e}")
             return

        active_clients = list(self.connected_clients) # Create a stable list for iteration
        broadcast_count = len(active_clients) - (1 if exclude_client in active_clients else 0)

        if broadcast_count <= 0:
            # print("ℹ️ 没有需要广播的客户端") # Less verbose
            return

        # print(f"📢 广播数据 ({len(encrypted_data)} 字节) 到 {broadcast_count} 个客户端") # Less verbose

        tasks = []
        for client in active_clients:
            if client == exclude_client:
                continue
            try:
                # Ensure data is sent as bytes
                tasks.append(asyncio.create_task(client.send(encrypted_data)))
            except Exception as e:
                print(f"❌ 创建广播任务失败: {e}")
                # Remove problematic client immediately?
                if client in self.connected_clients: self.connected_clients.remove(client)

        # Wait for all send tasks to complete (with a timeout)
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=10.0) # 10 second timeout for broadcast

            # Handle timeouts or errors during broadcast
            if pending:
                print(f"⚠️ {len(pending)} 个广播任务超时")
                for task in pending:
                    task.cancel()
            # Check for exceptions in completed tasks
            for task in done:
                 if task.exception():
                      print(f"❌ 广播发送时出错: {task.exception()}")
                      # Potentially identify and remove the client associated with the failed task
                      # This requires mapping tasks back to clients, which adds complexity.
                      # For now, rely on the main handle_client loop to detect closed connections.


    async def start_server(self, port=ClipboardConfig.DEFAULT_PORT): # Use config
        """启动 WebSocket 服务器"""
        stop_event = asyncio.Event() # Event to signal server stop

        async def server_logic():
            try:
                # Specify websockets use binary mode via subprotocols
                self.server = await websockets.serve(
                    self.handle_client,
                    ClipboardConfig.HOST, # Use config
                    port,
                    subprotocols=["binary"],
                    ping_interval=20, # Send pings every 20s
                    ping_timeout=20   # Wait 20s for pong response
                )
                await self.discovery.start_advertising(port)
                print(f"🌐 WebSocket 服务器启动在 {ClipboardConfig.HOST}:{port}")

                # Wait until stop_event is set
                await stop_event.wait()

            except OSError as e:
                 if "Address already in use" in str(e):
                      print(f"❌ 错误: 端口 {port} 已被占用。请关闭使用该端口的其他程序或选择不同端口。")
                 else:
                      print(f"❌ 服务器启动错误: {e}")
            except Exception as e:
                print(f"❌ 服务器错误: {e}")
            finally:
                # Stop advertising
                self.discovery.close()
                
                # Close all connected clients first
                if self.connected_clients:
                    print(f"📤 正在关闭 {len(self.connected_clients)} 个连接...")
                    close_tasks = []
                    for client in list(self.connected_clients):
                        close_tasks.append(client.close())
                    if close_tasks:
                        await asyncio.gather(*close_tasks, return_exceptions=True)
                    self.connected_clients.clear()
                
                # Close server if running
                if self.server:
                    self.server.close()
                    try:
                         await asyncio.wait_for(self.server.wait_closed(), timeout=2.0)
                         print("✅ WebSocket 服务器已关闭")
                    except asyncio.TimeoutError:
                         print("⚠️ WebSocket 服务器关闭超时")
                self.server = None # Ensure server attribute is cleared

        self._stop_server_func = stop_event.set # Store the function to stop the server
        await server_logic()


    async def check_clipboard(self):
        """轮询检查剪贴板内容变化"""
        print("📋 剪贴板监听已启动...")
        last_processed_time = 0

        while self.running:
            try:
                current_time = time.time()

                # Ignore if we are currently processing a received update
                if self.is_receiving:
                    await asyncio.sleep(0.1) # Short sleep while receiving
                    continue

                # Ignore if we recently updated the clipboard locally
                if current_time < self.ignore_clipboard_until:
                    await asyncio.sleep(0.1) # Short sleep during ignore window
                    continue

                # Check if enough time has passed since the last processing
                time_since_process = current_time - last_processed_time
                if time_since_process < ClipboardConfig.MIN_PROCESS_INTERVAL:
                    await asyncio.sleep(0.1) # Wait if processing too frequently
                    continue

                # Check for actual clipboard change count
                new_change_count = self.pasteboard.changeCount()
                if new_change_count != self.last_change_count:
                    print(f"📋 剪贴板变化 detected (Count: {self.last_change_count} -> {new_change_count})")
                    
                    # Debug: Show what types are on clipboard
                    types = self.pasteboard.types()
                    print(f"🔍 剪贴板类型: {list(types)}")
                    
                    self.last_change_count = new_change_count
                    processed = await self.process_clipboard()
                    if processed:
                        last_processed_time = time.time() # Update last processed time only if something was sent

                # Regular check interval
                await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)

            except asyncio.CancelledError:
                print("⏹️ 剪贴板监听已停止")
                break
            except Exception as e:
                print(f"❌ 剪贴板监听错误: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(1) # Longer sleep on error


    async def process_clipboard(self) -> bool:
        """
        处理本地剪贴板内容变化, 发送给客户端.
        Returns True if an update was sent, False otherwise.
        """
        types = self.pasteboard.types()
        sent_update = False
        try:
            # --- Handle Files First (if present) ---
            if AppKit.NSPasteboardTypeFileURL in types:
                file_urls = []
                # Correctly iterate through pasteboard items to get file URLs
                for item in self.pasteboard.pasteboardItems():
                    url_str = item.stringForType_(AppKit.NSPasteboardTypeFileURL)
                    if url_str:
                        # Convert file URL string to path
                        url = AppKit.NSURL.URLWithString_(url_str)
                        if url and url.isFileURL():
                             file_path = url.path()
                             if file_path and Path(file_path).exists(): # Check existence
                                  file_urls.append(file_path)
                             else:
                                  print(f"⚠️ 剪贴板中的文件路径无效或不存在: {file_path}")

                if file_urls and self.connected_clients:
                    # Use FileHandler to create and send file info message
                    new_hash, update_sent = await self.file_handler.handle_clipboard_files(
                        file_urls,
                        self.last_content_hash,
                        self.broadcast_encrypted_data # Pass broadcast function
                    )
                    if update_sent:
                        self.last_content_hash = new_hash
                        self.last_update_time = time.time()
                        sent_update = True
                        # File info sent - clients will request files they need
                        print("📤 文件信息已发送，等待客户端请求文件内容...")
                    return sent_update # Return immediately after handling files

            # --- Handle Text (if no files were handled) ---
            if AppKit.NSPasteboardTypeString in types:
                text = self.pasteboard.stringForType_(AppKit.NSPasteboardTypeString)
                if text and self.connected_clients: # Ensure text is not empty and we have connected clients
                    # Anti-loop check: Compare with last received remote hash
                    content_hash = hashlib.md5(text.encode()).hexdigest()
                    if (self.last_remote_content_hash == content_hash and
                        time.time() - self.last_remote_update_time < ClipboardConfig.UPDATE_DELAY * 2): # Wider window for remote check
                        # print("⏭️ 跳过发送回环内容 (与远程接收一致)") # Less verbose
                        return False # Don't send back recently received content

                    # Use FileHandler to process and send text message
                    current_time = time.time()
                    new_hash, new_time, update_sent = await self.file_handler.process_clipboard_content(
                        text,
                        current_time,
                        self.last_content_hash,
                        self.last_update_time,
                        self.broadcast_encrypted_data # Pass broadcast function
                    )
                    if update_sent:
                        self.last_content_hash = new_hash
                        self.last_update_time = new_time
                        sent_update = True
                    return sent_update

            # --- Handle Images (Optional, Placeholder) ---
            if AppKit.NSPasteboardTypePNG in types:
                print("⚠️ 图片同步暂不支持")
                # Future: Extract PNG data, use file handler logic
                # png_data = self.pasteboard.dataForType_(AppKit.NSPasteboardTypePNG)
                # if png_data:
                #    # Save to temp file, use handle_clipboard_files?
                #    pass

        except Exception as e:
            print(f"❌ 处理剪贴板内容时出错: {e}")
            import traceback
            traceback.print_exc()

        return sent_update # Return whether an update was sent


    async def perform_key_exchange(self, websocket):
        """Perform key exchange with client"""
        # Generate keys just before exchange if not already done
        if not self.security_mgr.private_key:
             self.security_mgr.generate_key_pair()

        # Create wrapper functions for sending/receiving through websocket
        async def send_to_websocket(data):
            await websocket.send(data)

        async def receive_from_websocket():
            return await websocket.recv()

        # Use the SecurityManager's key exchange implementation
        return await self.security_mgr.perform_key_exchange(
            send_to_websocket,
            receive_from_websocket
        )

    # Removed _looks_like_temp_file_path (moved to FileHandler)

    def stop(self):
        """Signals the server and related tasks to stop."""
        if not self.running:
             return # Already stopping
        print("\n⏹️ 正在请求停止服务器...")
        self.running = False

        # Signal the server task to stop
        if hasattr(self, '_stop_server_func'):
            self._stop_server_func()

        # Cancel clipboard task (if running) - Requires storing the task reference
        if hasattr(self, 'clipboard_task') and self.clipboard_task and not self.clipboard_task.done():
             self.clipboard_task.cancel()

        # Close discovery (already handled in server_logic finally block, but safe to call again)
        self.discovery.close()

        # Clear client list (connections will close naturally or in handle_client)
        # self.connected_clients.clear() # Let handle_client manage removal

        # Save file cache on exit
        if hasattr(self, 'file_handler'):
             self.file_handler.save_file_cache()

        print("👋 感谢使用 UniPaste 服务器!")

    # Removed get_files_content_hash (moved to FileHandler)


async def main():
    # Ensure NSApplication shared instance exists for main thread operations
    # Needs to be done before listener might use AppKit features indirectly
    app = AppKit.NSApplication.sharedApplication() # Initialize AppKit

    listener = ClipboardListener()

    # Setup signal handling for graceful shutdown
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        print("\n⚠️ 接收到关闭信号...")
        if not stop_event.is_set():
             listener.stop() # Initiate graceful shutdown
             stop_event.set() # Signal main loop to exit

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
             # Windows doesn't support add_signal_handler for console apps well
             print(f"ℹ️ 信号 {sig} 处理在当前系统可能不受支持。请使用 Ctrl+C。")


    try:
        print("🚀 UniPaste Mac 服务器已启动")
        print(f"📂 临时文件目录: {listener.temp_dir}")
        print("📋 按 Ctrl+C 退出程序")

        # Store task references for potential cancellation
        server_task = asyncio.create_task(listener.start_server())
        listener.clipboard_task = asyncio.create_task(listener.check_clipboard()) # Store reference

        # Wait for tasks (or stop signal)
        await asyncio.gather(server_task, listener.clipboard_task)

    except asyncio.CancelledError:
        print("\n⏹️ 主任务已取消")
    except Exception as e:
        print(f"\n❌ 发生未处理的错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Ensure stop is called even if gather fails unexpectedly
        if listener.running:
             listener.stop()
        # Final cleanup delay
        await asyncio.sleep(0.5)
        print("🚪 程序退出")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
         print("\n⌨️ 检测到 Ctrl+C，强制退出...")
         # Perform minimal cleanup if needed, but asyncio.run handles task cancellation
