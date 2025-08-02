"""
UniPaste Mac Server
Clipboard synchronization server for macOS systems
Handles multiple client connections and clipboard broadcasting
"""

import asyncio
import hashlib
import json
import signal
import tempfile
import time
from pathlib import Path

import AppKit
import websockets

from config import ClipboardConfig
from handlers.file_handler import FileHandler
from utils.connection_utils import ConnectionManager
from utils.constants import ConnectionStatus
from utils.message_format import ClipMessage, MessageType
from utils.network.discovery import DeviceDiscovery
from utils.security.auth import DeviceAuthManager
from utils.security.crypto import SecurityManager

class ClipboardListener:
    """
    Mac clipboard server for UniPaste
    Manages clipboard synchronization and file transfers across multiple clients
    """

    def __init__(self):
        """初始化剪贴板监听器"""
        self._init_basic_components()
        self._init_state_flags()
        self._init_file_handling()
        self._init_encryption()
        self.last_remote_content_hash = None
        self.last_remote_update_time = 0
        self.ignore_clipboard_until = 0 # Timestamp until which local clipboard changes are ignored

    def _init_basic_components(self):
        """初始化基础组件"""
        try:
            self.pasteboard = AppKit.NSPasteboard.generalPasteboard()
            self.security_mgr = SecurityManager()
            self.auth_mgr = DeviceAuthManager()
            self.discovery = DeviceDiscovery()
            self.connected_clients = set()
            self.client_connection_managers = {}  # Track reconnection state per client
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
            
            # 确保 temp_dir 是 Path 对象
            if not isinstance(self.temp_dir, Path):
                self.temp_dir = Path(self.temp_dir)
                
            # 创建 FileHandler 实例
            self.file_handler = FileHandler(self.temp_dir, self.security_mgr)
            
            # Load cache during init
            self.file_handler.load_file_cache()
        except Exception as e:
            print(f"❌ 文件处理初始化失败: {e}")
            print(f"详细错误信息: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
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

    # ================== Security & Authentication ==================

    async def perform_key_exchange(self, websocket):
        """执行密钥交换"""
        try:
            print("🔑 开始服务器端密钥交换...")
            
            # Generate server's key pair if not already done
            if not hasattr(self.security_mgr, 'private_key') or not self.security_mgr.private_key:
                print("🔧 生成服务器密钥对...")
                self.security_mgr.generate_key_pair()
            
            # Get server's public key
            server_public_key = self.security_mgr.get_public_key_pem()
            print(f"📤 发送服务器公钥 ({len(server_public_key)} 字符)")
            
            # Send server's public key to client
            key_exchange_message = {
                'type': 'key_exchange_server',
                'public_key': server_public_key
            }
            await websocket.send(json.dumps(key_exchange_message))
            print("✅ 服务器公钥已发送，等待客户端响应...")
            
            # Wait for client's public key response
            client_response = await asyncio.wait_for(websocket.recv(), timeout=15.0)
            print(f"📨 收到客户端响应 ({len(client_response)} 字节)")
            
            if isinstance(client_response, bytes):
                client_response = client_response.decode('utf-8')
            
            client_data = json.loads(client_response)
            print(f"📋 客户端消息类型: {client_data.get('type')}")
            
            if client_data.get('type') != 'key_exchange_client':
                print(f"❌ 收到无效的密钥交换响应类型: {client_data.get('type')}")
                return False
            
            client_public_key_pem = client_data.get('public_key')
            if not client_public_key_pem:
                print("❌ 客户端未提供公钥")
                return False
            
            print(f"📥 收到客户端公钥 ({len(client_public_key_pem)} 字符)")
            
            # Store client's public key in security manager
            success = self.security_mgr.set_peer_public_key(client_public_key_pem)
            if not success:
                print("❌ 无法设置客户端公钥")
                return False
            
            print("✅ 客户端公钥已设置")
            
            # Verify shared key is established
            if not hasattr(self.security_mgr, 'shared_key') or not self.security_mgr.shared_key:
                print("❌ 共享密钥未建立")
                return False
            
            print("✅ 共享密钥验证成功")
            
            # Send confirmation
            confirmation_message = {
                'type': 'key_exchange_complete',
                'status': 'success'
            }
            await websocket.send(json.dumps(confirmation_message))
            print("📤 发送密钥交换完成确认")
            
            print("🔑 密钥交换成功完成")
            return True
            
        except asyncio.TimeoutError:
            print("❌ 密钥交换超时 - 客户端可能未响应")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ 密钥交换响应格式无效: {e}")
            return False
        except Exception as e:
            print(f"❌ 密钥交换过程中出错: {e}")
            import traceback
            traceback.print_exc()
            return False

    # ================== Client Connection Management ==================
    
    async def handle_client(self, websocket):
        """处理 WebSocket 客户端连接"""
        device_id = None
        client_ip = websocket.remote_address[0] if websocket.remote_address else "未知IP"
        try:
            # --- Authentication ---
            auth_message = await websocket.recv()
            try:
                # ... existing authentication logic ...
                # (Ensure device_id is set correctly after successful auth)
                if isinstance(auth_message, str):
                    auth_info = json.loads(auth_message)
                else:
                    auth_info = json.loads(auth_message.decode('utf-8'))

                device_id = auth_info.get('identity', f'unknown-{client_ip}') # Use IP if ID missing
                signature = auth_info.get('signature', '')
                is_first_time = auth_info.get('first_time', False)

                print(f"📱 设备 {device_id} ({client_ip}) 尝试连接")

                if is_first_time:
                    print(f"🆕 设备 {device_id} 首次连接，授权中...")
                    token = self.auth_mgr.authorize_device(device_id, {
                        "name": auth_info.get("device_name", "未命名设备"),
                        "platform": auth_info.get("platform", "未知平台"),
                        "ip": client_ip # Store IP for info
                    })
                    await websocket.send(json.dumps({
                        'status': 'first_authorized',
                        'server_id': 'mac-server',
                        'token': token
                    }))
                    print(f"✅ 已授权设备 {device_id} 并发送令牌")
                else:
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
                print(f"❌ 来自 {client_ip} 的无效身份验证信息")
                await websocket.send(json.dumps({
                    'status': 'error',
                    'reason': 'Invalid authentication format'
                }))
                return
            except Exception as auth_err:
                 print(f"❌ 身份验证错误 for {device_id or client_ip}: {auth_err}")
                 await websocket.send(json.dumps({
                    'status': 'error',
                    'reason': f'Authentication failed: {auth_err}'
                 }))
                 return

            # --- Key Exchange ---
            if not await self.perform_key_exchange(websocket):
                print(f"❌ 与 {device_id} 的密钥交换失败，断开连接")
                return

            # --- Add Client and Start Receiving ---
            self.connected_clients.add(websocket)
            
            # Reset connection manager for this client on successful connection
            if device_id not in self.client_connection_managers:
                self.client_connection_managers[device_id] = ConnectionManager()
            self.client_connection_managers[device_id].reset_reconnect_delay()
            
            print(f"✅ 设备 {device_id} 已连接并完成密钥交换")

            while self.running: # Rely on exceptions inside the loop to detect closure
                try:
                    # Use longer timeout to reduce unnecessary disconnects (5 minutes)
                    encrypted_data = await asyncio.wait_for(websocket.recv(), timeout=300.0)
                    # Pass the specific client's websocket for potential direct replies
                    await self.process_received_data(encrypted_data, sender_websocket=websocket)
                except asyncio.TimeoutError:
                    # Send keepalive ping or check connection status
                    try:
                        pong_waiter = await websocket.ping()
                        await asyncio.wait_for(pong_waiter, timeout=30)
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
            
            # Log disconnection with retry info if available
            if device_id and device_id in self.client_connection_managers:
                mgr = self.client_connection_managers[device_id]
                if mgr.connection_attempts > 0:
                    print(f"➖ 设备 {device_id or client_ip} 已断开 (曾重试 {mgr.connection_attempts} 次)")
                else:
                    print(f"➖ 设备 {device_id or client_ip} 已断开")
            else:
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

    # ================== Message Processing ==================

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

                    # Set the completed file to the clipboard with timeout protection
                    try:
                        print(f"📎 正在将文件设置到剪贴板: {completed_path.name}")
                        change_count = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, 
                                self.file_handler.set_clipboard_file, 
                                completed_path
                            ),
                            timeout=10.0  # 10 second timeout
                        )
                        
                        if change_count is not None:
                            # Update state *after* successful clipboard operation
                            self.last_change_count = change_count
                            self.last_content_hash = content_hash # Mark this hash as processed locally
                            self.last_update_time = time.time() # Mark time of local update
                            self.ignore_clipboard_until = time.time() + ClipboardConfig.UPDATE_DELAY # Ignore local changes briefly

                            # Record hash and time from remote sender for loop detection
                            self.last_remote_content_hash = content_hash
                            self.last_remote_update_time = time.time()

                            print(f"✅ 文件 {completed_path.name} 已成功设置到剪贴板")

                        else:
                             print(f"❌ 将文件 {completed_path.name} 设置到剪贴板失败")
                             
                    except asyncio.TimeoutError:
                        print(f"❌ 设置文件 {completed_path.name} 到剪贴板超时（10秒）")
                    except Exception as e:
                        print(f"❌ 设置文件 {completed_path.name} 到剪贴板时出错: {e}")
                        import traceback
                        traceback.print_exc()

            elif msg_type == MessageType.FILE_REQUEST:
                 # Handle request from a client to send a file
                 file_path_requested = message.get("path")
                 if file_path_requested:
                      print(f"📤 收到文件请求: {Path(file_path_requested).name}")
                      # Pass a function to encrypt and send data back to the *requester*
                      await self.file_handler.handle_file_transfer(
                           file_path_requested,
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

    # ================== Clipboard Operations ==================

    async def process_clipboard(self) -> bool:
        """
        处理本地剪贴板内容变化, 发送给客户端.
        Returns True if an update was sent, False otherwise.
        """
        # Check if there are any connected clients before processing
        if not self.connected_clients:
            # print("ℹ️ 没有连接的客户端，跳过剪贴板处理") # Uncomment for debugging
            return False
        
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
                                  path_obj = Path(file_path)
                                  if path_obj.is_file():
                                      file_urls.append(file_path)
                                  elif path_obj.is_dir():
                                      print(f"📁 检测到文件夹: {path_obj.name}")
                                      # 收集文件夹中的所有文件
                                      folder_files = []
                                      try:
                                          for item in path_obj.rglob('*'):
                                              if item.is_file():
                                                  folder_files.append(str(item))
                                          if folder_files:
                                              file_urls.extend(folder_files)
                                              print(f"📁 从文件夹 {path_obj.name} 中找到 {len(folder_files)} 个文件")
                                          else:
                                              print(f"⚠️ 文件夹 {path_obj.name} 中没有文件")
                                      except Exception as e:
                                          print(f"❌ 读取文件夹 {path_obj.name} 时出错: {e}")
                             else:
                                  print(f"⚠️ 剪贴板中的文件路径无效或不存在: {file_path}")

                if file_urls:
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
                        # Initiate the actual file transfer after sending info
                        print("🔄 准备主动传输文件内容...")
                        for file_path in file_urls:
                             # Pass broadcast function for sending chunks
                             await self.file_handler.handle_file_transfer(
                                  file_path, self.broadcast_encrypted_data
                             )
                    return sent_update # Return immediately after handling files

            # --- Handle Text (if no files were handled) ---
            if AppKit.NSPasteboardTypeString in types:
                text = self.pasteboard.stringForType_(AppKit.NSPasteboardTypeString)
                if text: # Ensure text is not empty
                    # Skip system debug messages to prevent clipboard pollution
                    if any(debug_marker in text for debug_marker in ["🔄", "🔍", "调试信息", "连接成功", "重置重试延迟"]):
                        print(f"⏭️ 跳过系统调试消息: {text[:30]}...")
                        return False
                        
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

    # ================== Network Broadcasting ==================

    async def broadcast_encrypted_data(self, data_to_encrypt: bytes, exclude_client=None):
        """Encrypts and broadcasts data to all connected clients, excluding one if specified."""
        if not self.connected_clients:
            # print("ℹ️ 没有连接的客户端，跳过广播") # Uncomment for debugging
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

        print(f"📤 尝试广播数据到 {broadcast_count} 个客户端...")

        tasks = []
        client_task_map = {}  # Track which task belongs to which client
        for client in active_clients:
            if client == exclude_client:
                continue
            try:
                # Ensure data is sent as bytes
                task = asyncio.create_task(client.send(encrypted_data))
                tasks.append(task)
                client_task_map[task] = client
            except Exception as e:
                print(f"❌ 创建广播任务失败: {e}")
                # Remove problematic client immediately
                if client in self.connected_clients: 
                    self.connected_clients.remove(client)
                    broadcast_count -= 1

        # Wait for all send tasks to complete (with a timeout)
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=10.0) # 10 second timeout for broadcast

            successful_sends = 0
            failed_clients = []
            
            # Handle timeouts
            if pending:
                print(f"⚠️ {len(pending)} 个广播任务超时")
                for task in pending:
                    failed_client = client_task_map[task]
                    failed_clients.append(failed_client)
                    task.cancel()
            
            # Check for exceptions in completed tasks
            for task in done:
                if task.exception():
                    failed_client = client_task_map[task]
                    failed_clients.append(failed_client)
                    print(f"❌ 广播发送时出错: {task.exception()}")
                else:
                    successful_sends += 1
            
            # Remove failed clients
            for client in failed_clients:
                if client in self.connected_clients:
                    self.connected_clients.remove(client)
                    print(f"🔌 移除失败的客户端连接")
            
            # Report actual success
            if successful_sends > 0:
                print(f"✅ 成功广播到 {successful_sends} 个客户端")
            else:
                print(f"❌ 广播失败，没有客户端接收到数据")
        else:
            print(f"⚠️ 没有有效的客户端可以广播")

    # ================== Server Management ==================

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
                    ping_interval=60, # Send pings every minute
                    ping_timeout=30   # Wait 30s for pong response
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
                # Close server if running
                if self.server:
                    self.server.close()
                    try:
                         await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
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

                # Skip processing if no clients are connected
                if not self.connected_clients:
                    await asyncio.sleep(ClipboardConfig.CLIPBOARD_CHECK_INTERVAL)
                    continue

                # Ignore if we are currently processing a received update
                if self.is_receiving:
                    await asyncio.sleep(0.05) # Very short sleep while receiving
                    continue

                # Ignore if we recently updated the clipboard locally
                if current_time < self.ignore_clipboard_until:
                    await asyncio.sleep(0.05) # Very short sleep during ignore window
                    continue

                # Check if enough time has passed since the last processing
                time_since_process = current_time - last_processed_time
                if time_since_process < ClipboardConfig.MIN_PROCESS_INTERVAL:
                    # Dynamic sleep based on remaining time
                    remaining_time = ClipboardConfig.MIN_PROCESS_INTERVAL - time_since_process
                    await asyncio.sleep(min(0.05, remaining_time))
                    continue

                # Check for actual clipboard change count
                new_change_count = self.pasteboard.changeCount()
                if new_change_count != self.last_change_count:
                    print(f"📋 剪贴板变化 detected (Count: {self.last_change_count} -> {new_change_count})")
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

        # Log connection statistics
        self._log_connection_statistics()
        
        print("👋 感谢使用 UniPaste 服务器!")
    
    def _log_connection_statistics(self):
        """记录连接统计信息"""
        if not self.client_connection_managers:
            return
        
        print("\n📊 连接统计:")
        total_attempts = 0
        devices_with_retries = 0
        
        for device_id, mgr in self.client_connection_managers.items():
            total_attempts += mgr.connection_attempts
            if mgr.connection_attempts > 1:
                devices_with_retries += 1
                print(f"  📱 {device_id}: {mgr.connection_attempts} 次连接尝试")
        
        if devices_with_retries > 0:
            print(f"📈 总计: {len(self.client_connection_managers)} 台设备, {devices_with_retries} 台有重连, 总尝试 {total_attempts} 次")

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
