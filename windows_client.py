import asyncio
import websockets
import json
import os
import time
import sys
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery
from utils.message_format import ClipMessage, MessageType
from handlers.file_handler import FileHandler
from utils.platform_config import verify_platform, IS_WINDOWS
from config import ClipboardConfig
import traceback
from enum import IntEnum

class ConnectionStatus(IntEnum):
    """连接状态枚举"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2

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
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self.ws_url = None
        self.is_receiving = False
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        self.running = True
        self.last_content_hash = None
        self.last_update_time = 0
        self.last_remote_content_hash = None
        self.last_remote_update_time = 0
        self.ignore_clipboard_until = 0
        self._last_processed_content = None

        # 初始化连接状态管理
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.reconnect_delay = 3
        self.max_reconnect_delay = 30
        self.last_discovery_time = 0

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

        # 尝试加载文件缓存
        try:
            if hasattr(self.file_handler, 'load_file_cache'):
                self.file_handler.load_file_cache()
        except Exception as e:
            print(f"⚠️ 加载文件缓存失败: {e}")

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

    def on_service_found(self, url):
        """服务发现回调"""
        if url != self.ws_url:
            print(f"✅ 发现剪贴板服务: {url}")
            self.ws_url = url
            self.last_discovery_time = time.time()

    def stop(self):
        """停止客户端"""
        print("🛑 正在停止客户端...")
        self.running = False
        if hasattr(self.discovery, 'close'):
            self.discovery.close()

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

    def _set_windows_clipboard_file(self, file_path):
        """设置Windows剪贴板文件"""
        try:
            path_str = str(file_path.resolve())
            files = path_str + '\0'
            file_bytes = files.encode('utf-16le') + b'\0\0'

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
                print(f"📎 已将文件添加到剪贴板: {file_path.name}")
                return True
            finally:
                win32clipboard.CloseClipboard()

        except Exception as e:
            print(f"❌ 设置剪贴板文件失败: {e}")
            return False

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
                print(f"✅ 文件接收完成: {completed_path}")
                if self._set_windows_clipboard_file(completed_path):
                    print(f"📎 已将文件添加到剪贴板: {completed_path.name}")
                else:
                    print(f"❌ 未能将文件设置到剪贴板: {completed_path.name}")

        except Exception as e:
            print(f"❌ 处理文件响应时出错: {e}")
            traceback.print_exc()

    # 添加其他缺失的方法...
    async def sync_clipboard(self):
        """主同步循环"""
        print("🔍 搜索剪贴板服务...")
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
                        await self.connect_and_sync()
                        print("ℹ️ 连接已关闭，将尝试重新连接")
                        self.ws_url = None
                        await asyncio.sleep(1)
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
        delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
        self.reconnect_delay = delay
        print(f"⏱️ {int(delay)}秒后重新尝试连接...")
        
        wait_start = time.time()
        while self.running and time.time() - wait_start < delay:
            await asyncio.sleep(0.5)

        if self.running:
            self.ws_url = None
            print("🔄 重新搜索剪贴板服务...")
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
                ping_interval=20,
                ping_timeout=20,
                close_timeout=10
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
                self.reconnect_delay = 3  # Reset reconnect delay on successful connection
                
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