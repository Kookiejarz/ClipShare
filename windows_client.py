import asyncio
import websockets
import pyperclip
import json
import os
import hmac
import hashlib
import platform
import sys
from pathlib import Path
from utils.security.crypto import SecurityManager
from utils.network.discovery import DeviceDiscovery

class WindowsClipboardClient:
    def __init__(self):
        self.security_mgr = SecurityManager()
        self.discovery = DeviceDiscovery()
        self._init_encryption()
        self.ws_url = None
        self.last_clipboard_content = pyperclip.paste()
        self.is_receiving = False  # Flag to avoid clipboard loops
        self.device_id = self._get_device_id()
        self.device_token = self._load_device_token()
        self.running = True  # 控制运行状态的标志
        
    def _get_device_id(self):
        """获取唯一设备ID"""
        import socket
        # 使用主机名和MAC地址组合作为设备ID
        try:
            hostname = socket.gethostname()
            # 获取第一个网络接口的MAC地址
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 8*6, 8)][::-1])
            return f"{hostname}-{mac}"
        except:
            # 如果获取失败，生成一个随机ID
            import random
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
            with open(token_path, "r") as f:
                return f.read().strip()
        return None
    
    def _save_device_token(self, token):
        """保存设备令牌"""
        token_path = self._get_token_path()
        with open(token_path, "w") as f:
            f.write(token)
        print(f"💾 设备令牌已保存到 {token_path}")
    
    def _generate_signature(self):
        """生成签名"""
        if not self.device_token:
            return ""
        
        return hmac.new(
            self.device_token.encode(), 
            self.device_id.encode(), 
            hashlib.sha256
        ).hexdigest()

    def _init_encryption(self):
        try:
            self.security_mgr.generate_key_pair()
            print("✅ 加密系统初始化成功")
        except Exception as e:
            print(f"❌ 加密系统初始化失败: {e}")
            
    def stop(self):
        """停止客户端运行"""
        print("\n⏹️ 正在停止客户端...")
        self.running = False
        # 关闭发现服务
        if hasattr(self, 'discovery'):
            self.discovery.close()
        print("👋 感谢使用 ClipShare!")

    def on_service_found(self, ws_url):
        print(f"发现剪贴板服务: {ws_url}")
        self.ws_url = ws_url
        
    async def sync_clipboard(self):
        print("🔍 搜索剪贴板服务...")
        self.discovery.start_discovery(self.on_service_found)
        
        while not self.ws_url and self.running:
            await asyncio.sleep(1)
            
        if not self.running:
            return
            
        print(f"🔌 连接到服务器: {self.ws_url}")
        
        try:
            # 指定二进制子协议
            async with websockets.connect(
                self.ws_url,
                subprotocols=["binary"]
            ) as websocket:
                # 发送身份验证信息
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
                
                # 等待身份验证响应
                try:
                    auth_response = await websocket.recv()
                    if isinstance(auth_response, bytes):
                        auth_response = auth_response.decode('utf-8')
                    
                    response_data = json.loads(auth_response)
                    status = response_data.get('status')
                    
                    if status == 'authorized':
                        print(f"✅ 身份验证成功! 服务器: {response_data.get('server_id', '未知')}")
                    elif status == 'first_authorized':
                        token = response_data.get('token')
                        if token:
                            self._save_device_token(token)
                            self.device_token = token
                            print(f"🆕 设备已授权并获取令牌")
                        else:
                            print(f"❌ 服务器未提供令牌")
                            return
                    else:
                        print(f"❌ 身份验证失败: {response_data.get('reason', '未知原因')}")
                        return
                except Exception as e:
                    print(f"❌ 身份验证过程出错: {e}")
                    return
                
                # 执行密钥交换
                if not await self.perform_key_exchange(websocket):
                    print("❌ 密钥交换失败，断开连接")
                    return
                
                # 创建可取消的任务
                send_task = asyncio.create_task(self.send_clipboard_changes(websocket))
                receive_task = asyncio.create_task(self.receive_clipboard_changes(websocket))
                
                # 等待任务完成或者程序关闭
                try:
                    while self.running:
                        # 使用短超时来定期检查running标志
                        await asyncio.sleep(0.5)
                        if not send_task.done() and not receive_task.done():
                            continue
                        break
                    
                    # 取消任务
                    if not send_task.done():
                        send_task.cancel()
                    if not receive_task.done():
                        receive_task.cancel()
                        
                    # 等待取消完成
                    await asyncio.gather(send_task, receive_task, return_exceptions=True)
                
                except asyncio.CancelledError:
                    print("🛑 任务已取消")
                    # 取消子任务
                    if not send_task.done():
                        send_task.cancel()
                    if not receive_task.done():
                        receive_task.cancel()
                    raise
                    
        except websockets.exceptions.ConnectionClosed:
            print("📴 与服务器的连接已关闭")
        except Exception as e:
            if self.running:  # 只有在正常运行时才显示错误和重试
                print(f"❌ 连接错误: {e}")
                await asyncio.sleep(3)  # 等待一段时间后重试
                # 重新尝试连接
                if self.running:
                    await self.sync_clipboard()
    
    async def send_clipboard_changes(self, websocket):
        """Monitor and send clipboard changes to Mac"""
        while self.running:
            try:
                current_content = pyperclip.paste()
                if current_content != self.last_clipboard_content and not self.is_receiving:
                    # 显示发送的内容（限制字符数）
                    max_display_len = 100
                    display_content = current_content if len(current_content) <= max_display_len else current_content[:max_display_len] + "..."
                    print(f"📤 发送内容: \"{display_content}\"")
                    
                    # Encrypt and send content
                    encrypted_data = self.security_mgr.encrypt_message(current_content.encode('utf-8'))
                    await websocket.send(encrypted_data)
                    self.last_clipboard_content = current_content
                await asyncio.sleep(0.3)
            except asyncio.CancelledError:
                # 正常取消，不打印错误
                break
            except Exception as e:
                if self.running:  # 只在正常运行时打印错误
                    print(f"❌ 发送错误: {e}")
                await asyncio.sleep(1)  # Wait before retrying
    
    async def receive_clipboard_changes(self, websocket):
        """Receive clipboard changes from Mac"""
        while self.running:
            try:
                # 接收数据 - 可能是二进制或文本
                received_data = await websocket.recv()
                self.is_receiving = True
                
                # 确保数据是二进制格式
                if isinstance(received_data, str):
                    # 如果是JSON字符串，可能需要解析
                    if received_data.startswith('{'):
                        try:
                            data_obj = json.loads(received_data)
                            if 'encrypted_data' in data_obj:
                                # 从JSON提取并转换为bytes
                                import base64
                                encrypted_data = base64.b64decode(data_obj['encrypted_data'])
                            else:
                                print("❌ 收到无效的JSON数据")
                                continue
                        except json.JSONDecodeError:
                            print("❌ 无效的JSON格式")
                            continue
                    else:
                        # 普通字符串，直接使用UTF-8编码转为bytes
                        encrypted_data = received_data.encode('utf-8')
                else:
                    # 已经是bytes类型
                    encrypted_data = received_data
                
                # 解密数据
                decrypted_data = self.security_mgr.decrypt_message(encrypted_data)
                content = decrypted_data.decode('utf-8')
                
                # 显示收到的内容（限制字符数以防内容过长）
                max_display_len = 100
                display_content = content if len(content) <= max_display_len else content[:max_display_len] + "..."
                print(f"📥 收到内容: \"{display_content}\"")
                
                # 更新剪贴板
                pyperclip.copy(content)
                self.last_clipboard_content = content
                print("📋 已更新剪贴板")
                
                # 延迟后重置标志
                await asyncio.sleep(0.5)
                self.is_receiving = False
            except asyncio.CancelledError:
                # 正常取消，不打印错误
                break
            except Exception as e:
                if self.running:  # 只在正常运行时打印错误
                    print(f"❌ 接收错误: {e}")
                await asyncio.sleep(1)  # 出错后等待一段时间再继续

    async def perform_key_exchange(self, websocket):
        """Execute key exchange with server"""
        try:
            # Generate key pair if needed
            if not self.security_mgr.public_key:
                self.security_mgr.generate_key_pair()
            
            # Wait for server's public key
            server_key_message = await websocket.recv()
            server_data = json.loads(server_key_message)
            
            if server_data.get("type") != "key_exchange":
                print("❌ 服务器未发送公钥")
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
            
            # Wait for confirmation
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

def main():
    client = WindowsClipboardClient()
    
    try:
        print("🚀 ClipShare Windows 客户端已启动")
        print("📋 按 Ctrl+C 退出程序")
        
        # 简单使用asyncio.run，依赖KeyboardInterrupt异常处理
        asyncio.run(client.sync_clipboard())
        
    except KeyboardInterrupt:
        print("\n👋 正在关闭 ClipShare...")
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
    finally:
        # 确保资源被清理
        client.stop()

if __name__ == "__main__":
    main()