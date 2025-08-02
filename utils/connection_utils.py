"""连接和通信相关工具"""
import asyncio
import json
import time
import traceback

from utils.constants import ConnectionStatus

class ConnectionManager:
    """连接管理器"""
    
    def __init__(self):
        self.status = ConnectionStatus.DISCONNECTED
        self.retry_delays = [15, 30, 60, 180, 300]  # 15s, 30s, 1m, 3m, 5m
        self.current_retry_index = 0
        self.max_retry_delay = 300  # 5 minutes max (will repeat this infinitely)
        self.last_discovery_time = 0
        self.connection_attempts = 0
        self.last_successful_connection = 0
        self.infinite_retry = True  # Always retry without timeout
    
    def reset_reconnect_delay(self):
        """重置重连延迟"""
        self.current_retry_index = 0
        self.connection_attempts = 0
        self.last_successful_connection = time.time()
        print("🔄 连接成功，重置重试延迟")
    
    def calculate_reconnect_delay(self) -> int:
        """计算重连延迟时间 - 使用预定义的退避序列"""
        self.connection_attempts += 1
        
        # Use predefined delay sequence
        if self.current_retry_index < len(self.retry_delays):
            delay = self.retry_delays[self.current_retry_index]
            self.current_retry_index += 1
        else:
            # Stay at maximum delay after sequence is exhausted
            delay = self.max_retry_delay
        
        return delay
    
    def get_retry_status(self) -> str:
        """获取重试状态信息"""
        if self.current_retry_index < len(self.retry_delays):
            remaining = len(self.retry_delays) - self.current_retry_index
            return f"尝试 {self.connection_attempts}, 剩余 {remaining} 个预设延迟"
        else:
            return f"尝试 {self.connection_attempts}, 无限重试模式"
    
    async def wait_for_reconnect(self, running_flag):
        """等待重连"""
        delay = self.calculate_reconnect_delay()
        status = self.get_retry_status()
        
        # Format delay display
        if delay >= 60:
            delay_str = f"{delay//60}分{delay%60}秒" if delay % 60 else f"{delay//60}分钟"
        else:
            delay_str = f"{delay}秒"
        
        print(f"⏱️ {delay_str}后重新尝试连接... ({status}) [无限重试模式]")
        
        # More efficient waiting with longer sleep intervals for longer delays
        sleep_interval = min(1.0, delay / 10)  # Adaptive sleep interval
        wait_start = time.time()
        while running_flag() and time.time() - wait_start < delay:
            await asyncio.sleep(sleep_interval)

class AuthenticationHandler:
    """身份验证处理器"""
    
    @staticmethod
    async def authenticate_device(websocket, device_id: str, device_token: str, 
                                 device_name: str = None, platform: str = None):
        """设备身份验证"""
        try:
            is_first_time = device_token is None
            
            auth_info = {
                'identity': device_id,
                'signature': AuthenticationHandler._generate_signature(device_token, device_id),
                'first_time': is_first_time,
                'device_name': device_name or 'Unknown Device',
                'platform': platform or 'unknown'
            }
            
            print(f"🔑 {'首次连接' if is_first_time else '已注册设备'} ID: {device_id}")
            await websocket.send(json.dumps(auth_info))
            
            auth_response_raw = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            
            if isinstance(auth_response_raw, bytes):
                auth_response = auth_response_raw.decode('utf-8')
            else:
                auth_response = auth_response_raw
                
            response_data = json.loads(auth_response)
            status = response_data.get('status')
            
            if status == 'authorized':
                print(f"✅ 身份验证成功! 服务器: {response_data.get('server_id', '未知')}")
                return True, device_token
            elif status == 'first_authorized':
                token = response_data.get('token')
                if token:
                    print(f"🆕 设备已授权并获取令牌")
                    return True, token
                else:
                    print(f"❌ 服务器在首次授权时未提供令牌")
                    return False, None
            else:
                reason = response_data.get('reason', '未知原因')
                print(f"❌ 身份验证失败: {reason}")
                return False, None
                
        except asyncio.TimeoutError:
            print("❌ 等待身份验证响应超时")
            return False, None
        except json.JSONDecodeError:
            print("❌ 无效的身份验证响应格式")
            return False, None
        except Exception as e:
            print(f"❌ 身份验证过程中出错: {e}")
            traceback.print_exc()
            return False, None
    
    @staticmethod
    def _generate_signature(device_token: str, device_id: str) -> str:
        """生成签名"""
        if not device_token:
            return ""
        try:
            import hmac
            import hashlib
            return hmac.new(
                device_token.encode(),
                device_id.encode(),
                hashlib.sha256
            ).hexdigest()
        except Exception as e:
            print(f"❌ 生成签名失败: {e}")
            return ""