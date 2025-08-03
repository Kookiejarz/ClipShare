"""
Common message handling utilities for UniPaste
Provides shared functionality for processing different message types
"""

import json
import time
from typing import Callable, Optional

from utils.message_format import MessageType


class MessageHandler:
    """
    Handles common message processing logic
    """
    
    @staticmethod
    async def process_encrypted_message(
        encrypted_data, 
        security_mgr, 
        handlers: dict,
        sender_websocket=None
    ):
        """
        Process encrypted message and route to appropriate handler
        
        Args:
            encrypted_data: Raw encrypted data from websocket
            security_mgr: SecurityManager instance for decryption
            handlers: Dict mapping message types to handler functions
            sender_websocket: WebSocket connection that sent the message
        """
        try:
            # Decrypt the message
            decrypted_data = security_mgr.decrypt_message(encrypted_data)
            message_json = decrypted_data.decode('utf-8')
            message = json.loads(message_json)
            
            if not message or "type" not in message:
                print("⚠️ 收到的消息格式无效或无法解析")
                return False
            
            msg_type = message["type"]
            
            # Route to appropriate handler
            if msg_type in handlers:
                handler = handlers[msg_type]
                if sender_websocket:
                    await handler(message, sender_websocket)
                else:
                    await handler(message)
                return True
            else:
                print(f"⚠️ 未知消息类型: {msg_type}")
                return False
                
        except json.JSONDecodeError:
            print("❌ 收到的消息不是有效的JSON")
            return False
        except UnicodeDecodeError:
            print("❌ 无法将收到的消息解码为UTF-8")
            return False
        except Exception as e:
            print(f"❌ 处理接收数据时出错: {e}")
            return False
    
    @staticmethod
    def create_message(msg_type: str, **kwargs) -> dict:
        """Create a standardized message"""
        message = {
            'type': msg_type,
            'timestamp': kwargs.pop('timestamp', None) or time.time()
        }
        message.update(kwargs)
        return message
    
    @staticmethod
    async def send_encrypted_message(
        websocket, 
        security_mgr, 
        message: dict
    ):
        """Send an encrypted message"""
        try:
            message_json = json.dumps(message)
            encrypted_data = security_mgr.encrypt_message(message_json.encode('utf-8'))
            await websocket.send(encrypted_data)
            return True
        except Exception as e:
            print(f"❌ 发送加密消息失败: {e}")
            return False