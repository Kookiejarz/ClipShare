"""
Shared constants for UniPaste
Centralizes common values used across the application
"""

from enum import IntEnum


class ConnectionStatus(IntEnum):
    """Connection status enumeration"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2


class Platform(IntEnum):
    """Platform enumeration"""
    WINDOWS = 1
    MACOS = 2
    LINUX = 3


# Common error messages
ERROR_MESSAGES = {
    'auth_failed': '❌ 身份验证失败',
    'key_exchange_failed': '❌ 密钥交换失败',
    'connection_failed': '❌ 连接失败',
    'decryption_failed': '❌ 消息解密失败',
    'invalid_message': '⚠️ 收到无效消息格式',
    'unknown_message_type': '⚠️ 未知消息类型',
}

# Success messages
SUCCESS_MESSAGES = {
    'connected': '✅ 连接建立成功',
    'auth_success': '✅ 身份验证成功',
    'key_exchange_success': '🔑 密钥交换成功',
    'file_transfer_complete': '✅ 文件传输完成',
    'broadcast_success': '✅ 成功广播消息',
}

# Status indicators
STATUS_INDICATORS = {
    ConnectionStatus.DISCONNECTED: "🔴 已断开连接",
    ConnectionStatus.CONNECTING: "🟡 正在连接",
    ConnectionStatus.CONNECTED: "🟢 已连接",
}