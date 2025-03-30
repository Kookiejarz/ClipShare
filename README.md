# ClipShare: 安全跨平台剪贴板同步工具

![ClipShare](https://img.shields.io/badge/ClipShare-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.7+-green)
![License](https://img.shields.io/badge/License-MIT-orange)

ClipShare 是一个端到端加密的跨平台剪贴板同步工具，支持 Mac 和 Windows 设备之间安全地共享剪贴板内容。

## 特性
- **实时同步**：在设备间即时同步剪贴板内容
- **端到端加密**：使用高级 AES-256-GCM 加密保护所有传输数据
- **零配置网络**：自动在本地网络中发现设备，无需手动设置 IP 地址
- **防止剪贴板循环**：智能检测并防止剪贴板内容在设备间无限循环
- **支持多种内容**：支持文本、文件路径 (图像支持在开发中)

## 安装

### 前置要求
- Python 3.7 或更高版本
- pip 包管理器

### 安装依赖
```sh
pip install -r requirements.txt
```

## 使用方法

### 在 Mac 上启动服务端
```sh
python server.py
```

### 在 Windows 上启动客户端
```sh
python windows_client.py
```

## 实际使用
1. 在 Mac 设备上启动服务端。
2. 在 Windows 设备上启动客户端。
3. Windows 客户端会自动发现并连接到 Mac 服务端。
4. 连接建立后，两台设备的剪贴板内容会自动保持同步。

## 加密技术
ClipShare 使用多层加密技术确保数据安全：
- **椭圆曲线密钥交换 (ECDHE)**：安全地协商共享密钥
- **HKDF 密钥派生**：从共享密钥安全地派生加密密钥
- **AES-256-GCM**：高级加密标准和认证加密模式
- **临时测试密钥**：当前版本使用临时预共享密钥用于测试

## 项目结构
```
ClipShare/
├── server.py        # 服务器端程序 (Mac)
├── windows_client.py # 客户端程序 (Windows)
├── requirements.txt # 依赖列表
├── README.md        # 说明文档
└── utils/           # 工具模块
```

## 开发指南

### 添加新功能
- **支持更多平台**：为 Linux 或移动平台添加支持
- **图像共享**：添加对图像剪贴板内容的支持
- **更好的授权机制**：添加设备认证和记住授权设备功能

### 本地开发环境
```sh
git clone https://github.com/your-repo/ClipShare.git
cd ClipShare
pip install -r requirements.txt
```

## 安全注意事项
- 本工具仅设计用于安全的本地网络环境。
- 在公共网络上使用可能导致数据泄露。
- 当前版本使用简化的密钥管理，适合测试但不适合生产环境。
- 建议仅在信任的设备间使用。

## 故障排除

### 无法发现设备
- 确保两台设备在同一个本地网络中。
- 检查防火墙设置，确保 **mDNS (UDP 5353)** 和 **WebSocket (TCP 8765)** 端口开放。
- 网络可能阻止了 mDNS 流量，尝试使用有线连接。

### 解密错误
- 确保两端使用相同的共享密钥。
- 检查运行日志中显示的密钥哈希是否匹配。
- 重新启动两端应用程序同步密钥状态。

### 剪贴板未更新
- 某些应用程序可能会锁定剪贴板，尝试关闭这些应用。
- Windows 权限问题可能阻止写入剪贴板，尝试以 **管理员权限** 运行。

## 许可证
MIT © 2025 ClipShare Developers

## 致谢
- **Zeroconf** 提供的网络服务发现
- **websockets** 提供的 WebSocket 实现
- **cryptography** 提供的密码学工具
- **pyperclip** 提供的剪贴板操作

> ⚠️ **注意**：此项目为原型演示，不建议用于安全敏感的应用场景。在生产环境使用前，应加强身份验证和密钥管理功能。

