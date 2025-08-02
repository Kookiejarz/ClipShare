# UniPaste: 安全跨平台剪贴板同步工具

[中文](./README.md) | [English](./README_EN.md)

![UniPaste-favicon](https://github.com/Kookiejarz/UniPaste/blob/main/unipaste.png?raw=true)
![UniPaste](https://img.shields.io/badge/UniPaste-1.1.1-blue)
![Python](https://img.shields.io/badge/Python-3.9+-green)
![License](https://img.shields.io/badge/License-GNU%20GPL-blue)
![Platform](https://img.shields.io/badge/Platform-Mac%20%7C%20Windows-lightgrey)

UniPaste是一个端到端加密的跨平台剪贴板同步工具，支持 Mac 和 Windows 设备之间安全地共享剪贴板内容。无需云服务，保护您的数据隐私。

## ✨ 特性

- **实时同步**：在设备间即时同步剪贴板内容
- **端到端加密**：使用 AES-256-GCM 加密保护所有传输数据
- **零配置网络**：自动在本地网络中发现设备，无需手动设置 IP 地址
- **防止剪贴板循环**：智能检测并防止剪贴板内容在设备间无限循环
- **多内容类型**：支持文本、文件路径的传输

## 📥 安装

### 直接安装
从 [Releases](https://github.com/Kookiejarz/UniPaste/releases) 页面下载最新的安装包。

### 前置要求
- Python 3.9 或更高版本
- pip 包管理器

### 从源码安装

```sh
# 克隆仓库
git clone https://github.com/Kookiejarz/UniPaste.git
cd UniPaste

# 安装依赖
pip install -r requirements.txt
```

## 🚀 使用方法

### 在 Mac 上启动服务端
```sh
python mac_clip_check.py 
```

### 在 Windows 上启动客户端
```sh
python windows_client.py
```

## 📋 实际使用流程

1. 在 Mac 设备上启动服务端
2. 在 Windows 设备上启动客户端
3. Windows 客户端会自动发现并连接到 Mac 服务端
4. 连接建立后，两台设备的剪贴板内容会自动保持同步
5. 在任一设备上复制新内容后，另一设备的剪贴板将自动更新

## 🔒 加密技术详解

UniPaste 使用多层加密技术确保数据安全：

- **椭圆曲线密钥交换 (ECDHE)**：安全地协商共享密钥，不需要预共享密钥
- **HKDF 密钥派生**：从共享密钥安全地派生加密密钥
- **AES-256-GCM**：使用高级加密标准和认证加密模式，确保数据机密性和完整性

## 🛠 本地开发环境

```sh
git clone https://github.com/Kookiejarz/UniPaste.git
cd UniPaste
pip install -r requirements.txt
```

## ⚠️ 安全注意事项

- 本工具仅设计用于安全的本地网络环境
- 不建议在公共网络或不受信任的网络上使用，可能导致数据泄露
- 定期检查 GitHub 页面获取安全更新
- 建议仅在信任的设备间使用

## 🔍 故障排除

### 无法发现设备
- 确保两台设备在同一个本地网络中
- 检查防火墙设置，确保 **mDNS (UDP 5353)** 和 **WebSocket (TCP 8765)** 端口开放
- 网络可能阻止了 mDNS 流量，尝试使用有线连接或手动指定 IP 地址

### 解密错误
- 确保两端使用相同的加密协议版本
- 检查运行日志中显示的密钥哈希是否匹配
- 重新启动两端应用程序以重新同步密钥状态

### 剪贴板未更新
- 某些应用程序可能会锁定剪贴板，尝试关闭这些应用
- Windows 权限问题可能阻止写入剪贴板，尝试以 **管理员权限** 运行
- 检查应用程序日志以获取更详细的错误信息


## 致谢

- **[Zeroconf](https://github.com/jstasiak/python-zeroconf)** 提供的网络服务发现
- **[websockets](https://github.com/aaugustin/websockets)** 提供的 WebSocket 实现
- **[cryptography](https://github.com/pyca/cryptography)** 提供的密码学工具
- **[pyperclip](https://github.com/asweigart/pyperclip)** 提供的剪贴板操作

## 📄 许可证

本项目采用 GNU-GPL 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 🤝 贡献

欢迎提交 Pull Request 和 Issue！在开始大型更改前，请先开 Issue 讨论您的想法。
