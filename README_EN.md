# UniPaste: Secure Cross-Platform Clipboard Sync Tool

![UniPaste](https://img.shields.io/badge/UniPaste-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.9+-green)
![License](https://img.shields.io/badge/License-GNU%20GPL-blue) 
![Platform](https://img.shields.io/badge/Platform-Mac%20%7C%20Windows-lightgrey)

UniPaste is an end-to-end encrypted cross-platform clipboard synchronization tool that enables secure sharing of clipboard content between Mac and Windows devices. No cloud services required, protecting your data privacy.

## ✨ Features

- **Real-time Sync**: Instantly synchronize clipboard content between devices
- **End-to-End Encryption**: All transmitted data is protected with AES-256-GCM encryption
- **Zero-Config Networking**: Automatically discover devices on your local network without manual IP configuration
- **Clipboard Loop Prevention**: Smart detection prevents infinite clipboard content loops between devices
- **Multiple Content Types**: Support for text and file path transfers

## 📥 Installation

### Direct Installation
Download the latest package from the [Releases](https://github.com/Kookiejarz/UniPaste/releases) page.

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Install from Source

```sh
# Clone repository
git clone https://github.com/Kookiejarz/UniPaste.git
cd UniPaste

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Usage

### Start Server on Mac
```sh
python mac_clip_check.py 
```

### Start Client on Windows
```sh
python windows_client.py
```

## 📋 Practical Usage Flow

1. Start the server on your Mac device
2. Start the client on your Windows device
3. The Windows client will automatically discover and connect to the Mac server
4. Once connected, clipboard content will stay synchronized between both devices
5. After copying new content on either device, the clipboard on the other device will automatically update

## 🔒 Encryption Technology Details

UniPaste uses multi-layered encryption technology to ensure data security:

- **Elliptic Curve Diffie-Hellman (ECDHE)**: Securely negotiate shared keys without pre-shared secrets
- **HKDF Key Derivation**: Securely derive encryption keys from shared secrets, increasing key entropy
- **AES-256-GCM**: Advanced Encryption Standard with Galois/Counter Mode for data confidentiality and integrity

## 🛠 Local Development Environment

```sh
git clone https://github.com/Kookiejarz/UniPaste.git
cd UniPaste
pip install -r requirements.txt
python -m pytest tests/  # Run tests
```

## ⚠️ Security Considerations

- This tool is designed for use on secure local networks only
- Not recommended for use on public or untrusted networks, which may lead to data leakage
- Check GitHub page regularly for security updates
- Only use between trusted devices

## 🔍 Troubleshooting

### Cannot Discover Devices
- Ensure both devices are on the same local network
- Check firewall settings, make sure **mDNS (UDP 5353)** and **WebSocket (TCP 8765)** ports are open
- Network might be blocking mDNS traffic, try using a wired connection or manually specifying IP addresses

### Decryption Errors
- Ensure both ends are using the same encryption protocol version
- Check if key hashes shown in run logs match
- Restart applications on both ends to resynchronize key states

### Clipboard Not Updating
- Some applications may lock the clipboard, try closing these applications
- Windows permission issues may prevent clipboard writing, try running with **administrator privileges**
- Check application logs for more detailed error information


## Acknowledgements

- **[Zeroconf](https://github.com/jstasiak/python-zeroconf)** for network service discovery
- **[websockets](https://github.com/aaugustin/websockets)** for WebSocket implementation
- **[cryptography](https://github.com/pyca/cryptography)** for cryptography tools
- **[pyperclip](https://github.com/asweigart/pyperclip)** for clipboard operations

## 📄 License

This project is licensed under the GNU-GPL License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Pull requests and issues are welcome! For major changes, please open an issue first to discuss what you would like to change.
