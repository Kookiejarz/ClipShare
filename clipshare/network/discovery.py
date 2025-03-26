import socket
import json
from zeroconf import ServiceBrowser, Zeroconf, ServiceInfo, ServiceListener
import netifaces
import asyncio
from concurrent.futures import ThreadPoolExecutor

class ClipboardServiceListener(ServiceListener):
    def __init__(self, callback):
        self.callback = callback
        
    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if info:
            address = str(info.parsed_addresses()[0])
            port = info.port
            self.callback(f"ws://{address}:{port}")
            
    # Required methods for ServiceListener
    def remove_service(self, zeroconf, type_, name):
        pass

    def update_service(self, zeroconf, type_, name):
        pass

class DeviceDiscovery:
    def __init__(self, service_name="_clipshare._tcp.local."):
        self.zeroconf = Zeroconf()
        self.service_name = service_name
        self.discovered_devices = {}
        self._executor = ThreadPoolExecutor(max_workers=1)

    async def start_advertising(self, port):
        """Advertise this device on the network."""
        ip_addr = self._get_local_ip()
        info = ServiceInfo(
            self.service_name,
            f"Device_{socket.gethostname()}.{self.service_name}",
            addresses=[socket.inet_aton(ip_addr)],
            port=port,
            properties={},
        )
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self.zeroconf.register_service, info)
        print("✅ 服务注册成功")

    def _get_local_ip(self):
        """Get the local IP address."""
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if addr['addr'] != '127.0.0.1':
                        return addr['addr']
        return '127.0.0.1'

    def close(self):
        """Clean up resources."""
        self.zeroconf.close()
        self._executor.shutdown()
