# device/__init__.py
"""
device/__init__.py

Factory for device managers.
Returns either a single-device handler or MultiDeviceManager based on config.
Currently defaults to BasicPhysicalDevice for single-device mode (unrooted physical).
When physical/emulator sub-modules are implemented, update imports accordingly.
"""

from typing import Union
from config import ConfigManager
from .base import BasicPhysicalDevice, DeviceInterface
from .manager import MultiDeviceManager

def get_device_manager(config: ConfigManager) -> Union[DeviceInterface, MultiDeviceManager]:
    """
    Factory function to get the appropriate device manager.
    - If multi_device.enabled: returns MultiDeviceManager
    - Else: returns a single BasicPhysicalDevice (fallback for physical unrooted)
    """
    if config.get('fuzzer.multi_device.enabled', False):
        return MultiDeviceManager(config)
    
    # Single-device mode – basic physical unrooted fallback
    return BasicPhysicalDevice(config)