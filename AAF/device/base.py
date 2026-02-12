# device/base.py
"""
device/base.py

Abstract base interface and a basic concrete implementation for physical devices.
The BasicPhysicalDevice is fully functional for unrooted physical devices/emulators
that are already connected via ADB.
Sub-modules (physical/rooted, emulator/unrooted, etc.) will inherit and extend this.
"""

from abc import ABC, abstractmethod
from typing import Optional

from config import ConfigManager
from .utils import wait_for_device, wait_for_boot_complete, run_adb
import logging

logger = logging.getLogger(__name__)

class DeviceInterface(ABC):
    """
    Abstract base class for all device handlers.
    """

    def __init__(self, config: ConfigManager, serial: Optional[str] = None):
        self.config = config
        self.serial = serial

    @abstractmethod
    def setup(self) -> None:
        """Prepare the device (e.g., start emulator, connect, etc.)"""
        pass

    @abstractmethod
    def wait_for_ready(self) -> bool:
        """Wait until device is fully booted and stable. Return success."""
        pass

    @abstractmethod
    def teardown(self) -> None:
        """Clean up resources (stop emulator, kill processes)"""
        pass

    @abstractmethod
    def get_serial(self) -> str:
        """Return the ADB serial string"""
        pass

class BasicPhysicalDevice(DeviceInterface):
    """
    Basic concrete implementation for already-connected physical devices or emulators.
    Handles connection stability and boot completion checks.
    Suitable for unrooted physical devices or as a base for emulator variants.
    """

    def setup(self) -> None:
        logger.info(f"Setting up basic physical device (serial: {self.serial or 'default'})")
        # No additional setup needed for already-connected devices
        pass

    def wait_for_ready(self) -> bool:
        timeout = self.config.get('device.timeout_seconds', 300)
        interval = self.config.get('device.retry_interval_seconds', 10)

        logger.info(f"Waiting for device {self.get_serial()} to connect...")
        if not wait_for_device(self.serial, timeout, interval):
            return False

        logger.info(f"Waiting for boot completion on {self.get_serial()}...")
        if not wait_for_boot_complete(self.serial, timeout, interval):
            return False

        # Additional stability check: simple command
        result = run_adb(self.serial, ["shell", "true"])
        if result and result.returncode == 0:
            logger.info(f"Device {self.get_serial()} is fully ready")
            return True

        logger.error(f"Device {self.get_serial()} failed stability check")
        return False

    def teardown(self) -> None:
        logger.info(f"Tearing down basic physical device (serial: {self.serial or 'default'})")
        # Optional: adb disconnect or emu kill if applicable
        pass

    def get_serial(self) -> str:
        return self.serial or "default"