# plugins/invariants/base.py
"""
plugins/invariants/base.py

Abstract base class and registry for invariant plugins.
All invariant plugins must inherit from InvariantPlugin.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List

class InvariantPlugin(ABC):
    """
    Base class for all invariant check plugins.
    Subclasses are automatically registered via __init_subclass__.
    """

    # Class-level registry
    registry: List["InvariantPlugin"] = []

    # Required attributes – subclasses should override
    name: str = "unnamed_invariant"
    description: str = "No description provided"

    @classmethod
    def register(cls):
        """Register the plugin class if not already present."""
        if cls not in cls.registry and cls is not InvariantPlugin:
            cls.registry.append(cls)
            # Note: we register the class, not instance – instantiation happens in loader

    def __init_subclass__(cls, **kwargs):
        """Automatically register subclasses."""
        super().__init_subclass__(**kwargs)
        cls.register()

    @abstractmethod
    def check(
        self,
        before_pkg: Dict[str, Any],
        after_pkg: Dict[str, Any],
        before_global: Dict[str, Any],
        after_global: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Perform invariant checks.

        :return: List of issue dictionaries (each must have at least 'type').
        """
        return []

    def priority(self) -> int:
        """
        Execution priority – higher values run earlier.
        Default: 50.
        """
        return 50