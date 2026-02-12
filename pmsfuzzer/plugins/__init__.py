# plugins/__init__.py
"""
plugins/__init__.py

Minimal package initializer.
Exposes the plugin loader for easy import elsewhere.
"""

from .loader import get_plugin_loader, PluginLoader  # re-export for convenience

__all__ = [
    "get_plugin_loader",
    "PluginLoader",
]