from .addons import DefaultAddons
from .async_api import AsyncCamoufox, AsyncNewBrowser, AsyncNewContext
from .proxy import (
    ProxyEndpoint,
    ProxyRotationConfig,
    ProxyRotator,
    ProxySession,
    build_rotator,
    parse_proxy_file,
    parse_proxy_string,
)
from .sync_api import Camoufox, NewBrowser, NewContext
from .utils import launch_options

__all__ = [
    "Camoufox",
    "NewBrowser",
    "NewContext",
    "AsyncCamoufox",
    "AsyncNewBrowser",
    "AsyncNewContext",
    "DefaultAddons",
    "launch_options",
    # Proxy rotation
    "ProxyEndpoint",
    "ProxySession",
    "ProxyRotationConfig",
    "ProxyRotator",
    "build_rotator",
    "parse_proxy_file",
    "parse_proxy_string",
]
