# Compatibility shim package for legacy imports using a capitalized module name.
# This makes `import Discovery` work by re-exporting symbols from `discovery`.
from discovery import *  # noqa: F401,F403
from discovery import HostDiscoverer  # explicit re-export

__all__ = ['HostDiscoverer']

