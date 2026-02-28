"""
Root conftest.py — ensures both proxy.* and mcp_server.* are importable
from any test file, regardless of working directory.
"""
import sys
import os

# Add the arkheia-mcp root to sys.path so `import proxy.*` and
# `import mcp_server.*` resolve correctly when running pytest from
# any directory.
_root = os.path.dirname(os.path.abspath(__file__))
if _root not in sys.path:
    sys.path.insert(0, _root)
