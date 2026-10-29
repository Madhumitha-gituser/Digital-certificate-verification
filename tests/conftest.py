# conftest.py — pytest configuration
# This file is automatically loaded by pytest.
# It ensures the project root is on sys.path for all tests.

import sys
from pathlib import Path

# Add the project root to Python's module search path
sys.path.insert(0, str(Path(__file__).parent))

