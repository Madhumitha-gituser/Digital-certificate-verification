# conftest.py — pytest configuration
import sys
import subprocess
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

@pytest.fixture(autouse=True, scope="session")
def setup_and_teardown_test_samples():
    """
    Ensure sample files exist during the pytest run so all web and crypto tests pass.
    Cleans up all generated files upon test completion so sample_certificates remains clean.
    """
    samples_dir = PROJECT_ROOT / "sample_certificates"
    samples_dir.mkdir(exist_ok=True)

    # Run sample generator for test execution
    gen_script = PROJECT_ROOT / "generate_samples.py"
    if gen_script.exists():
        subprocess.run([sys.executable, str(gen_script)], check=True, cwd=str(PROJECT_ROOT), capture_output=True)

    yield

    # Teardown: Clean up sample files so repository stays clean
    if samples_dir.exists():
        for f in samples_dir.glob("*"):
            if f.is_file():
                try:
                    f.unlink()
                except Exception:
                    pass
