import atexit
import os
import shutil
import tempfile

_state = tempfile.mkdtemp(prefix="jep-api-test-")
os.environ["JEP_STATE_DIR"] = _state
atexit.register(shutil.rmtree, _state, ignore_errors=True)
