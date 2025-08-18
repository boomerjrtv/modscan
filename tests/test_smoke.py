import os
import engine

def test_env_seclists_dir():
    assert os.environ.get("SECLISTS_DIR")

def test_import_engine():
    assert hasattr(engine, "__file__")
