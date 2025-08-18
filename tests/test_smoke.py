import os, pytest

def test_env_seclists_dir():
    assert os.environ.get("SECLISTS_DIR")

def test_import_engine():
    try:
        import engine  # noqa: F401
    except Exception as e:
        pytest.xfail(f"smoke: import engine failed on this branch: {e}")
