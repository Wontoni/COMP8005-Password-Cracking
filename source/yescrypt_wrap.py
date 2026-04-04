import ctypes
from pathlib import Path

_lib = ctypes.CDLL(str(Path(__file__).with_name("libyescrypt_wrap.so")))

_lib.verify_yescrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.verify_yescrypt.restype = ctypes.c_int


def verify_yescrypt(password: str, full_hash: str) -> bool:
    rc = _lib.verify_yescrypt(
        password.encode("utf-8"),
        full_hash.encode("utf-8"),
    )
    if rc == -1:
        raise RuntimeError("verify_yescrypt() failed")
    return rc == 1