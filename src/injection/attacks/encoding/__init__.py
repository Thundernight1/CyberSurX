from .caesar import caesar_encode
from .leetspeak import leetspeak_encode
from .base64_enc import base64_encode
from .a1z26 import a1z26_encode
from .mirror import mirror_encode
from .affine import affine_encode
from .vaporwave import vaporwave_encode
from .ogham import ogham_encode
from .zalgo import zalgo_encode
from .ascii_smuggling import ascii_smuggle

ENCODING_METHODS = {
    "base64": base64_encode,
    "caesar": caesar_encode,
    "leetspeak": leetspeak_encode,
    "a1z26": a1z26_encode,
    "mirror": mirror_encode,
    "affine": affine_encode,
    "vaporwave": vaporwave_encode,
    "ogham": ogham_encode,
    "zalgo": zalgo_encode,
    "ascii_smuggling": ascii_smuggle,
}

__all__ = ["ENCODING_METHODS"]