"""
checker.py — Password validator compiled to .pyc for the rev-dotnetobf challenge.

This module will be compiled with py_compile and the resulting .pyc
distributed as the reversing target. Players must decompile it (e.g. with
uncompyle6, decompyle3, or pycdc) and analyse the obfuscated constant.

The password is embedded as an integer list that is converted back to bytes
and compared with the input. The variable names are intentionally cryptic.

Password: DOTNET_OBF_KEY (14 characters)
"""

import sys as _s

# Obfuscated key: each element is (ord(c) ^ 0x13) XOR 0x13 = ord(c)
# The XOR here is a decoy; real value is just the ASCII codes.
# Stored as a tuple of ints to make naive string search ineffective.
__0 = (
    0x44 ^ 0x00, 0x4F ^ 0x00, 0x54 ^ 0x00, 0x4E ^ 0x00,
    0x45 ^ 0x00, 0x54 ^ 0x00, 0x5F ^ 0x00, 0x4F ^ 0x00,
    0x42 ^ 0x00, 0x46 ^ 0x00, 0x5F ^ 0x00, 0x4B ^ 0x00,
    0x45 ^ 0x00, 0x59 ^ 0x00,
)

# Second layer: each value is __0[i] XOR __1[i] where __1 = [0]*14
__1 = bytes(__0)


def __2(__3):
    """Validate the input string against the embedded key."""
    if len(__3) != 14:
        return False
    __4 = __3.encode() if isinstance(__3, str) else __3
    return __4 == __1


def __main():
    if len(_s.argv) > 1 and __2(_s.argv[1]):
        print("CORRECT")
    else:
        print("WRONG")


if __name__ == "__main__":
    __main()
