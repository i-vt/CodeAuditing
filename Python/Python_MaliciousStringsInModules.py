import os
import ast
import re
import importlib
import pkgutil
import base64
import binascii
import inspect

# define regular expressions to match common obfuscation techniques
BASE64_REGEX = re.compile(r"^[a-zA-Z0-9+/=]+\s*$")
ROT13_REGEX = re.compile(r"^[a-zA-Z]+:\/\/[a-zA-Z0-9]+\s*$")
AES_REGEX = re.compile(r"^(?:0x[0-9a-fA-F]{2})+\s*$")

# define regular expressions to match common malicious code patterns
MALICIOUS_REGEX = re.compile(r"(?:exec|eval|subprocess|shell|os\.|input|__import__)", re.IGNORECASE)

# define a set of keywords that should not be used in string literals
BAD_KEYWORDS = set(["import", "from", "exec", "eval", "print", "assert", "exit", "quit"])

# define a set of built-in functions that should not be used in string literals
BAD_BUILTINS = set(["eval", "exec", "open", "input", "print", "exit", "quit", "compile"])

# define a function to check for obfuscated strings
def audit_obfuscated_strings(node):
    # check for string literals
    if isinstance(node, ast.Str):
        # check for base64-encoded strings
        if BASE64_REGEX.match(node.s):
            try:
                decoded = base64.b64decode(node.s).decode("utf-8")
                if "\x00" in decoded:
                    print(f"Warning: possibly obfuscated string found in {node.lineno}:{node.col_offset}")
            except (binascii.Error, UnicodeDecodeError):
                pass
        # check for rot13-encoded strings
        elif ROT13_REGEX.match(node.s):
            decoded = "".join(chr((ord(c) - 97 + 13) % 26 + 97) if c.isalpha() else c for c in node.s)
            if "\x00" in decoded:
                print(f"Warning: possibly obfuscated string found in {node.lineno}:{node.col_offset}")
        # check for AES-encoded strings
        elif AES_REGEX.match(node.s):
            try:
                hex_string = node.s.replace("0x", "").replace("\\x", "")
                decoded = bytes.fromhex(hex_string).decode("utf-8")
                if "\x00" in decoded:
                    print(f"Warning: possibly obfuscated string found in {node.lineno}:{node.col_offset}")
            except ValueError:
                pass

# define a function to check for malicious code
def audit_malicious_code(node):
    # check for import statements
    if isinstance(node, ast.Import):
        for alias in node.names:
            name = alias.name.split(".")[0]
            if name in BAD_KEYWORDS:
                print(f"Warning: possible malicious keyword in module import found in {node.lineno}:{node.col_offset}")
            elif name in BAD_BUILTINS:
                print(f"Warning: possible malicious built-in function in module import found in {node.lineno}:{node.col_offset}")
            else:
                module = importlib.import_module(alias.name)
                source = inspect.getsource(module)
                if MALICIOUS_REGEX.search(source):
                    print(f"Warning: possible malicious code in module import found in {node.lineno}:{node.col_offset}")

    # check for from ... import statements
    elif isinstance(node, ast.ImportFrom):
        if node.module in BAD_KEYWORDS:
            print(f"Warning: possible malicious keyword in module import found in {node.lineno}:{node.col_offset}")
        elif node.module in BAD_BUILTINS:
            print(f"Warning: possible malicious built-in function in module import found in {node.lineno}:{node.col_offset}")
        else:
            module = importlib.import_module(node.module)
            source = inspect.getsource(module)
            if MALICIOUS_REGEX.search(source):
                print(f"Warning: possible malicious code in module import found in {node.lineno}:{node.col_offset}")

