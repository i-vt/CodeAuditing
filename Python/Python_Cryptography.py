import ast
import re

INSECURE_HASH_FUNC_PATTERN = re.compile(r"(^|\W)hashlib\.(md5|sha1)\W")
INSECURE_MAC_FUNC_PATTERN = re.compile(r"(^|\W)(hmac\.new|hashlib\.pbkdf2_hmac)\W")
INSECURE_RANDOM_FUNC_PATTERN = re.compile(r"(^|\W)random\.\w+\W")

CRYPTO_KEY_SIZES = {
    "RSA": 2048,
    "DSA": 2048,
    "ECDSA": 256,
    "Ed25519": 256,
    "AES": 256,
    "ChaCha20": 256,
}

CRYPTO_REQUIRED_OPS = {
    "RSA": {"encrypt", "decrypt", "sign", "verify"},
    "DSA": {"sign", "verify"},
    "ECDSA": {"sign", "verify"},
    "Ed25519": {"sign", "verify"},
    "AES": {"encrypt", "decrypt"},
    "ChaCha20": {"encrypt", "decrypt"},
}

def check_for_insecure_usage(node, func_name):
    """Check and print warnings for insecure cryptography usage."""
    if INSECURE_HASH_FUNC_PATTERN.search(func_name):
        print(f"Warning: {node.name} uses an insecure hash function")
    elif INSECURE_MAC_FUNC_PATTERN.search(func_name):
        print(f"Warning: {node.name} uses an insecure MAC function")
    elif INSECURE_RANDOM_FUNC_PATTERN.search(func_name):
        print(f"Warning: {node.name} uses an insecure random number generator")

def audit_cryptography(node):
    if isinstance(node, ast.FunctionDef):
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func_name = (
                    call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                )
                check_for_insecure_usage(node, func_name)

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                if targets:
                    check_key_sizes_and_operations(stmt, node)

def check_key_sizes_and_operations(stmt, node):
    if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name):
        crypto_name = stmt.value.func.id
        if crypto_name in CRYPTO_KEY_SIZES or crypto_name in CRYPTO_REQUIRED_OPS:
            check_key_size(crypto_name, stmt, node)
            check_required_operations(crypto_name, stmt, node)

def check_key_size(crypto_name, stmt, node):
    if crypto_name in CRYPTO_KEY_SIZES:
        size = next(
            (kw.value.n for kw in stmt.value.keywords if kw.arg == "bits"), 
            CRYPTO_KEY_SIZES[crypto_name]
        )
        if size < CRYPTO_KEY_SIZES[crypto_name]:
            print(f"Warning: {node.name} uses a weak key size for {crypto_name}")

def check_required_operations(crypto_name, stmt, node):
    if crypto_name in CRYPTO_REQUIRED_OPS:
        ops = {arg.s for arg in stmt.value.args} | {kw.arg for kw in stmt.value.keywords}
        if not CRYPTO_REQUIRED_OPS[crypto_name].issubset(ops):
            missing_ops = CRYPTO_REQUIRED_OPS[crypto_name] - ops
            print(f"Warning: {node.name} is missing operations for {crypto_name}: {', '.join(missing_ops)}")

def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
    for node in ast.walk(tree):
        audit_cryptography(node)

