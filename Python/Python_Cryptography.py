import ast
import re

# define regular expressions for insecure cryptography patterns
insecure_hash_func_re = re.compile(r"(^|\W)hashlib\.(md5|sha1)\W")
insecure_mac_func_re = re.compile(r"(^|\W)(hmac\.new|hashlib\.pbkdf2_hmac)\W")
insecure_random_func_re = re.compile(r"(^|\W)random\.\w+\W")

# define default settings for cryptographic key sizes and operations
key_sizes = {
    "RSA": 2048,
    "DSA": 2048,
    "ECDSA": 256,
    "Ed25519": 256,
    "AES": 256,
    "ChaCha20": 256,
}

required_ops = {
    "RSA": {"encrypt", "decrypt", "sign", "verify"},
    "DSA": {"sign", "verify"},
    "ECDSA": {"sign", "verify"},
    "Ed25519": {"sign", "verify"},
    "AES": {"encrypt", "decrypt"},
    "ChaCha20": {"encrypt", "decrypt"},
}

# define a function to check for cryptography usage
def audit_cryptography(node, key_sizes=key_sizes, required_ops=required_ops):
    # check for function definitions
    if isinstance(node, ast.FunctionDef):
        # check for calls to insecure cryptography functions
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func_name = call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                if insecure_hash_func_re.search(func_name):
                    print(f"Warning: {node.name} uses an insecure hash function")
                elif insecure_mac_func_re.search(func_name):
                    print(f"Warning: {node.name} uses an insecure message authentication code (MAC) function")
                elif insecure_random_func_re.search(func_name):
                    if not any(isinstance(parent, ast.Call) and parent.func == call for parent in ast.iter_parents(call)):
                        print(f"Warning: {node.name} uses the insecure random number generator (consider using secrets module)")
        # check for cryptographic key sizes and operations
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                if targets and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name):
                    crypto_name = stmt.value.func.id
                    if crypto_name in key_sizes:
                        size = next((kw.value.n for kw in stmt.value.keywords if kw.arg == "bits"), None) or key_sizes[crypto_name]
                        if size < key_sizes[crypto_name]:
                            print(f"Warning: {node.name} uses a weak key size for {crypto_name}")
                    if crypto_name in required_ops:
                        ops = {arg.s for arg in stmt.value.args} | {kw.arg for kw in stmt.value.keywords}
                        if not required_ops[crypto_name].issubset(ops):
                            missing_ops = required_ops[crypto_name] - ops
                            print(f"Warning: {node.name} does not use all required cryptographic operations for {crypto_name} ({', '.join(missing_ops)})")

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_cryptography(node)

# example usage
traverse_ast("example.py")

