import ast
import re

# define a function to check for secure configuration management
def audit_secure_config(node):
    # check for function definitions
    if isinstance(node, ast.FunctionDef):
        # check for calls to insecure configuration functions
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func_name = call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                if func_name in ["ConfigParser", "os.environ"]:
                    print(f"Warning: {node.name} uses an insecure configuration function ({func_name})")
                elif func_name == "open":
                    if len(call.args) > 0 and isinstance(call.args[0], ast.Str):
                        if call.args[0].s.endswith(".ini"):
                            print(f"Warning: {node.name} uses an insecure configuration file format (.ini)")
                elif func_name in ["subprocess.call", "subprocess.Popen"]:
                    if len(call.args) > 0 and isinstance(call.args[0], ast.Str):
                        if any(arg in call.args[0].s for arg in ["ssh", "scp"]):
                            print(f"Warning: {node.name} uses an insecure shell command ({call.args[0].s})")
                elif func_name == "getpass":
                    if not any(isinstance(parent, ast.Call) and parent.func == call for parent in ast.iter_parents(call)):
                        print(f"Warning: {node.name} uses getpass() instead of a secure password input function")
        # check for hardcoded secrets
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.targets[0], ast.Name) and isinstance(stmt.value, ast.Str):
                    if stmt.targets[0].id in ["username", "password", "secret_key", "api_key"]:
                        print(f"Warning: {node.name} has a hardcoded {stmt.targets[0].id}")
                elif isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.left, ast.Str) and isinstance(stmt.value.right, ast.Str):
                    if isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id in ["password", "secret_key", "api_key"]:
                        print(f"Warning: {node.name} has a hardcoded {stmt.targets[0].id} (using string concatenation)")
                elif isinstance(stmt.value, ast.JoinedStr) and all(isinstance(value, ast.Str) for value in stmt.value.values):
                    if any(secret in stmt.value.s for secret in ["password", "secret_key", "api_key"]):
                        print(f"Warning: {node.name} has a hardcoded secret (using f-strings or format() method)")
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Str):
                if "password" in stmt.value.s or "secret_key" in stmt.value.s or "api_key" in stmt.value.s:
                    print(f"Warning: {node.name} has a hardcoded password or API key")
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.annotation, ast.Name) and stmt.annotation.id == "bytes":
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, bytes) and re.search(br"password|secret_key|api_key", stmt.value.value):
                    print(f"Warning: {node.name} has a hardcoded secret (using bytes annotation)")

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_secure_config(node)

# example usage
traverse_ast("example.py")

