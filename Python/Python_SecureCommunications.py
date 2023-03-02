import ast
import re

# define regular expressions to match insecure communication functions and arguments
insecure_comm_funcs = re.compile(r"socket|httplib|urllib|requests")
insecure_comm_protocols = re.compile(r"http://|ftp://|telnet://")
insecure_comm_kwargs = re.compile(r"(cafile|capath|certfile|keyfile|cert_reqs|ssl_version|context|verify)")

# define a function to check for secure communication
def audit_secure_communication(node):
    # check for function definitions
    if isinstance(node, ast.FunctionDef):
        # check for calls to insecure communication functions
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                # check for insecure communication functions
                func_name = call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                if insecure_comm_funcs.search(func_name):
                    # check for insecure protocol usage
                    if len(call.args) > 0 and isinstance(call.args[0], ast.Str):
                        if insecure_comm_protocols.search(call.args[0].s):
                            print(f"Warning: {node.name} uses insecure communication protocol")
                    # check for missing certificate verification
                    if func_name == "requests" and len(call.keywords) > 0:
                        for kwarg in call.keywords:
                            if kwarg.arg == "verify" and isinstance(kwarg.value, ast.Constant) and not kwarg.value.value:
                                print(f"Warning: {node.name} does not verify server certificates")
                    # check for insecure communication keyword arguments
                    insecure_kwargs = []
                    for kwarg in call.keywords:
                        if insecure_comm_kwargs.search(kwarg.arg):
                            insecure_kwargs.append(kwarg.arg)
                    if insecure_kwargs:
                        print(f"Warning: {node.name} uses insecure communication keyword arguments: {', '.join(insecure_kwargs)}")

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_secure_communication(node)

# example usage
traverse_ast("example.py")

