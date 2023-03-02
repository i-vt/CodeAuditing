import ast
import re

# define a regular expression to match common API keys in URLs and headers
API_KEY_REGEX = re.compile(r"^(?:api|access)_?(?:key|token)$", re.IGNORECASE)

# define a function to check for API security
def audit_api_security(node):
    # check for function definitions
    if isinstance(node, ast.FunctionDef):
        # check for insecure API usage
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func_name = call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                # check for insecure JSON response
                if func_name in ["flask.jsonify", "django.http.JsonResponse"]:
                    if len(call.args) > 0 and isinstance(call.args[0], ast.Dict):
                        if not any(key.s == "status" and value.s == "success" for key, value in zip(call.args[0].keys, call.args[0].values)):
                            print(f"Warning: {node.name} returns insecure JSON response")
                # check for missing or weak API key validation
                elif func_name == "flask.request":
                    headers = [arg for arg in call.args if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "get"]
                    for header in headers:
                        if isinstance(header.args[0], ast.Str) and API_KEY_REGEX.match(header.args[0].s):
                            if not any(isinstance(parent, ast.If) and isinstance(parent.test, ast.Compare) and isinstance(parent.test.ops[0], ast.Eq) and isinstance(parent.test.left, ast.Attribute) and parent.test.left.attr == "get" and isinstance(parent.test.right, ast.Str) and parent.test.right.s == "ADMIN" for parent in ast.iter_parents(header)):
                                print(f"Warning: {node.name} does not validate or weakly validates {header.args[0].s} header")
                    query_params = [arg for arg in call.args if isinstance(arg, ast.Name) and arg.id == "args"]
                    for query_param in query_params:
                        if isinstance(query_param.ctx, ast.Load):
                            if not any(isinstance(parent, ast.If) and isinstance(parent.test, ast.Compare) and isinstance(parent.test.ops[0], ast.Eq) and isinstance(parent.test.left, ast.Attribute) and parent.test.left.attr == query_param.id and isinstance(parent.test.right, ast.Str) and parent.test.right.s == "ADMIN" for parent in ast.iter_parents(query_param)):
                                print(f"Warning: {node.name} does not validate or weakly validates {query_param.id} query parameter")
                # check for insecure authentication methods
                elif func_name == "flask_httpauth.HTTPBasicAuth.login_required":
                    if not any(isinstance(parent, ast.Compare) and isinstance(parent.ops[0], ast.NotEq) and isinstance(parent.left, ast.Attribute) and parent.left.attr == "username" and isinstance(parent.right, ast.Str) and parent.right.s == "ADMIN" for parent in ast.iter_parents(call)):
                        print(f"Warning: {node.name} uses insecure authentication method")
                elif func_name == "flask_login.login_required":
                    if not any(isinstance(parent, ast.Compare) and isinstance(parent.ops[0], ast.NotEq) and isinstance(parent.left, ast.Attribute) and parent.left.attr == "user" and isinstance(parent.right, ast.Name) and parent.right.id == "current_user" for parent in ast.iter_parents(call)):
                        print(f"Warning: {node.name} uses insecure authentication method")

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_api_security(node)

# example usage
traverse_ast("example.py")
