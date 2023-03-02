import ast

# define a function to check for safe authentication and authorization
def audit_auth_and_authz(node):
    # check for function definitions
    if isinstance(node, ast.FunctionDef):
        # check for calls to unsafe authentication or authorization functions
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func_name = call.func.attr if isinstance(call.func, ast.Attribute) else call.func.id
                if func_name in ["authenticate", "authorize"]:
                    # check for unsalted password hashing
                    if len(call.args) > 0 and func_name == "authenticate" and isinstance(call.args[0], ast.Str):
                        if not any(hash_func in call.args[0].s for hash_func in ["bcrypt", "scrypt", "argon2"]):
                            print(f"Warning: {node.name} uses unsalted password hashing")
                    # check for insecure session management
                    if len(call.args) > 0 and func_name == "authorize" and isinstance(call.args[0], ast.Str):
                        if not "secure" in call.args[0].s.lower():
                            print(f"Warning: {node.name} uses insecure session management")
                    # check for insecure authorization checks
                    if len(call.args) > 1 and func_name == "authorize" and isinstance(call.args[1], ast.Dict):
                        # check for unchecked keys in the authorization dictionary
                        unchecked_keys = [key.s for key in call.args[1].keys if not any(s in key.s.lower() for s in ["allow", "deny"])]
                        if unchecked_keys:
                            print(f"Warning: {node.name} performs incomplete authorization checks for keys: {unchecked_keys}")
                        # check for overly permissive allow/deny rules
                        allow_rules = [rule for rule in call.args[1].values if isinstance(rule, ast.Constant) and rule.value == True and "allow" in rule.parent.keys.s]
                        deny_rules = [rule for rule in call.args[1].values if isinstance(rule, ast.Constant) and rule.value == True and "deny" in rule.parent.keys.s]
                        if allow_rules and not deny_rules:
                            print(f"Warning: {node.name} includes overly permissive 'allow' rules in its authorization checks")
                        if deny_rules and not allow_rules:
                            print(f"Warning: {node.name} includes overly permissive 'deny' rules in its authorization checks")

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_auth_and_authz(node)

# example usage
traverse_ast("example.py")

