import ast
import re
import builtins

# define regular expressions to match common malicious strings
MALICIOUS_REGEX = re.compile(r"(?:exec|eval|subprocess|shell|os\.)", re.IGNORECASE)
DANGEROUS_MODULES = set(["subprocess", "os", "shutil", "sys"])
DANGEROUS_FUNCTIONS = set(["eval", "exec", "input", "open", "__import__"])

# define a function to check for malicious strings
def audit_malicious_strings(node):
    # check for string literals
    if isinstance(node, ast.Str):
        if MALICIOUS_REGEX.search(node.s):
            print(f"Warning: possible malicious string found in {node.lineno}:{node.col_offset}")
        else:
            # check if string is used in a dangerous context
            try:
                names = set(node.parent().names)
                for name in names:
                    if name in DANGEROUS_MODULES:
                        print(f"Warning: possible malicious module import found in {node.lineno}:{node.col_offset}")
                        break
                else:
                    for name in names:
                        if name in DANGEROUS_FUNCTIONS:
                            print(f"Warning: possible malicious function call found in {node.lineno}:{node.col_offset}")
                            break
            except AttributeError:
                pass

# define a function to traverse the abstract syntax tree of a Python file
def traverse_ast(filename):
    with open(filename, "r") as file:
        tree = ast.parse(file.read())
        # iterate over the nodes in the tree
        for node in ast.walk(tree):
            audit_malicious_strings(node)

# example usage
traverse_ast("example.py")

