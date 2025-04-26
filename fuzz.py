#!/usr/bin/env python3

import random
import string
import sys
import os
import importlib.util
import traceback
from datetime import datetime
import yaml
import json

# Configure logging
import logging
logging.basicConfig(
    filename='fuzz_results.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def random_string(length=10):
    """Generate a random string."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def random_int(min_val=-1000, max_val=1000):
    """Generate a random integer."""
    return random.randint(min_val, max_val)

def random_float():
    """Generate a random float."""
    return random.uniform(-1000.0, 1000.0)

def random_bool():
    """Generate a random boolean."""
    return random.choice([True, False])

def random_list(max_length=10):
    """Generate a random list."""
    length = random.randint(0, max_length)
    return [random_choice() for _ in range(length)]

def random_dict(max_length=5):
    """Generate a random dictionary."""
    length = random.randint(0, max_length)
    return {random_string(): random_choice() for _ in range(length)}

def random_choice():
    """Return a random value of a random type."""
    choice = random.choice(['string', 'int', 'float', 'bool', 'list', 'dict', 'None'])
    if choice == 'string':
        return random_string()
    elif choice == 'int':
        return random_int()
    elif choice == 'float':
        return random_float()
    elif choice == 'bool':
        return random_bool()
    elif choice == 'list':
        return random_list(3)  # Limiting nested depth
    elif choice == 'dict':
        return random_dict(2)  # Limiting nested depth
    elif choice == 'None':
        return None

def random_file_path():
    """Generate a random file path."""
    extensions = ['.py', '.yml', '.yaml', '.json', '.txt', '.md']
    depth = random.randint(0, 3)
    path = ""
    for _ in range(depth):
        path += random_string(5) + "/"
    path += random_string(8) + random.choice(extensions)
    return path

def random_yaml_content():
    """Generate random YAML content."""
    data = {
        'apiVersion': random_string(5),
        'kind': random_string(8),
        'metadata': {
            'name': random_string(10),
            'namespace': random_string(6)
        },
        'spec': {
            'containers': [
                {
                    'name': random_string(8),
                    'image': f"{random_string(6)}/{random_string(8)}:{random_string(4)}",
                    'ports': [{'containerPort': random_int(1, 65535)}]
                }
            ]
        }
    }
    return yaml.dump(data)

def import_module_from_file(file_path):
    """Import a module from a file path."""
    try:
        module_name = os.path.basename(file_path).replace('.py', '')
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            logging.error(f"Could not create spec for {file_path}")
            return None
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            logging.error(f"Error executing module {file_path}: {str(e)}")
            return None
    except Exception as e:
        logging.error(f"Error importing module {file_path}: {str(e)}")
        return None

def get_specific_args_for_method(method_name):
    """Return specific arguments for known methods."""
    if method_name == "load_manifest":
        return [random_file_path()]
    elif method_name == "parse_yaml":
        return [random_yaml_content()]
    elif method_name == "kube_parser":
        return [random_file_path()]
    elif method_name == "scanForCredentials":
        return [random_dict(), random_string()]
    elif method_name == "getYAMLFiles":
        return [random_string()]
    else:
        return None  # No specific args, use random

def fuzz_function(func, iterations=100):
    """Fuzz a function with random inputs."""
    bugs_found = 0
    bug_details = []
    
    for i in range(iterations):
        # Determine number of arguments
        import inspect
        sig = inspect.signature(func)
        param_count = len(sig.parameters)
        
        # Generate arguments - either specific or random
        specific_args = get_specific_args_for_method(func.__name__)
        if specific_args is not None:
            args = specific_args
        else:
            args = [random_choice() for _ in range(param_count)]
        
        try:
            func(*args)
        except Exception as e:
            bugs_found += 1
            bug_info = {
                "function": func.__name__,
                "iteration": i,
                "arguments": str(args),
                "exception": str(e),
                "traceback": traceback.format_exc()
            }
            bug_details.append(bug_info)
            logging.error(f"Bug found in {func.__name__}:")
            logging.error(f"  Arguments: {args}")
            logging.error(f"  Exception: {str(e)}")
            logging.error(f"  Traceback: {traceback.format_exc()}")
            
    return bugs_found, bug_details

def main():
    # List the Python files and methods to fuzz
    # Based on repository files
    target_methods = [
        {"file": "parser.py", "method": "getYAMLFiles"},
        {"file": "scanner.py", "method": "scanForCredentials"},
        {"file": "graphtaint.py", "method": "getDictGraph"},
        {"file": "main.py", "method": "load_manifest"},
        {"file": "TEST_INTEGRATION.py", "method": "kube_parser"}
    ]
    
    total_bugs = 0
    all_bug_details = []
    
    logging.info(f"Starting fuzzing at {datetime.now()}")
    print(f"Starting fuzzing at {datetime.now()}")
    
    # Create results directory
    os.makedirs("fuzzing_results", exist_ok=True)
    
    for target in target_methods:
        file_path = target["file"]
        method_name = target["method"]
        
        try:
            module = import_module_from_file(file_path)
            if module is None:
                logging.warning(f"Could not import module from {file_path}")
                continue
                
            if hasattr(module, method_name):
                func = getattr(module, method_name)
                logging.info(f"Fuzzing {file_path}:{method_name}")
                print(f"Fuzzing {file_path}:{method_name}")
                
                bugs, bug_details = fuzz_function(func)
                total_bugs += bugs
                all_bug_details.extend(bug_details)
                
                logging.info(f"Completed fuzzing {file_path}:{method_name} - Found {bugs} bugs")
                print(f"Completed fuzzing {file_path}:{method_name} - Found {bugs} bugs")
            else:
                logging.warning(f"Method {method_name} not found in {file_path}")
                print(f"Method {method_name} not found in {file_path}")
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {str(e)}")
            print(f"Error processing file {file_path}: {str(e)}")
    
    # Write bug details to a JSON file
    with open("fuzzing_results/bug_report.json", "w") as f:
        json.dump(all_bug_details, f, indent=2)
    
    # Write summary to a markdown file
    with open("fuzzing_results/summary.md", "w") as f:
        f.write("# Fuzzing Results Summary\n\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Total bugs found: {total_bugs}\n\n")
        
        if total_bugs > 0:
            f.write("## Bugs by Method\n\n")
            method_bugs = {}
            for bug in all_bug_details:
                method = bug["function"]
                if method not in method_bugs:
                    method_bugs[method] = []
                method_bugs[method].append(bug)
            
            for method, bugs in method_bugs.items():
                f.write(f"### {method}: {len(bugs)} bugs\n\n")
                for i, bug in enumerate(bugs):
                    f.write(f"#### Bug {i+1}\n\n")
                    f.write(f"- Arguments: {bug['arguments']}\n")
                    f.write(f"- Exception: {bug['exception']}\n\n")
    
    logging.info(f"Fuzzing completed. Total bugs found: {total_bugs}")
    print(f"Fuzzing completed. Total bugs found: {total_bugs}")
    print(f"See fuzzing_results/summary.md and fuzzing_results/bug_report.json for details")

if __name__ == "__main__":
    main()