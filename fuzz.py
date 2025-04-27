import atheris
import sys
import json
import parser
import tempfile
import os
import traceback
import time
import signal
import yaml
import random
from typing import Dict, Any, List, Optional, Union

# Constants
LOG_FILE = "fuzz_errors.log"
STATS_FILE = "fuzz_stats.json"
MAX_EXECUTION_TIME = 300  # 5 minutes timeout per function
FUZZ_ITERATIONS = 1000000  # Increased number of iterations
MAX_JSON_SIZE = 4096
MAX_KEY_SIZE = 100
YAML_EXTENSIONS = [".yaml", ".yml"]

# Global statistics
stats = {
    "total_runs": 0,
    "crashes": 0,
    "timeouts": 0,
    "functions": {
        "getKeyRecursively": {"calls": 0, "exceptions": 0, "avg_time": 0},
        "getValuesRecursively": {"calls": 0, "exceptions": 0, "avg_time": 0},
        "keyMiner": {"calls": 0, "exceptions": 0, "avg_time": 0},
        "checkIfValidK8SYaml": {"calls": 0, "exceptions": 0, "avg_time": 0},
        "find_json_path_keys": {"calls": 0, "exceptions": 0, "avg_time": 0},
        "parse_json_or_yaml": {"calls": 0, "exceptions": 0, "avg_time": 0}
    }
}

# Initialize corpus directory for interesting inputs
CORPUS_DIR = "fuzz_corpus"
os.makedirs(CORPUS_DIR, exist_ok=True)


def save_stats():
    """Save current statistics to file"""
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)


def log_error(message, stack_trace=None):
    """Log error with timestamp and optional stack trace"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
        if stack_trace:
            f.write(f"Stack trace: {stack_trace}\n")
        f.write("-" * 80 + "\n")


def save_interesting_input(data, function_name, error_type):
    """Save interesting inputs to corpus for future fuzzing"""
    filename = f"{CORPUS_DIR}/{function_name}_{error_type}_{int(time.time())}.bin"
    with open(filename, "wb") as f:
        f.write(data)


def timeout_handler(signum, frame):
    """Handle timeouts"""
    raise TimeoutError("Function execution timed out")


def with_timeout(func, *args, **kwargs):
    """Execute function with timeout"""
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(MAX_EXECUTION_TIME)

    try:
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        return result, elapsed
    except Exception as e:
        elapsed = time.time() - start_time
        raise e
    finally:
        signal.alarm(0)  # Clear the alarm


def generate_valid_json(fdp, max_depth=3, current_depth=0):
    """Generate valid JSON structure for more targeted fuzzing"""
    if current_depth >= max_depth:
        # Generate leaf node
        choice = fdp.ConsumeIntInRange(0, 3)
        if choice == 0:
            return fdp.ConsumeString(MAX_KEY_SIZE)
        elif choice == 1:
            return fdp.ConsumeInt(MAX_KEY_SIZE)
        elif choice == 2:
            return fdp.ConsumeFloat()
        else:
            return fdp.ConsumeBool()

    # Generate container type
    container_type = fdp.ConsumeIntInRange(0, 1)
    if container_type == 0:  # Object
        result = {}
        num_fields = fdp.ConsumeIntInRange(1, 5)
        for _ in range(num_fields):
            key = fdp.ConsumeString(20)
            if key:  # Ensure key is not empty
                result[key] = generate_valid_json(fdp, max_depth, current_depth + 1)
        return result
    else:  # Array
        result = []
        num_elements = fdp.ConsumeIntInRange(1, 5)
        for _ in range(num_elements):
            result.append(generate_valid_json(fdp, max_depth, current_depth + 1))
        return result


def generate_yaml_content(fdp):
    """Generate semi-valid YAML content for targeted fuzzing"""
    try:
        # Start with valid structure
        base_structure = generate_valid_json(fdp)
        # Convert to YAML
        yaml_content = yaml.dump(base_structure)

        # Introduce potential errors
        if fdp.ConsumeBool():
            # Add some intentional syntax errors
            error_choice = fdp.ConsumeIntInRange(0, 3)
            if error_choice == 0:
                # Indentation error
                lines = yaml_content.split('\n')
                if len(lines) > 1:
                    idx = fdp.ConsumeIntInRange(1, len(lines) - 1)
                    spaces = fdp.ConsumeIntInRange(1, 10)
                    lines[idx] = ' ' * spaces + lines[idx].lstrip()
                    yaml_content = '\n'.join(lines)
            elif error_choice == 1:
                # Missing colon
                yaml_content = yaml_content.replace(':', '', 1)
            elif error_choice == 2:
                # Invalid characters
                yaml_content += fdp.ConsumeString(20)

        return yaml_content
    except Exception:
        # Fall back to random string if structured generation fails
        return fdp.ConsumeString(MAX_JSON_SIZE)


def test_function(func_name, func, *args, **kwargs):
    """Test a function and track statistics"""
    global stats

    stats["functions"][func_name]["calls"] += 1

    try:
        result, elapsed = with_timeout(func, *args, **kwargs)

        # Update average execution time
        current_avg = stats["functions"][func_name]["avg_time"]
        current_calls = stats["functions"][func_name]["calls"]
        stats["functions"][func_name]["avg_time"] = (current_avg * (current_calls - 1) + elapsed) / current_calls

        return result
    except TimeoutError as e:
        stats["timeouts"] += 1
        stats["functions"][func_name]["exceptions"] += 1
        log_error(f"[{func_name}] Timeout after {MAX_EXECUTION_TIME} seconds")
        return None
    except Exception as e:
        stats["functions"][func_name]["exceptions"] += 1
        stack_trace = traceback.format_exc()
        log_error(f"[{func_name}] Exception: {repr(e)}", stack_trace)
        return None


def test_get_key_recursively(fdp, data):
    """Test getKeyRecursively function"""
    try:
        # Try to get valid JSON first
        if fdp.ConsumeBool():
            # Use structured JSON generation
            obj = generate_valid_json(fdp)
        else:
            # Use random JSON data
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(min(MAX_JSON_SIZE, len(data))))

        if isinstance(obj, dict):
            lst = []
            test_function("getKeyRecursively", parser.getKeyRecursively, obj, lst)
    except Exception as e:
        log_error(f"[getKeyRecursively] Failed to prepare test: {repr(e)}")


def test_get_values_recursively(fdp, data):
    """Test getValuesRecursively function"""
    try:
        # Try to get valid JSON first
        if fdp.ConsumeBool():
            # Use structured JSON generation
            obj = generate_valid_json(fdp)
        else:
            # Use random JSON data
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(min(MAX_JSON_SIZE, len(data))))

        if isinstance(obj, dict):
            test_function("getValuesRecursively", parser.getValuesRecursively, obj)
    except Exception as e:
        log_error(f"[getValuesRecursively] Failed to prepare test: {repr(e)}")


def test_key_miner(fdp, data):
    """Test keyMiner function"""
    try:
        # Try to get valid JSON first
        if fdp.ConsumeBool():
            # Use structured JSON generation
            obj = generate_valid_json(fdp)
        else:
            # Use random JSON data
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(min(MAX_JSON_SIZE, len(data))))

        if isinstance(obj, dict):
            search_key = fdp.ConsumeUnicodeNoSurrogates(MAX_KEY_SIZE)
            test_function("keyMiner", parser.keyMiner, obj, search_key)
    except Exception as e:
        log_error(f"[keyMiner] Failed to prepare test: {repr(e)}")


def test_check_if_valid_k8s_yaml(fdp, data):
    """Test checkIfValidK8SYaml function"""
    try:
        # Generate YAML content
        if fdp.ConsumeBool():
            fake_yaml = generate_yaml_content(fdp)
        else:
            fake_yaml = fdp.ConsumeUnicodeNoSurrogates(MAX_JSON_SIZE)

        # Choose random extension
        ext = random.choice(YAML_EXTENSIONS)

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            fake_path = f.name
            f.write(fake_yaml.encode("utf-8"))

        # Test function
        test_function("checkIfValidK8SYaml", parser.checkIfValidK8SYaml, fake_path)

        # Clean up
        if os.path.exists(fake_path):
            os.remove(fake_path)
    except Exception as e:
        log_error(f"[checkIfValidK8SYaml] Failed to prepare test: {repr(e)}")
        # Clean up in case of exception
        if 'fake_path' in locals() and os.path.exists(fake_path):
            os.remove(fake_path)


def test_find_json_path_keys(fdp, data):
    """Test find_json_path_keys function"""
    try:
        # Try to get valid JSON first
        if fdp.ConsumeBool():
            # Use structured JSON generation
            obj = generate_valid_json(fdp)
        else:
            # Use random JSON data
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(min(MAX_JSON_SIZE, len(data))))

        if isinstance(obj, dict):
            test_function("find_json_path_keys", parser.find_json_path_keys, obj)
    except Exception as e:
        log_error(f"[find_json_path_keys] Failed to prepare test: {repr(e)}")


def test_parse_json_or_yaml(fdp, data):
    """Test new function for parsing both JSON and YAML"""
    if not hasattr(parser, 'parse_json_or_yaml'):
        # Skip if function doesn't exist
        return

    try:
        # Create a test file
        is_json = fdp.ConsumeBool()

        if is_json:
            # Generate JSON content
            if fdp.ConsumeBool():
                content = json.dumps(generate_valid_json(fdp))
            else:
                content = fdp.ConsumeUnicodeNoSurrogates(MAX_JSON_SIZE)
            ext = ".json"
        else:
            # Generate YAML content
            if fdp.ConsumeBool():
                content = generate_yaml_content(fdp)
            else:
                content = fdp.ConsumeUnicodeNoSurrogates(MAX_JSON_SIZE)
            ext = random.choice(YAML_EXTENSIONS)

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as f:
            file_path = f.name
            f.write(content.encode("utf-8"))

        # Test function
        test_function("parse_json_or_yaml", parser.parse_json_or_yaml, file_path)

        # Clean up
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        log_error(f"[parse_json_or_yaml] Failed to prepare test: {repr(e)}")
        # Clean up in case of exception
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)


def TestOneInput(data):
    """Main fuzzing function that tests all target functions"""
    global stats
    stats["total_runs"] += 1

    # Create fuzzed data provider
    fdp = atheris.FuzzedDataProvider(data)

    # Deterministically choose which function to test
    # This focuses fuzzing on one function at a time for more effective testing
    function_choice = fdp.ConsumeIntInRange(0, 5)

    try:
        if function_choice == 0:
            test_get_key_recursively(fdp, data)
        elif function_choice == 1:
            test_get_values_recursively(fdp, data)
        elif function_choice == 2:
            test_key_miner(fdp, data)
        elif function_choice == 3:
            test_check_if_valid_k8s_yaml(fdp, data)
        elif function_choice == 4:
            test_find_json_path_keys(fdp, data)
        elif function_choice == 5:
            test_parse_json_or_yaml(fdp, data)
    except Exception as e:
        stats["crashes"] += 1
        log_error(f"[TestOneInput] Unhandled exception: {repr(e)}", traceback.format_exc())
        save_interesting_input(data, "TestOneInput", type(e).__name__)

    # Save stats periodically
    if stats["total_runs"] % 1000 == 0:
        save_stats()
        print(f"Progress: {stats['total_runs']} runs, "
              f"{stats['crashes']} crashes, "
              f"{stats['timeouts']} timeouts")


def load_corpus():
    """Load any existing corpus files"""
    corpus_data = []
    if os.path.exists(CORPUS_DIR):
        for filename in os.listdir(CORPUS_DIR):
            if filename.endswith(".bin"):
                try:
                    with open(os.path.join(CORPUS_DIR, filename), 'rb') as f:
                        corpus_data.append(f.read())
                except Exception as e:
                    print(f"Failed to load corpus file {filename}: {e}")
    return corpus_data


def main():
    """Main function to set up and run the fuzzer"""
    # Clear old log file
    open(LOG_FILE, "w").close()

    # Initialize stats file
    save_stats()

    print("Starting enhanced fuzzer...")

    # Check if we're running in AFL mode
    if os.getenv('AFL_FUZZ'):
        print("Running in AFL mode")
        atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
        atheris.Fuzz()
    else:
        print(f"Running in standalone mode with {FUZZ_ITERATIONS} iterations")

        # Load corpus data
        corpus = load_corpus()
        if corpus:
            print(f"Loaded {len(corpus)} files from corpus")

        try:
            # Run with corpus first
            for corpus_data in corpus:
                TestOneInput(corpus_data)

            # Then run with random data
            for i in range(FUZZ_ITERATIONS):
                if i % 10000 == 0 and i > 0:
                    print(f"Completed {i} iterations")

                # Generate random data with varying size
                size = random.randint(128, MAX_JSON_SIZE)
                fuzz_data = os.urandom(size)
                TestOneInput(fuzz_data)

        except KeyboardInterrupt:
            print("Fuzzing interrupted by user")
        finally:
            # Save final stats
            save_stats()

            # Print summary
            print("\nFuzzing completed")
            print(f"Total runs: {stats['total_runs']}")
            print(f"Total crashes: {stats['crashes']}")
            print(f"Total timeouts: {stats['timeouts']}")
            print("\nFunction statistics:")
            for func_name, func_stats in stats["functions"].items():
                if func_stats["calls"] > 0:
                    print(f"  {func_name}:")
                    print(f"    Calls: {func_stats['calls']}")
                    print(
                        f"    Exceptions: {func_stats['exceptions']} ({func_stats['exceptions'] / func_stats['calls'] * 100:.2f}%)")
                    print(f"    Avg time: {func_stats['avg_time']:.6f} seconds")


if __name__ == "__main__":
    main()