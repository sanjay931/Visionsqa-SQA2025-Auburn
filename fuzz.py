import atheris
import sys
import json
import parser
import tempfile
import os

LOG_FILE = "fuzz_errors.log"

def log_error(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Test 1: getKeyRecursively
    try:
        obj1 = json.loads(fdp.ConsumeUnicodeNoSurrogates(1000))
        if isinstance(obj1, dict):
            lst = []
            parser.getKeyRecursively(obj1, lst)
    except Exception as e:
        log_error(f"[getKeyRecursively] Exception: {repr(e)}")

    # Test 2: getValuesRecursively
    try:
        obj2 = json.loads(fdp.ConsumeUnicodeNoSurrogates(1000))
        if isinstance(obj2, dict):
            parser.getValuesRecursively(obj2)
    except Exception as e:
        log_error(f"[getValuesRecursively] Exception: {repr(e)}")

    # Test 3: keyMiner
    try:
        obj3 = json.loads(fdp.ConsumeUnicodeNoSurrogates(1000))
        if isinstance(obj3, dict):
            parser.keyMiner(obj3, fdp.ConsumeUnicodeNoSurrogates(20))
    except Exception as e:
        log_error(f"[keyMiner] Exception: {repr(e)}")

    # Test 4: checkIfValidK8SYaml
    try:
        fake_yaml = fdp.ConsumeUnicodeNoSurrogates(1000)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as f:
            fake_path = f.name
            f.write(fake_yaml.encode("utf-8"))
        parser.checkIfValidK8SYaml(fake_path)
        os.remove(fake_path)
    except Exception as e:
        log_error(f"[checkIfValidK8SYaml] Exception: {repr(e)}")
        if os.path.exists(fake_path):
            os.remove(fake_path)

    # Test 5: find_json_path_keys
    try:
        obj5 = json.loads(fdp.ConsumeUnicodeNoSurrogates(1000))
        if isinstance(obj5, dict):
            parser.find_json_path_keys(obj5)
    except Exception as e:
        log_error(f"[find_json_path_keys] Exception: {repr(e)}")



def main():
    # Clear old log file
    open(LOG_FILE, "w").close()

    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    #atheris.Fuzz()
    fdp = atheris.FuzzedDataProvider(b"")

    for _ in range(500000):
        fuzz_data = os.urandom(4096)
        TestOneInput(fuzz_data)


if __name__ == "__main__":
    main()
