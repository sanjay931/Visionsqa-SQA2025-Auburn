 Task 4.c - Forensics Integration

 Overview
We integrated forensics capabilities into 5 key methods of the KubeSec project to enhance security analysis with detailed audit trails and execution tracking.
 Methods Modified with Forensics

1. **main()** in main.py
   - The entry point for the application
   - Forensics track the overall execution flow, including input directories and results

2. **scanSingleManifest()** in scanner.py
   - Core function for analyzing Kubernetes manifests
   - Forensics capture detected security issues and manifest processing details

3. **scanForOverPrivileges()** in scanner.py
   - Specialized function for detecting privilege escalation risks
   - Forensics log privilege-related security findings

4. **mineSecretGraph()** in graphtaint.py
   - Function for tracking secret propagation through configuration files
   - Forensics track secret detection and taint analysis

5. **loadMultiYAML()** in parser.py
   - Critical function for parsing Kubernetes YAML files
   - Forensics log file loading operations and parsing errors

 Implementation Details

 Forensics Decorator
We implemented a `forensics_decorator` that:
- Captures method entry with timestamp and parameters
- Records call stack information
- Logs method exit with execution time
- Captures return values
- Handles exceptions with detailed error information
- Creates structured logs in both text and JSON formats

 Logging Infrastructure
- **Log Files**: Generated in the `forensics_logs` directory
- **Text Logs**: Human-readable logs in `forensics.log`
- **JSON Logs**: Machine-parsable structured logs in `forensics.json`
- **Log Content**: Each log entry includes timestamp, execution ID, method name, parameters, and execution results

 Error Handling
We enhanced error handling for missing dependencies:
- Graceful handling of missing `yq` command
- Default line number assignment when line information cannot be determined
- Exception capture with detailed context

 How to Access Forensics Data

1. Run the KubeSec application
2. Check the `forensics_logs` directory for log files
3. Analyze `forensics.log` for human-readable logs
4. Process `forensics.json` for automated analysis

 Benefits

- **Enhanced Debugging**: Detailed execution tracking makes troubleshooting easier- **Security Audit Trail**: Complete record of security checks and findings
- **Performance Monitoring**: Execution time tracking identifies bottlenecks
- **Error Identification**: Comprehensive exception logging aids in resolving issues
- **Execution Transparency**: Clear visibility into the analysis process

This forensics implementation significantly enhances the security analysis capabilities of KubeSec by providing a comprehensive audit trail and detailed visibility into the scanning process.
---

 4.a Git Hook for Bandit Security Scanning 

 Applied Technique
We implemented a **Git pre-commit hook** that automatically performs a **static security analysis** of staged Python files using [Bandit](https://bandit.readthedocs.io/en/latest/).

The hook executes every time a `.py` file is committed and generates a CSV report (`bandit_report.csv`) containing security warnings such as:
- Use of `eval()`
- Hardcoded passwords
- Insecure system calls
- Unsafe imports

 Hook Implementation Summary
- Initially attempted to use Docker-based Bandit images (e.g., `ghcr.io`, `banditsec/bandit`) — failed due to login/auth issues and broken entrypoints.
- Final working solution used local Bandit installation via `pip install bandit`.
- Hook script creates `.bandit_temp` folder, scans it with Bandit, and saves results in `bandit_report.csv`.

 Example Output
```csv
filename,test_name,test_id,issue_severity,issue_text
.bandit_temp/test.py,blacklist_calls,B307,HIGH,Use of eval detected.
