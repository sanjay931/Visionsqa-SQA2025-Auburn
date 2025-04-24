# #!/bin/bash

# # Pre-commit hook to run security analysis on Python files
# echo "Running security analysis on Python files..."

# # Get list of staged Python files
# STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.py$")

# # If no Python files are staged, exit with success
# if [ -z "$STAGED_FILES" ]; then
#   echo "No Python files to analyze. Skipping security scan."
#   exit 0
# fi

# # Directory for security reports
# mkdir -p security_reports

# # Timestamp for the report filename
# TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
# REPORT_FILE="security_reports/security_weakness_report_$TIMESTAMP.csv"

# # Run bandit on the staged Python files
# echo "Running bandit security analysis..."
# bandit -r $STAGED_FILES -f csv -o $REPORT_FILE

# # Check if vulnerabilities were found
# if [ $? -eq 0 ]; then
#   echo "No security issues found."
#   # Remove the report file if no issues found
#   rm $REPORT_FILE
#   exit 0
# else
#   # Count issues by severity
#   HIGH=$(grep ",HIGH$" $REPORT_FILE | wc -l)
#   MEDIUM=$(grep ",MEDIUM$" $REPORT_FILE | wc -l)
#   LOW=$(grep ",LOW$" $REPORT_FILE | wc -l)
  
#   echo "Security scan completed. Issues found:"
#   echo "  HIGH: $HIGH"
#   echo "  MEDIUM: $MEDIUM"
#   echo "  LOW: $LOW"
#   echo "Report saved to $REPORT_FILE"
  
#   # Add the report to git
#   git add $REPORT_FILE
  
#   echo "Security analysis completed. See $REPORT_FILE for details."
#   # Allow the commit to proceed
#   exit 0
# fi