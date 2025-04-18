#!/usr/bin/env python3

import logging
import datetime
import os
import time
import traceback
import json
import inspect
import functools
import sys

# Ensure forensics directory exists
os.makedirs("forensics_logs", exist_ok=True)

# Configure forensics logging
forensics_logger = logging.getLogger('forensics')
forensics_logger.setLevel(logging.INFO)

# Create file handler
log_file = 'forensics_logs/forensics.log'
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add handler to logger
if not forensics_logger.handlers:
    forensics_logger.addHandler(file_handler)

# Create JSON handler for structured logging
json_log_file = 'forensics_logs/forensics.json'

def log_to_json(log_entry):
    """Write a log entry to the JSON log file."""
    with open(json_log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def forensics_decorator(func):
    """
    Decorator to add forensics logging to a function.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Generate a unique execution ID
        exec_id = str(int(time.time() * 1000))
        
        # Get function details
        module = func.__module__
        func_name = func.__name__
        
        # Get caller info
        caller_frame = inspect.currentframe().f_back
        caller_info = ""
        if caller_frame:
            caller_filename = caller_frame.f_code.co_filename
            caller_lineno = caller_frame.f_lineno
            caller_function = caller_frame.f_code.co_name
            caller_info = f"{caller_filename}:{caller_function}:{caller_lineno}"

        # Log method entry
        start_time = datetime.datetime.now()
        
        # Format args and kwargs for logging
        args_str = ", ".join(repr(arg) for arg in args)
        kwargs_str = ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
        params_str = args_str
        if kwargs_str:
            if params_str:
                params_str += ", " + kwargs_str
            else:
                params_str = kwargs_str
                
        entry_msg = f"Method Entry: {module}.{func_name}({params_str})"
        forensics_logger.info(entry_msg)
        
        # Create log entry for JSON
        log_entry = {
            "timestamp": start_time.isoformat(),
            "exec_id": exec_id,
            "type": "entry",
            "module": module,
            "function": func_name,
            "caller": caller_info,
            "args": str(args),
            "kwargs": str(kwargs),
        }
        log_to_json(log_entry)
        
        # Execute the function
        result = None
        exception_raised = None
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            exception_raised = e
            # Log the exception
            error_msg = f"Exception in {module}.{func_name}: {str(e)}"
            forensics_logger.error(error_msg)
            forensics_logger.error(traceback.format_exc())
            
            # Create exception log entry for JSON
            log_entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "exec_id": exec_id,
                "type": "exception",
                "module": module,
                "function": func_name,
                "exception": str(e),
                "traceback": traceback.format_exc()
            }
            log_to_json(log_entry)
            
            # Re-raise the exception
            raise
        finally:
            # Log method exit
            end_time = datetime.datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            # Determine result type
            result_type = "None"
            if result is not None:
                result_type = type(result).__name__
                
            # Create abbreviated result string
            result_str = "None"
            if result is not None:
                try:
                    if isinstance(result, (list, dict, tuple)):
                        result_str = f"{result_type} of length {len(result)}"
                    else:
                        result_str = str(result)[:100]
                        if len(str(result)) > 100:
                            result_str += "..."
                except:
                    result_str = f"<{result_type} object>"
            
            exit_msg = f"Method Exit: {module}.{func_name}, Duration: {execution_time:.6f}s, Result: {result_str}"
            forensics_logger.info(exit_msg)
            
            # Create exit log entry for JSON
            log_entry = {
                "timestamp": end_time.isoformat(),
                "exec_id": exec_id,
                "type": "exit",
                "module": module,
                "function": func_name,
                "duration": execution_time,
                "result_type": result_type,
                "status": "error" if exception_raised else "success"
            }
            log_to_json(log_entry)
    
    return wrapper
