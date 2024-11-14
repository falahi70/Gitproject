import subprocess
import os
from datetime import datetime

def run_command(command, log_file):
    """Run a shell command and write output to a log file."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    current_dir = f"In current working directory: {os.getcwd()}\n"

    with open(log_file, "a") as log:
        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=log)

            success_message = f"{current_time} - Command '{command}' executed successfully.\n"
            print(success_message.strip())
            print(current_dir)
            log.write(success_message)
            log.write(current_dir)

        except subprocess.CalledProcessError as e:
            error_message = f"{current_time} - Error executing '{command}': {e}\n"
            print(error_message.strip())
            print(current_dir)
            log.write(error_message)
            log.write(current_dir)

def main():
    # ip_mac_history
    os.chdir("/CoreInspect/agents/ip_mac_history")
    run_command("/root/.pyenv/shims/python3 main.py", "/CoreInspect/agents/ip_mac_history/ip_mac_history.log")
    
    # portScanner
    os.chdir("/CoreInspect/agents/portScanner")
    run_command("/root/.pyenv/shims/python3 tcpPortScanner.py", "/CoreInspect/agents/portScanner/portScanner.log")
    
    # webSignatureDetector
    os.chdir("/CoreInspect/agents/webSignatureDetector")
    run_command("/root/.pyenv/shims/python3 main.py", "/CoreInspect/agents/webSignatureDetector/webSignatureDetector.log")

if __name__ == "__main__":
    main()

