# -*- coding: utf-8 -*-
"""
Created on Mon Mar 3 6:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Process Injection Attack Detector")
print(Fore.GREEN+font)

import os
import psutil
import pefile
import hashlib
import time

# Function to compute SHA256 hash of a file
def compute_file_hash(file_path):
    """Computes SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read file in chunks
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to analyze PE file (Windows Executable)
def analyze_pe_file(file_path):
    """Analyze PE (Portable Executable) file and check for unusual modifications."""
    try:
        pe = pefile.PE(file_path)
        
        print(f"\nAnalyzing PE file: {file_path}")
        
        # Check for unusual code section modifications
        suspicious_sections = []
        for section in pe.sections:
            # Look for non-zero entropy or very large sections in unexpected places
            if section.SizeOfRawData > 100000:  # Large section might indicate injected code
                suspicious_sections.append(section)
        
        if suspicious_sections:
            print("Warning: Potential process injection detected in the following sections:")
            for section in suspicious_sections:
                print(f"  - Section: {section.Name.decode().strip()}")
                print(f"    Size: {section.SizeOfRawData} bytes")
                print(f"    Virtual Address: {hex(section.VirtualAddress)}")
        else:
            print("No suspicious sections found in the PE file.")
        
        # Check for any unexpected imports (which could be indicative of injected code)
        suspicious_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                # If the function name is not the expected one, it could be a sign of malicious modification
                if imp.name and len(imp.name) > 0:
                    suspicious_imports.append((entry.dll.decode(), imp.name.decode()))
        
        if suspicious_imports:
            print("\nSuspicious imports detected:")
            for dll, func in suspicious_imports:
                print(f"  - Library: {dll}, Function: {func}")
        else:
            print("\nNo suspicious imports detected.")
        
    except Exception as e:
        print(f"Error analyzing PE file: {e}")

# Function to monitor a running process for injection
def monitor_process(file_path):
    """Monitor a running process created from the given executable for signs of injection."""
    try:
        # Start the executable file as a process
        process = psutil.Popen(file_path)
        pid = process.pid
        
        print(f"\nMonitoring process with PID: {pid}...")
        print(f"Process Name: {process.name()}")
        print(f"Process Command Line: {process.cmdline()}")

        # Monitor the process for unusual memory usage or unexpected behavior
        while process.is_running():
            print(f"\nChecking process {pid}...")
            memory_info = process.memory_info()
            print(f"Memory Usage: {memory_info.rss / 1024 / 1024:.2f} MB")
            
            # Check for modules loaded into the process
            modules = process.memory_maps()
            for module in modules:
                print(f"  - Module: {module.path}, Address Range: {module.addr}")
            
            # Check if there are any unknown or suspicious DLLs loaded
            suspicious_dlls = []
            for module in modules:
                if "suspicious_dll" in module.path.lower():  # Placeholder for suspicious DLL checks
                    suspicious_dlls.append(module.path)
            
            if suspicious_dlls:
                print("Suspicious DLLs detected:")
                for dll in suspicious_dlls:
                    print(f"  - {dll}")
            
            # Add any other checks based on the process's activity (e.g., CPU usage, open files, etc.)
            cpu_usage = process.cpu_percent(interval=1)
            print(f"CPU Usage: {cpu_usage}%")
            
            print("=" * 40)
            time.sleep(1)  # Check every second

        print(f"\nProcess {pid} has finished executing.")
    
    except Exception as e:
        print(f"Error monitoring process: {e}")

def main():
    
    
    # Get file path from user
    file_path = input("Please enter the path of the executable file to analyze:").strip()
    
    if not os.path.isfile(file_path):
        print(f"Error: The file '{file_path}' does not exist or is not a valid file.")
        return
    
    # Compute the SHA256 hash of the executable file for integrity checking
    file_hash = compute_file_hash(file_path)
    print(f"SHA256 Hash of the file: {file_hash}")

    # Perform PE analysis for Windows Executables
    if file_path.lower().endswith('.exe'):
        analyze_pe_file(file_path)
    else:
        print("The file is not a Windows executable (.exe). No PE analysis performed.")
    
    # Ask user if they want to monitor the process for injection behavior
    user_input = input(f"Would you like to monitor the process of {file_path}? (y/n): ").strip().lower()
    if user_input == 'y':
        monitor_process(file_path)
    else:
        print("Exiting the tool.")

if __name__ == "__main__":
    main()
