**Ransomware Simulation Project**

**Overview**

This project simulates a ransomware attack on a Windows victim machine from an attacker's Ubuntu machine. The simulation involves infecting the victim machine via a phishing email, encrypting a specific directory, and detecting the attack using a monitoring component.

The project aims to demonstrate the mechanisms of a ransomware attack, including:

Initial infection via a phishing email.
Downloading and executing malicious PowerShell code.
File encryption using AES-256-CBC.
Real-time file system monitoring.
Detection of ransomware activity based on log analysis.
Simulated mitigation actions.

**Environment Setup**

**Operating System**

Attacker Machine: Ubuntu
Victim Machine: Windows 10

**Python Version**
Python 3.9.7

**Installation (Attacker Machine - Ubuntu)**
Install Python: Ensure Python 3.6 or higher is installed.
sudo apt update
sudo apt install python3 python3-pip


**Navigate to the Project Directory:** Open a terminal and navigate to the directory containing the Python scripts.
**Install Required Libraries:** Use pip to install the necessary Python libraries:
pip3 install cryptography watchdog


cryptography: Used for AES encryption, decryption, and key generation.
watchdog: Used for monitoring file system events.

**Installation (Victim Machine - Windows 10)**
No specific Python libraries need to be installed on the victim machine as the attack is carried out by PowerShell. However, ensure that PowerShell is enabled and that its execution policy allows running scripts. The default settings may need to be modified.

**Dependencies**
**Python:** (Used on the attacker machine)
https://www.python.org/
**cryptography:** For AES encryption, decryption, and key derivation (PBKDF2HMAC).
https://cryptography.io/en/latest/
**watchdog:** For monitoring file system events on the victim machine.
https://pypi.org/project/watchdog/
**csv:** Built-in Python module for working with CSV files (for logging).
https://docs.python.org/3/library/csv.html
**datetime:** Built-in Python module for working with dates and times (for timestamps).
https://docs.python.org/3/library/datetime.html
**collections:** Built-in Python module, specifically defaultdict is used.
https://docs.python.org/3/library/collections.html
**os:** Built-in Python module for interacting with the operating system.
https://docs.python.org/3/library/os.html
**base64:** Built-in Python module for Base64 encoding/decoding.
https://docs.python.org/3/library/base64.html

**Project Structure**

The project consists of the following files:
**key_generation.py:** Generates the AES-256 encryption key and saves it to key.txt. (Attacker)
**encrypt.py:** Encrypts files in the target directory (critical) using AES-256-CBC. (Attacker)
**decrypt.py:** Decrypts files in the target directory (critical) that were encrypted by encrypt.py. (Attacker)
**monitor.py:** Monitors file system events in the target directory and logs them to monitor_log.csv. (Victim)
**detect.py:** Analyzes the monitor_log.csv file to detect potential ransomware activity. (Victim)
**mitigation.py:** Simulates mitigation actions in response to detected ransomware activity. (Victim)
**encrypt.ps1:** PowerShell script to download and execute encrypt.py and key.txt on the victim machine. (Attacker)
**decryt.ps1:** PowerShell script to download and execute decrypt.py and key.txt on the victim machine. (Attacker)
**monitor_log.csv:** Log file generated by monitor.py on the victim machine.
**mitigation_log.txt:** Log file generated by mitigation.py on the victim machine.
**key.txt:** File containing the AES-256 encryption key. (Attacker)

**Running the Simulation**
This simulation involves steps on both the attacker (Ubuntu) and victim (Windows 10) machines.

**Attacker Machine (Ubuntu**)
**Set up the Attacker's Web Server:**
Navigate to the directory containing the Python scripts.
Host the encryption scripts and key using Python's built-in web server. You will need to do this in two separate terminals, as you need to host the files in two different directories at different times.

**First Server (for encrypt.py, decrypt.py, key_generation.py, and key.txt):**
python3 -m http.server 8080


**Second Server (for the renamed PowerShell script):**
Create a directory, move the renamed powershell script into it.
Navigate to the directory containing the renamed powershell script.
python3 -m http.server 8081


**Generate the Encryption Key:**
python3 key_generation.py
This will create the key.txt file. Ensure this file is served by the first python server.

**Prepare the Phishing Email (Simulated):**
The attacker creates a phishing email with a link that points to the second Python web server hosting the renamed PowerShell script (e.g., http://attacker_ip:8081/invoice_details.lnk). This step is simulated; you would manually create an email with this link for testing.

**Victim Machine (Windows 10)**
**Disable Windows Security Features (For Testing Purposes ONLY):**
**Disable Windows Firewall:** (Not recommended in a real-world scenario)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

**Disable Windows Defender Real-time Protection: (Not recommended in a real-world scenario)**
Set-MpPreference -DisableRealtimeMonitoring $true

**Set PowerShell Execution Policy: (May be required to run the downloaded script)**
Set-ExecutionPolicy Unrestricted -Scope CurrentUser


**Warning:** Setting the execution policy to Unrestricted can lower your system's security. Use with caution and only in a controlled testing environment. It is crucial to revert these changes after testing.

**Simulate Receiving and Opening the Phishing Email:**
The victim receives the simulated phishing email and clicks the link.
The victim downloads the renamed PowerShell script (e.g., invoice_details.lnk).

**Run the Encryption Script (Simulated - Triggered by the downloaded file):**
The victim double-clicks the downloaded PowerShell script. This triggers the encrypt.ps1 script to execute. This script downloads and runs the encrypt.py script from the attacker's server.
A PowerShell window may briefly appear and disappear.

**Start File System Monitoring:**
Open a PowerShell command prompt as an administrator.
Run the monitor.py script:
python monitor.py


(Note: You will need to copy the monitor.py script to the victim machine and have Python installed. For a true simulation of the attack from the Attacker machine, you would need to find a way to execute this remotely, which is outside the scope of this project.)
This will start monitoring the C:\Users\Nagesh Goud Karinga\critical directory.

**Observe Encryption:**
The files in C:\Users\Nagesh Goud Karinga\critical will be encrypted.
The monitor.py script will log the file changes in the PowerShell window and in monitor_log.csv.

**Detect the Attack:**
Open another PowerShell command prompt as an administrator.
Run the detect.py script:
python detect.py


(Note: You will need to copy the detect.py script to the victim machine and have Python installed. For a true simulation of the attack from the Attacker machine, you would need to find a way to execute this remotely, which is outside the scope of this project.)
The detect.py script will analyze the monitor_log.csv file and display any detected ransomware activity.

**(Optional) Simulate Decryption:**
To simulate decryption (after the hypothetical ransom payment), the attacker would provide the decrypt_remote.ps1 script to the victim.
The victim would run the decrypt.ps1 script, which downloads and executes decrypt.py.
powershell.exe -ExecutionPolicy Unrestricted -File decrypt.ps1
(Note: The execution policy may need to be adjusted as described in step 1.)

**(Optional) Simulate Mitigation:**
Run the mitigation.py script:
python mitigation.py
(Note: You will need to copy the mitigation.py script to the victim machine and have Python installed. For a true simulation of the attack from the Attacker machine, you would need to find a way to execute this remotely, which is outside the scope of this project.)
The script will analyze the monitor_log.csv and log simulated mitigation actions to mitigation_log.txt.

**Limitations**
**Email Delivery**: Gmail and other email providers block the sending of potentially harmful executable files. This simulation bypasses this by hosting the PowerShell script on a web server and providing a download link. A more realistic attack might involve a more sophisticated delivery method.

**Windows Security**: Windows Firewall and Windows Defender may block the download or execution of the malicious PowerShell script. For this simulation, these features were manually disabled. A real-world attack would attempt to bypass these security measures.

**Process Termination:** The mitigation.py script simulates process termination but does not implement the actual process termination. The script lacks the ability to obtain the process ID of the ransomware process. Further research is needed to implement this functionality.

**Remote Execution:** For simplicity, the monitor.py, detect.py, and mitigation.py scripts are intended to be run directly on the victim machine. A real-world attack scenario would involve the attacker executing these scripts remotely.

**Notes and Considerations**
This simulation is for educational purposes only. Do not use it to perform actual attacks.
Ensure that you have the necessary permissions to create and modify files in the directories used in this simulation.

Re-enable Windows security features (Firewall, Defender) and restore the original PowerShell execution policy after completing the simulation.

The critical directory should be created in the specified location before running the simulation.

The IP addresses used in the PowerShell scripts (192.168.50.232) are for demonstration purposes. You will need to replace them with the actual IP address of your attacker machine.
The invoice_details.lnk file is a placeholder. In a real attack, this would be a convincingly named file to trick the user.


