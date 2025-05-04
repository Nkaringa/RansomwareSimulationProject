<#
.SYNOPSIS
    Downloads and executes the decrypt.py script from a remote server to decrypt files.
    It also downloads the decryption key (if not already present) and cleans up the downloaded files.
.DESCRIPTION
    This script first downloads the decrypt.py Python script from the specified URL
    to the temporary directory of the current user. It then checks if the key.txt
    file (containing the decryption key) is already present in the temporary directory.
    If not, it downloads it from the specified key URL. After downloading (or finding)
    the key file, the script changes the current directory to the temporary directory
    and executes the downloaded decrypt.py script using the Python interpreter.
    After the script execution, it changes back to the original directory and removes
    both the downloaded Python script and the key file from the temporary directory.
.PARAMETER url_decrypt
    The URL of the decrypt.py Python script to download.
.PARAMETER key_url
    The URL of the key.txt file containing the decryption key.
.PARAMETER target_dir
    The target directory on the local machine containing the encrypted files.
    Note: This parameter is defined within the script but might be used by the
          remote decrypt.py script.
.EXAMPLE
    .\decrypt_remote.ps1 -url_decrypt "http://192.168.50.232:8080/decrypt.py" -key_url "http://192.168.50.232:8080/key.txt"
#>
# Define the URL for the decrypt.py script
$url_decrypt = "http://192.168.50.232:8080/decrypt.py" 
# Define the URL for the key.txt file (should be the same key used for encryption)
$key_url = "http://192.168.50.232:8080/key.txt"      # The same key should be used for decryption
# Define the local path to save the downloaded decrypt.py script in the temporary directory
$save_path_decrypt = "$env:TEMP\decrypt.py"
# Define the local path where the key.txt file will be (or should be)
$key_path = "$env:TEMP\key.txt"
# Define the target directory containing the encrypted files
$target_dir = "C:\Users\Nagesh Goud Karinga\critical" # The directory containing the encrypted files

# Download the decrypt.py file from the specified URL and save it to the temporary directory
Invoke-WebRequest -Uri $url_decrypt -OutFile $save_path_decrypt

# Download the key.txt file only if it does not already exist in the temporary directory
if (-not (Test-Path $key_path)) {
    Invoke-WebRequest -Uri $key_url -OutFile $key_path
}

# Change the current PowerShell working directory to the temporary directory
cd $env:TEMP

# Execute the downloaded decrypt.py script using the Python interpreter
python $save_path_decrypt

# Change the current PowerShell working directory back to the original directory
cd $PWD

# Remove the downloaded decrypt.py file from the temporary directory
Remove-Item $save_path_decrypt -Force
# Remove the key.txt file from the temporary directory
Remove-Item $key_path -Force