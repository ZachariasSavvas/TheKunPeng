# DecryptKeystrokes.ps1 - Script to decrypt an AES-encrypted keystroke log file

# Function to decrypt a file
function Decrypt-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InputPath,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )
    
    try {
        # Same salt as used in encryption for compatibility
        $salt = [System.Text.Encoding]::UTF8.GetBytes("StaticSalt123")
        $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
        $key = $keyDerivation.GetBytes(32)  # 256-bit key
        $iv = $keyDerivation.GetBytes(16)   # 128-bit IV
    
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
    
        $fileBytes = [System.IO.File]::ReadAllBytes($InputPath)
        $decryptor = $aes.CreateDecryptor()
        $memoryStream = [System.IO.MemoryStream]::new($fileBytes)
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $reader = [System.IO.StreamReader]::new($cryptoStream)
    
        [System.IO.File]::WriteAllText($OutputPath, $reader.ReadToEnd())
        
        Write-Host "File decrypted successfully to: $OutputPath"
    }
    catch {
        Write-Host "Decryption failed: $($_.Exception.Message)"
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($cryptoStream) { $cryptoStream.Dispose() }
        if ($memoryStream) { $memoryStream.Dispose() }
        if ($aes) { $aes.Dispose() }
    }
}

# Main script logic
Write-Host "Keystroke Log Decryption Tool"
Write-Host "----------------------------"

# Prompt for the input file path
$inputPath = Read-Host "Enter the path to the encrypted keystroke file (e.g., C:\Path\to\keystrokes_encrypted.txt)"
if (-not (Test-Path $inputPath)) {
    Write-Host "Error: File not found at '$inputPath'. Please check the path and try again."
    exit
}

# Prompt for the password
$password = Read-Host "Enter the password used to encrypt the file"

# Set the output path (same directory as input with '_decrypted' appended)
$outputDir = Split-Path $inputPath -Parent
$outputFileName = [System.IO.Path]::GetFileNameWithoutExtension($inputPath) + "_decrypted.txt"
$outputPath = Join-Path $outputDir $outputFileName

# Perform decryption
Decrypt-File -InputPath $inputPath -OutputPath $outputPath -Password $password

Write-Host "----------------------------"
Write-Host "Decryption process completed. Press Enter to exit."
Read-Host