# KunPeng - Telegram-Controlled Backdoor

**KunPeng** is a PowerShell-based, Telegram-controlled backdoor designed for educational purposes to demonstrate remote command-and-control (C2) techniques on Windows systems. It integrates keylogging, screenshot capture, command execution, and file exfiltration into a lightweight script, showcasing how such tools operate in penetration testing scenarios. The interactive keystroke recording feature, with optional AES encryption, highlights operational security (OpSec) concepts for secure data handling.

> **Disclaimer**: This tool is for **educational use only** in controlled, authorized environments (e.g., labs or with explicit permission). Unauthorized use on systems you do not own or have consent to test is illegal and unethical. Use responsibly to learn, not to harm.

---

## Features

### Keystroke Logging
- **Description**: Captures keystrokes for a user-defined duration, logging them with timestamps and active window titles.
- **Interactive Workflow**: Prompts for recording time and encryption choice, offering AES-256 encryption with a user-supplied password.
- **Educational Value**: Learn how keyloggers harvest credentials or monitor activity, and explore encryption for data protection.

### Screenshot Capture
- **Description**: Takes a snapshot of the primary screen and sends it as a PNG via Telegram.
- **Educational Value**: Understand visual reconnaissance techniques to identify user behavior or sensitive on-screen data.

### Command Execution
- **Description**: Executes Windows CMD commands remotely, returning output (split into chunks for large results).
- **Educational Value**: Study remote system enumeration (e.g., `whoami`, `netstat -an`) and payload deployment techniques.

### File Exfiltration
- **Description**: Uploads files (up to 50MB) from the target system to Telegram.
- **Educational Value**: Explore methods for extracting data like logs or documents during security testing.

### Telegram C2
- **Description**: Leverages the Telegram Bot API for command input and data output over HTTPS.
- **Educational Value**: Investigate covert C2 channels that blend with legitimate traffic, bypassing basic network defenses.

### Security Features
- **Password Handling**: Encrypts keystroke logs with a password, avoiding console logging and clearing memory quickly.
- **File Cleanup**: Deletes temporary files (e.g., logs, screenshots) post-transmission.
- **Educational Value**: Learn OpSec practices for secure data transfer and minimizing forensic evidence.

---

## Technical Highlights
- **Language**: PowerShell with embedded C# for keylogging, using Windows APIs (`GetAsyncKeyState`, `GetForegroundWindow`).
- **Encryption**: AES-256 with PBKDF2 key derivation (static salt for simplicity).
- **Persistence**: Loops to poll Telegram commands (no built-in persistence; stops if terminated).
- **Stealth**: Detectable by EDR due to noisy operations (e.g., keylogging), but Telegram traffic may evade basic filters.

---

## Educational Use Case
KunPeng serves as a hands-on learning tool for:
- **Post-Exploitation**: Simulate how attackers maintain access and gather data after initial compromise.
- **Reconnaissance**: Practice capturing keystrokes, screenshots, and system info in a lab environment.
- **Data Protection**: Experiment with encryption to secure sensitive outputs.
- **C2 Concepts**: Understand how modern backdoors use platforms like Telegram for discreet communication.

---

## Setup
1. **Create a Telegram Bot**:
   - Message `@BotFather` on Telegram with `/newbot`, name your bot, and get a token.
   - Replace `$TOKEN` in the script with your bot token.

2. **Interact**:
   - Chat with your bot on Telegram and send commands (e.g., `keystrokes`, `screenshot`).
---

3. **Decrypt Logs** (if encrypted):
   - Use the companion `DecryptKeystrokes.ps1` script with the file path and password.

---

## Commands
- `keystrokes`: Starts an interactive keylogging session (asks for duration and encryption).
- `screenshot`: Captures and sends a screenshot.
- `cmd <command>`: Runs a CMD command (e.g., `cmd whoami`).
- `upload <file_path>`: Uploads a file (e.g., `upload C:\test.txt`).

---

## Detection Risks
- **EDR**: Keylogging and PowerShell activity may trigger alerts (e.g., Microsoft Defender, CrowdStrike).
- **Logs**: Script Block Logging (Event ID 4104) can capture the password unless disabled.
- **Network**: Telegram API calls are visible but encrypted.

---


## Ethical Considerations
This tool is intended for:
- **Security Researchers**: To study backdoor mechanics and defenses.
- **Students**: To learn penetration testing concepts in a safe, legal environment.
- **Pentesters**: To simulate attacks with client consent during authorized engagements.

