# ProcessAnalyzer

PowerShell script for detailed process analysis, including network connections, file hashes, and threat intelligence.

## Features
- Analyzes process by ID or name
- Retrieves process details: path, hash, parent process, user, and command line
- Checks file hash with VirusTotal
- Queries AbuseIPDB and GeoIP for remote IPs
- Lists loaded DLLs
- Sends report via Telegram
- Optional HTML report export

## Requirements
- PowerShell 5.1+
- Internet access for API queries
- API keys for VirusTotal, AbuseIPDB
- Telegram bot token and chat ID

## Usage
.\ProcessAnalyzer.ps1 -ProcessId <ID> [-ExportHtml]

.\ProcessAnalyzer.ps1 -ProcessName <Name> [-ExportHtml]

## Setup
1. Clone the repository:
git clone <https://github.com/GL1T0H/ProcessAnalyzer.git>

3. Update API keys and Telegram settings in the script:

- $TelegramBotToken = "YOUR_TELEGRAM_BOT_TOKEN"
- $TelegramChatID = "YOUR_CHAT_ID"
- $AbuseIPDBApiKey = "YOUR_ABUSEIPDB_API_KEY"
- $VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY"

3. Run the script with appropriate parameters.

## Example

```.\ProcessAnalyzer.ps1 -ProcessId 1234 -ExportHtml```

```.\ProcessAnalyzer.ps1 -ProcessName notepad```

## Output
- Telegram message with formatted report
- Optional HTML report saved to $env:TEMP\ProcessReport_<ProcessId>.html
  
## Notes
- Replace placeholder API keys before use.
- Ensure proper error handling for API failures.
