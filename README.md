# FireMon Zone Access Matrix Report Generator

Generates zone access matrix reports that identify which services are allowed between firewall zones, with filtering options and email delivery capabilities.

## Features

- **Zone Access Matrix**: Visual matrix showing traffic flow between security zones
- **Service/Application Details**: Shows allowed services and applications for each zone pair
- **Multiple Report Formats**: Generate CSV and/or HTML reports
- **Advanced Filtering**:
  - Filter by specific zones
  - Filter by source/destination subnets
  - Highlight public/external (non-RFC1918) IP rules
  - Hide unused zone combinations (zones with no bidirectional rules)
  - Exclude same-zone traffic
- **Email Delivery**: Automatically email reports using sendmail
- **Device Flexibility**: Generate reports for single devices, multiple devices, device groups, or all devices
- **Interactive & Non-Interactive Modes**: Run manually or automate with cron

## Requirements

- Python 3.6+
- FireMon Security Manager
- Access to FireMon API
- sendmail (for email functionality, standard on FMOS appliances)

## Installation

1. Clone or download the script to your FireMon appliance or workstation
2. Ensure Python 3 is installed: `python3 --version`
3. No additional Python packages required (uses FireMon's built-in libraries)

## Usage

### Interactive Mode

```bash
python3.12 zone-services-report.py
```

Follow the prompts to enter:
- FireMon host URL
- Username and password
- Device selection (single, multiple, group, or all)
- Report type (CSV, HTML, or both)

### Non-Interactive Mode (Command-Line)

```bash
# Basic usage - single device
python3.12 zone-services-report.py \
  --host https://firemon.example.com \
  --username admin \
  --password "your_password" \
  --device-id 124

# Multiple devices
python3.12 zone-services-report.py \
  --host https://firemon.example.com \
  --username admin \
  --password "your_password" \
  --device-ids "124,125,126"

# Device group
python3.12 zone-services-report.py \
  --host https://firemon.example.com \
  --username admin \
  --password "your_password" \
  --device-group 5

# All devices
python3.12 zone-services-report.py \
  --host https://firemon.example.com \
  --username admin \
  --password "your_password" \
  --all-devices
```

## Command-Line Options

### Connection Parameters
- `--host` - FireMon host URL (e.g., https://firemon.example.com)
- `--username` - FireMon username
- `--password` - FireMon password

### Device Selection (choose one)
- `--device-id` - Single device ID
- `--device-ids` - Comma-separated list of device IDs
- `--device-group` - Device group ID
- `--all-devices` - Process all devices

### Filtering Options
- `--zones` - Comma-separated list of zones to include (e.g., "Trust,DMZ,Untrust")
- `--src-subnets` - Filter by source subnets (e.g., "10.0.0.0/8,192.168.0.0/16")
- `--dst-subnets` - Filter by destination subnets
- `--exclude-same-zone` - Exclude same-zone traffic from report
- `--show-non-rfc1918` - Highlight zone combinations with public/external IP rules
- `--show-unused` - Show unused zone combinations (default: hidden)

### Report Options
- `--report-type` - Type of report: `csv`, `html`, or `both` (default: both)
- `--output-dir` - Output directory for reports (default: reports)

### Email Options
- `--email-to` - Email address(es) to send report to (comma-separated)
- `--email-from` - Email sender address (default: firemon-reports@localhost)
- `--email-subject` - Custom email subject (optional)
- `--email-body` - Custom email body text (optional)

### Other Options
- `--debug` - Enable debug output showing filtering details
- `--obfuscate-ips` - Obfuscate IP addresses in logs (default: enabled)
- `--no-obfuscate-ips` - Disable IP obfuscation
- `--non-interactive` - Run in non-interactive mode (for automation)

## Advanced Examples

### Filter by Specific Zones
```bash
python3.12 zone-services-report.py \
  --device-id 124 \
  --zones "Trust,DMZ,Untrust" \
  --host https://firemon.example.com \
  --username admin --password "pass"
```

### Highlight Public IP Rules
```bash
python3.12 zone-services-report.py \
  --device-id 124 \
  --show-non-rfc1918 \
  --host https://firemon.example.com \
  --username admin --password "pass"
```

### Exclude Same-Zone Traffic
```bash
python3.12 zone-services-report.py \
  --device-id 124 \
  --exclude-same-zone \
  --host https://firemon.example.com \
  --username admin --password "pass"
```

### Show Unused Zone Combinations
```bash
python3.12 zone-services-report.py \
  --device-id 124 \
  --show-unused \
  --host https://firemon.example.com \
  --username admin --password "pass"
```

### Email Reports
```bash
# Basic email with auto-generated subject and body
python3.12 zone-services-report.py \
  --device-id 124 \
  --host https://firemon.example.com \
  --username admin --password "pass" \
  --email-to "security-team@example.com"

# Email to multiple recipients with custom subject
python3.12 zone-services-report.py \
  --device-id 124 \
  --host https://firemon.example.com \
  --username admin --password "pass" \
  --email-to "user1@example.com,user2@example.com" \
  --email-from "firemon@company.com" \
  --email-subject "Weekly Zone Access Report"

# Email only HTML report
python3.12 zone-services-report.py \
  --device-id 124 \
  --report-type html \
  --host https://firemon.example.com \
  --username admin --password "pass" \
  --email-to "security-team@example.com"
```

### Debug Mode
```bash
python3.12 zone-services-report.py \
  --device-id 124 \
  --debug \
  --host https://firemon.example.com \
  --username admin --password "pass"
```

## Automation with Cron

Schedule automated reports on a FireMon appliance:

```bash
# Edit crontab
crontab -e

# Run weekly on Monday at 8 AM, email results
0 8 * * MON /usr/bin/python3 /path/to/zone-services-report.py \
  --non-interactive \
  --host https://localhost \
  --username admin \
  --password "your_password" \
  --device-id 124 \
  --email-to "security-team@company.com" \
  --email-from "firemon@company.com" \
  >> /var/log/zone-reports.log 2>&1

# Run daily for all devices, exclude same-zone traffic
0 6 * * * /usr/bin/python3 /path/to/zone-services-report.py \
  --non-interactive \
  --host https://localhost \
  --username admin \
  --password "your_password" \
  --all-devices \
  --exclude-same-zone \
  --email-to "security-team@company.com" \
  >> /var/log/zone-reports.log 2>&1
```

## Output Files

Reports are saved in the `reports/` directory (or custom directory specified with `--output-dir`):

- **CSV Report**: `zone_access_matrix_<device_name>_<timestamp>.csv`
- **HTML Report**: `zone_access_matrix_<device_name>_<timestamp>.html`
- **Log File**: `zone-services-report.log` (in script directory)

## Report Features

### CSV Report
- Matrix format with zones as rows and columns
- Rule counts and service/application details for each zone pair
- Easy to import into spreadsheets for further analysis
- Shows first 5 services and first 3 applications per cell

### HTML Report
- Interactive matrix with clickable cells
- Color-coded cells:
  - **Blue**: Cross-zone access
  - **Purple**: Same-zone access
  - **Red**: Contains public/external IP rules (when `--show-non-rfc1918` is used)
  - **Gray**: No access
- Click any cell to view:
  - Zone path
  - Number of rules
  - Complete list of services/ports
  - Complete list of applications
  - Link to view rules in FireMon UI
- Sticky headers for easy navigation of large matrices
- Direct links to FireMon rule viewer with pre-filtered results

## Understanding the Filtering

### Default Behavior (No `--show-unused`)
By default, the report only shows zones that have **bidirectional connectivity** (zones that both send AND receive traffic). This eliminates:
- Zones that only receive traffic but never send (e.g., "multicast")
- Zones that only send traffic but never receive
- Result: Cleaner matrix with only actively communicating zones

### With `--show-unused`
Shows all zones that appear in any rule, even if they only have traffic in one direction. This may result in:
- Rows with all empty cells (zone sends no traffic)
- Columns with all empty cells (zone receives no traffic)

### Exclude Same-Zone (`--exclude-same-zone`)
Removes same-zone traffic from the report. When combined with default filtering, zones that ONLY have same-zone rules will be completely excluded.

## Troubleshooting

### Email Not Sending
- Verify sendmail is installed: `which sendmail`
- Check sendmail logs: `tail -f /var/log/mail.log` or `/var/log/maillog`
- Verify email addresses are correct
- Check firewall allows SMTP traffic

### Authentication Errors
- Verify credentials are correct
- Ensure user has API access permissions in FireMon
- Check FireMon host URL is correct

### No Rules Fetched
- Verify device ID is correct
- Check device has processed rules in FireMon
- Verify user has permissions to view device rules

### Debug Output
Run with `--debug` flag to see detailed filtering information:
```bash
python3.12 zone-services-report.py --device-id 124 --debug --host https://firemon.example.com --username admin --password "pass"
```

## Example Output

### CSV Report
A matrix showing zone-to-zone access with rule counts and service details:

```
Source \ Destination,Trust,DMZ,Untrust
Trust,"Rules: 50 | Services: tcp/443, tcp/80, tcp/22","Rules: 25 | Services: tcp/443, tcp/3389","Rules: 100 | Services: Any"
DMZ,,"Rules: 10 | Services: tcp/443",
Untrust,,,
```

### HTML Report
An interactive matrix with:
- Color-coded cells showing access types
- Clickable cells revealing detailed rule information
- Direct links to FireMon rule viewer
- Sticky headers for large matrices

## License

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

## Support

For issues or questions, contact your FireMon administrator or open an issue in the repository.
