# FireMon Zone Access Matrix Report Generator

A Python script that generates comprehensive zone-based access matrix reports from FireMon Security Manager, providing visual insights into security rule configurations across firewall zones.

## Overview

This tool connects to FireMon Security Manager via API to analyze security rules and generate zone-to-zone access matrices that show:
- Which zones can communicate with each other
- Number of rules allowing access between zones
- Services/ports permitted between zones
- Applications allowed between zones
- Identification of rules containing public/external IP addresses (non-RFC1918)

## Features

- **Multiple Device Support**: Analyze single devices, multiple devices, device groups, or all devices in a domain
- **Zone Filtering**: Focus on specific zones of interest
- **Subnet Filtering**: Filter rules by source/destination subnets
- **Public IP Detection**: Optionally highlight zone pairs that have rules with non-RFC1918 addresses
- **Multiple Output Formats**: Generate CSV and/or interactive HTML reports
- **Interactive HTML Reports**: Clickable cells with detailed service/application information and direct FireMon links
- **Sticky Headers**: HTML reports feature floating headers for easy navigation of large matrices
- **Non-Interactive Mode**: Support for automation and cron jobs
- **Comprehensive Logging**: Detailed logging for troubleshooting

## Prerequisites

### System Requirements
- Python 3.6 or higher
- FireMon Security Manager access with API credentials
- Network connectivity to FireMon server

### Python Dependencies
The script uses standard library modules plus:
- `requests` (included in FireMon's Python environment)

### FireMon Requirements
- FireMon Security Manager with API access enabled
- User account with appropriate permissions to:
  - Authenticate via API
  - Read device configurations
  - Query security rules
  - Access device groups (if using group features)

## Installation

1. Copy the script to your FireMon server or a system with API access:
```bash
scp zone-services-report.py user@firemon-server:/path/to/script/
```

2. Make the script executable:
```bash
chmod +x zone-services-report.py
```

3. The script automatically detects and adds FireMon Python paths. No additional setup required.

## Usage

### Interactive Mode (Default)
Simply run the script and follow the prompts:
```bash
python3 zone-services-report.py
```

### Non-Interactive Mode (For Automation)

#### Single Device Analysis
```bash
python3 zone-services-report.py \
  --host https://firemon.example.com \
  --username apiuser \
  --password 'password' \
  --device-id 123 \
  --non-interactive
```

#### Multiple Devices
```bash
python3 zone-services-report.py \
  --host https://firemon.example.com \
  --username apiuser \
  --password 'password' \
  --device-ids "123,456,789" \
  --non-interactive
```

#### Device Group Analysis
```bash
python3 zone-services-report.py \
  --host https://firemon.example.com \
  --username apiuser \
  --password 'password' \
  --device-group 10 \
  --non-interactive
```

#### All Devices in Domain
```bash
python3 zone-services-report.py \
  --host https://firemon.example.com \
  --username apiuser \
  --password 'password' \
  --all-devices \
  --non-interactive
```

### Advanced Filtering Examples

#### Filter by Specific Zones
```bash
python3 zone-services-report.py \
  --device-id 123 \
  --zones "Trust,DMZ,Untrust" \
  --non-interactive
```

#### Filter by Subnets
```bash
python3 zone-services-report.py \
  --device-id 123 \
  --src-subnets "10.0.0.0/8,172.16.0.0/12" \
  --dst-subnets "192.168.0.0/16" \
  --non-interactive
```

#### Exclude Same-Zone Traffic
```bash
python3 zone-services-report.py \
  --device-id 123 \
  --exclude-same-zone \
  --non-interactive
```

#### Highlight Public IP Rules
```bash
python3 zone-services-report.py \
  --device-id 123 \
  --show-non-rfc1918 \
  --non-interactive
```

## Command-Line Options

### Connection Options
| Option | Description | Example |
|--------|-------------|---------|
| `--host` | FireMon server URL | `https://firemon.example.com` |
| `--username` | API username | `apiuser` |
| `--password` | API password | `password123` |

### Device Selection Options
| Option | Description | Example |
|--------|-------------|---------|
| `--device-id` | Single device ID | `123` |
| `--device-ids` | Comma-separated device IDs | `"123,456,789"` |
| `--all-devices` | Process all devices in domain | (flag only) |
| `--device-group` | Device group ID | `10` |

### Filtering Options
| Option | Description | Example |
|--------|-------------|---------|
| `--zones` | Comma-separated zone names to include | `"Trust,DMZ,Untrust"` |
| `--src-subnets` | Source subnet filter (CIDR notation) | `"10.0.0.0/8,172.16.0.0/12"` |
| `--dst-subnets` | Destination subnet filter (CIDR notation) | `"192.168.0.0/16"` |
| `--exclude-same-zone` | Exclude same-zone traffic | (flag only) |
| `--show-non-rfc1918` | Highlight zones with public IPs | (flag only) |

### Report Options
| Option | Description | Default |
|--------|-------------|---------|
| `--report-type` | Output format: `csv`, `html`, or `both` | `both` |
| `--output-dir` | Directory for report files | `reports` |
| `--obfuscate-ips` | Obfuscate IPs in logs | `True` |
| `--no-obfuscate-ips` | Disable IP obfuscation | (flag only) |

### Execution Options
| Option | Description |
|--------|-------------|
| `--non-interactive` | Run without prompts (for automation) |

## Output Files

Reports are saved in the specified output directory (default: `reports/`) with timestamps:

### CSV Report Format
- **Filename**: `zone_access_matrix_{device_name}_{timestamp}.csv`
- **Content**: Matrix showing zone-to-zone access with rule counts, services, and applications
- **Example Cell**: `Rules: 5 | Services: tcp/443, tcp/80 | Apps: HTTPS, HTTP`

### HTML Report Format
- **Filename**: `zone_access_matrix_{device_name}_{timestamp}.html`
- **Features**:
  - Interactive clickable cells
  - Detailed modal popups with services/applications
  - Direct links to FireMon rule views
  - Sticky headers for large matrices
  - Color coding for access types:
    - Blue: Cross-zone access
    - Purple: Same-zone access
    - Red: Contains public/external IPs (when `--show-non-rfc1918` is used)
    - Gray: No access
<img width="1918" height="946" alt="image" src="https://github.com/user-attachments/assets/3d51c82c-2130-4bad-a8c5-a0aae66fa21d" />

## Report Interpretation

### Matrix Cells
Each cell in the matrix represents potential communication from a source zone (row) to a destination zone (column):
- **Number**: Count of ACCEPT rules allowing this communication
- **Empty**: No rules permit this communication
- **✕**: Same-zone traffic excluded (when using `--exclude-same-zone`)

### Public IP Detection
When using `--show-non-rfc1918`:
- Red cells indicate zone pairs with rules containing non-RFC1918 (public/external) IP addresses
- Helps identify potential internet-facing rules or connections to external services

### Service/Application Details
Click any cell in the HTML report to view:
- Complete list of allowed services/ports
- Applications permitted
- Direct link to view rules in FireMon
- Separate link for public IP rules only (if applicable)

## Logging

The script creates a detailed log file `zone-services-report.log` in the execution directory containing:
- API calls and responses
- Rule processing details
- Error messages
- Performance metrics

## Troubleshooting

### Common Issues

#### Authentication Failed
- Verify credentials are correct
- Ensure user has API access permissions
- Check if API is enabled on FireMon server

#### No Devices Found
- Verify device IDs are correct
- Check user permissions for device access
- Ensure devices exist in the specified domain

#### Import Errors
- Script automatically detects FireMon Python paths
- If issues persist, manually verify FireMon installation paths
- Check that requests module is available in FireMon environment

#### Large Reports
- For environments with many zones, consider:
  - Using zone filters to focus on specific areas
  - Generating separate reports for different device groups
  - Using subnet filters to reduce rule count

### Performance Considerations

- Large device groups may take several minutes to process
- API rate limits may affect processing speed
- Consider running during off-peak hours for large analyses

## Security Notes

- Credentials are not stored by the script
- Use `--obfuscate-ips` (default) to hide sensitive IP information in logs
- Reports may contain sensitive network topology information - handle accordingly
- Consider using service accounts with read-only permissions

## Example Cron Job

To run daily analysis of critical zones:
```bash
0 2 * * * /usr/bin/python3 /path/to/zone-services-report.py \
  --host https://firemon.example.com \
  --username apiuser \
  --password 'password' \
  --device-group 10 \
  --zones "DMZ,Internet,Internal" \
  --show-non-rfc1918 \
  --output-dir /var/reports/firemon \
  --non-interactive >> /var/log/firemon-report.log 2>&1
```

## License

This script is provided as-is for use with FireMon Security Manager. Ensure compliance with your organization's policies before deployment.

## Support

For issues related to:
- FireMon API: Consult FireMon documentation or support
- Script functionality: Review the log file for detailed error messages
- Network connectivity: Verify firewall rules allow API access

## Version History

- **1.0.0**: Initial release with zone matrix reporting
- **1.1.0**: Added public IP detection and sticky headers
- **1.2.0**: Enhanced filtering options and non-interactive mode
