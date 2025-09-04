# FireMon Zone Access Matrix Report Generator

A Python script that generates comprehensive zone-to-zone access matrix reports from FireMon security rules, providing both CSV and HTML output formats for network security analysis.

## Features

- **Zone Access Matrix**: Creates a clear matrix view showing traffic flow between security zones
- **Dual Output Formats**: 
  - HTML with interactive clickable cells showing service/application details
  - CSV matrix format for easy data analysis
- **Multiple Device Support**: Process single devices, multiple devices, device groups, or all devices in a domain
- **Service & Application Details**: Shows allowed protocols, ports, and applications for each zone pair
- **Direct FireMon Integration**: Links in HTML reports open relevant rules directly in FireMon interface
- **Timestamped Reports**: All reports include timestamps to prevent overwrites
- **Progress Tracking**: Clear visual feedback during processing with emojis and progress indicators

## Requirements

- Python 3.6 or higher
- FireMon Security Manager access
- FireMon Python libraries (automatically detected from `/usr/lib/firemon/devpackfw/lib`)
- `requests` library (included with FireMon)

## Installation

Copy the script to your FireMon server:
```bash
scp zone-services-report.py firemon@your-firemon-server:~/
```

## Usage

Run the script and follow the interactive prompts:

```bash
python3 zone-services-report.py
```

### Interactive Options

1. **FireMon Host**: Enter your FireMon server URL (e.g., `https://firemon.example.com`)
2. **Authentication**: Provide your FireMon username and password
3. **Device Selection**:
   - Option 1: Single Device ID
   - Option 2: Multiple Device IDs (comma-separated)
   - Option 3: All Devices in domain
   - Option 4: Device Group ID
4. **Report Type**:
   - Option 1: CSV only
   - Option 2: HTML only
   - Option 3: Both CSV and HTML

## Output

### File Naming Convention

Reports are saved with timestamps in the `reports/` directory:
- Single device: `access_matrix_DeviceName_YYYYMMDD_HHMMSS.csv`
- Device group: `access_matrix_device_group_ID_YYYYMMDD_HHMMSS.html`
- All devices: `access_matrix_all_devices_YYYYMMDD_HHMMSS.csv`

### CSV Matrix Format

The CSV output provides a matrix view with:
- **First Row**: Header with all destination zones
- **First Column**: Source zones
- **Cell Content**: 
  - `Rules: X | Services: tcp/22, tcp/443 | Apps: SSH, HTTPS` for allowed traffic
  - Empty cell for no access
  - `N/A` for same-zone intersections

Example:
```csv
Source \ Destination,DMZ,Internal,External,Management
DMZ,N/A,Rules: 5 | Services: tcp/443,Rules: 2 | Services: tcp/80,
Internal,Rules: 3 | Services: tcp/22,,N/A,Rules: 1 | Services: tcp/3389
External,Rules: 1 | Services: tcp/443,,,N/A
Management,Rules: 4 | Services: tcp/22, tcp/443,Rules: 2 | Services: tcp/161,,N/A
```

### HTML Matrix Format

The HTML output provides:
- **Interactive Matrix**: Click any cell to view detailed access information
- **Sticky Headers**: Top row and first column remain visible while scrolling
- **Modal Details**: Shows:
  - Zone path (source → destination)
  - Number of rules
  - Allowed services/ports
  - Applications
  - Direct link to view rules in FireMon
- **Color Coding**:
  - Blue cells: Access allowed (with rule count)
  - Gray cells: No access
  - Dark gray with ✕: Same zone (N/A)

## Example Output

```
================================================================
       FIREMON ZONE ACCESS MATRIX REPORT GENERATOR
================================================================
Started at: 2025-09-04 15:35:00

⏳ Authenticating with FireMon...
✅ Authentication successful

📋 Select Device Selection Option:
1. Single Device ID
2. List of Device IDs (comma-separated)
3. All Devices
4. Device Group ID
Enter option (1/2/3/4): 1

Enter the device ID: 2

🔄 Processing 1 device(s)...
----------------------------------------
📍 Device 1/1 - ID: 2
   🔍 Fetching device name for ID 2...
   ✅ Device name: Panorama
   📋 Fetching security rules for device 2...
   ✅ Fetched 5653 security rules
----------------------------------------
✅ Total rules collected: 5653

================================================================
                 GENERATING REPORTS
================================================================
📝 Generating CSV matrix report...
✅ CSV matrix report generated with 155x155 cells and 639 access paths

📊 Generating HTML matrix report...
✅ Generated 155x155 matrix with 639 access paths

================================================================
              REPORT GENERATION COMPLETE!
================================================================

📊 Summary:
   • Devices processed: 1
   • Total rules analyzed: 5653
   • Timestamp: 20250904_153557
   • Reports generated:

   📄 CSV Matrix Report:
      Location: reports/access_matrix_Panorama_20250904_153557.csv
      Size: 45,678 bytes

   🌐 HTML Matrix Report:
      Location: reports/access_matrix_Panorama_20250904_153557.html
      Size: 1,697,526 bytes

   📁 Reports saved in: /home/firemon/reports/

Completed at: 2025-09-04 15:36:12
================================================================
```

## Logging

The script creates a `script.log` file with detailed debug information, including:
- API calls and responses
- Rule processing details
- Error messages
- Performance metrics

## Troubleshooting

### Common Issues

1. **Import Error for requests module**
   - The script automatically searches for FireMon Python libraries
   - Check that FireMon is properly installed

2. **Authentication Failed**
   - Verify your credentials
   - Ensure the FireMon API is accessible
   - Check the URL format (should be `https://hostname` without `/api`)

3. **No Rules Found**
   - Verify the device ID exists
   - Check user permissions for the device
   - Review the `script.log` for detailed error messages

4. **Large Report Generation**
   - For environments with many zones, report generation may take several minutes
   - The script processes rules in batches of 100 for efficiency
   - Progress indicators show current status

### Performance Tips

- For large environments, consider processing device groups instead of all devices
- Use the HTML report for interactive exploration
- Use the CSV report for data analysis in Excel or other tools
- Reports are cached with timestamps, so previous reports are never overwritten

## Security Notes

- IP addresses are obfuscated by default in logs (X.X.X.X)
- Credentials are never logged
- HTTPS certificate verification is disabled for self-signed certificates
- Reports contain security policy information - handle with appropriate care

## Support

For issues or questions:
1. Check the `script.log` file for detailed error information
2. Verify FireMon API accessibility
3. Ensure proper permissions for the authenticated user
4. Contact your FireMon administrator for API access issues

## Version History

- **1.0.0** - Initial release with basic CSV export
- **2.0.0** - Added HTML matrix view with interactive features
- **2.1.0** - Added timestamps and CSV matrix format
- **2.1.1** - Fixed sticky headers and improved UI

## License

This script is provided as-is for use with FireMon Security Manager installations.
