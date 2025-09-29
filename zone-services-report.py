# zone-services-report.py
import sys
import csv
import getpass
import warnings
import os
import logging
import argparse
import re
import glob
import urllib.parse
from collections import defaultdict
from pathlib import Path
from datetime import datetime
import json
import ipaddress

# Set up logging configuration near the top
logging.basicConfig(
    filename='zone-services-report.log',
    filemode='w',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Dynamic Python path detection for FireMon packages
def add_firemon_paths():
    """Dynamically add FireMon package paths based on available Python versions."""
    base_path = '/usr/lib/firemon/devpackfw/lib'
    
    # First, try to find any python3.* directories
    if os.path.exists(base_path):
        python_dirs = glob.glob(os.path.join(base_path, 'python3.*'))
        python_dirs.sort(reverse=True)  # Sort in descending order to try newest first
        
        for python_dir in python_dirs:
            site_packages = os.path.join(python_dir, 'site-packages')
            if os.path.exists(site_packages):
                sys.path.append(site_packages)
                logging.info(f"Added Python path: {site_packages}")
    
    # Also try common Python version patterns
    for minor_version in range(20, 5, -1):  # Try from 3.20 down to 3.6
        path = f'/usr/lib/firemon/devpackfw/lib/python3.{minor_version}/site-packages'
        if os.path.exists(path) and path not in sys.path:
            sys.path.append(path)
            logging.info(f"Added Python path: {path}")

# Add FireMon paths dynamically
add_firemon_paths()

try:
    import requests
except ImportError:
    logging.error("Failed to import requests module after adding all possible paths")
    print("Error: Could not import requests module. Please check FireMon installation.")
    sys.exit(1)

# Suppress warnings for unverified HTTPS requests
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Global cache for service names to avoid redundant API calls
service_name_cache = {}

# Regular expression for matching IP addresses with optional CIDR notation within strings
ip_address_pattern = re.compile(
    r'(?:^|[^0-9])'
    r'('
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?:/\d{1,2})?'
    r')'
    r'(?:$|[^0-9])'
)

# Function to obfuscate IP addresses in data structures
def obfuscate_ip_addresses(data):
    if isinstance(data, dict):
        return {key: obfuscate_ip_addresses(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [obfuscate_ip_addresses(element) for element in data]
    elif isinstance(data, str):
        return ip_address_pattern.sub(lambda m: m.group(0).replace(m.group(1), 'X.X.X.X'), data)
    else:
        return data

# Function to authenticate and get the token
def authenticate(api_url, username, password):
    login_url = f"{api_url}/authentication/login"
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username, 'password': password}
    print("\n⏳ Authenticating with FireMon...")
    try:
        response = requests.post(login_url, json=payload, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error("Error during authentication request: %s", e)
        print(f"❌ Authentication failed: {e}")
        sys.exit(1)
        
    if response.status_code == 200:
        try:
            token = response.json()['token']
            logging.debug("Authentication token received.")
            print("✅ Authentication successful")
            return token
        except KeyError:
            logging.error("Authentication succeeded but token not found in response.")
            print("❌ Authentication error: Token not found in response")
            sys.exit(1)
    else:
        logging.error("Authentication failed: %s %s", response.status_code, response.text)
        print(f"❌ Authentication failed: HTTP {response.status_code}")
        sys.exit(1)

# Function to extract IP addresses from address objects
def extract_addresses_from_objects(address_objects):
    """Extract IP addresses from FireMon address objects."""
    addresses = []
    for obj in address_objects:
        if 'addresses' in obj:
            for addr_info in obj['addresses']:
                if 'address' in addr_info:
                    addresses.append(addr_info['address'])
                elif 'ip' in addr_info:
                    addresses.append(addr_info['ip'])
                elif 'ipRange' in addr_info:
                    addresses.append(addr_info['ipRange'])
    return addresses

# Function to check if address is RFC1918 private
def is_rfc1918(addr_str):
    """Check if address is in RFC1918 private ranges."""
    try:
        if addr_str == 'Any':
            return False  # Any includes both private and public
        
        # RFC1918 ranges
        rfc1918_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]
        
        # Handle IP ranges (e.g., "10.0.0.0-10.255.255.255")
        if '-' in addr_str:
            start_ip, end_ip = addr_str.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            # Check if both start and end are within RFC1918 ranges
            start_is_private = any(start in private_range for private_range in rfc1918_ranges)
            end_is_private = any(end in private_range for private_range in rfc1918_ranges)
            
            # Only consider it RFC1918 if the entire range is private
            return start_is_private and end_is_private
        
        # Parse CIDR notation or single IP
        if '/' in addr_str:
            network = ipaddress.ip_network(addr_str, strict=False)
        else:
            network = ipaddress.ip_network(f"{addr_str}/32", strict=False)
        
        # Check if it's IPv4
        if not isinstance(network, ipaddress.IPv4Network):
            return False
        
        # Check if network is entirely within any RFC1918 range
        for private_range in rfc1918_ranges:
            if network.subnet_of(private_range):
                return True
        
        return False
    except (ipaddress.AddressValueError, ValueError):
        return False  # If can't parse, assume not RFC1918

# Function to check if any address matches subnet filters
def addresses_match_subnet(addresses, subnet_filters):
    """Check if any address matches the subnet filters."""
    if not subnet_filters or not addresses:
        return True  # No filter means match all
    
    for addr_str in addresses:
        try:
            # Parse the address (could be CIDR or single IP)
            if '/' in addr_str:
                addr_net = ipaddress.ip_network(addr_str, strict=False)
            else:
                addr_net = ipaddress.ip_network(f"{addr_str}/32", strict=False)
            
            # Check against each filter
            for filter_str in subnet_filters:
                try:
                    if '/' in filter_str:
                        filter_net = ipaddress.ip_network(filter_str, strict=False)
                    else:
                        filter_net = ipaddress.ip_network(f"{filter_str}/32", strict=False)
                    
                    # Check if networks overlap
                    if addr_net.overlaps(filter_net):
                        return True
                except (ipaddress.AddressValueError, ValueError):
                    # Simple string matching as fallback
                    if filter_str in addr_str or addr_str in filter_str:
                        return True
        except (ipaddress.AddressValueError, ValueError):
            # Fallback to string matching
            for filter_str in subnet_filters:
                if filter_str in addr_str or addr_str in filter_str:
                    return True
    
    return False

# Function to check if rule matches subnet filters
def rule_matches_subnet_filters(rule, src_subnets=None, dst_subnets=None):
    """Check if rule matches the specified subnet filters."""
    if not src_subnets and not dst_subnets:
        return True
    
    # Extract source addresses from the sources array
    src_addresses = extract_addresses_from_objects(rule.get('sources', []))
    
    # Extract destination addresses from the destinations array  
    dst_addresses = extract_addresses_from_objects(rule.get('destinations', []))
    
    # Check source subnet filter
    if src_subnets:
        if not src_addresses or src_addresses == ['Any']:
            # If no specific addresses or "Any", pass the filter
            pass
        elif not addresses_match_subnet(src_addresses, src_subnets):
            return False
    
    # Check destination subnet filter
    if dst_subnets:
        if not dst_addresses or dst_addresses == ['Any']:
            # If no specific addresses or "Any", pass the filter
            pass
        elif not addresses_match_subnet(dst_addresses, dst_subnets):
            return False
    
    return True

# Function to get security rules from a device with filtering
def get_security_rules(api_url, token, device_id, zone_filter=None, src_subnets=None, dst_subnets=None):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"device {{ id = {device_id} }}"
    all_rules = []
    page = 0
    page_size = 100
    
    print(f"   📋 Fetching security rules for device {device_id}...")
    
    while True:
        url = f"{api_url}/siql/secrule/paged-search?q={query}&page={page}&pageSize={page_size}"
        try:
            response = requests.get(url, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching security rules for device ID {device_id} on page {page}: %s", e)
            print(f"   ❌ Error fetching rules: {e}")
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                rules = data.get('results', [])
                if not rules:
                    break
                
                # Apply zone and subnet filters
                filtered_rules = []
                for rule in rules:
                    # Check zone filter
                    if zone_filter:
                        src_context = rule.get('srcContext') or rule.get('source', {}) or {}
                        dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
                        src_zones = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
                        dst_zones = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
                        
                        if not src_zones:
                            src_zones = ['Any']
                        if not dst_zones:
                            dst_zones = ['Any']
                        
                        # Check if any of the rule's zones match the filter
                        zone_match = False
                        for zone in src_zones + dst_zones:
                            if zone in zone_filter:
                                zone_match = True
                                break
                        
                        if not zone_match:
                            continue
                    
                    # Check subnet filter
                    if not rule_matches_subnet_filters(rule, src_subnets, dst_subnets):
                        continue
                    
                    filtered_rules.append(rule)
                
                all_rules.extend(filtered_rules)
                logging.debug(f"Fetched {len(rules)} rules, {len(filtered_rules)} after filtering for device ID {device_id} on page {page}")
                
                if len(rules) < page_size:
                    break
                page += 1
            except KeyError:
                logging.error(f"Security rules fetched for device ID {device_id} but 'results' key not found in response.")
                sys.exit(1)
        else:
            logging.error(f"Failed to fetch security rules for device ID {device_id} on page {page}: %s %s", response.status_code, response.text)
            print(f"   ❌ Failed to fetch rules (HTTP {response.status_code})")
            sys.exit(1)
    
    logging.info(f"Total security rules fetched for device ID {device_id}: {len(all_rules)}")
    print(f"   ✅ Fetched {len(all_rules)} security rules (after filtering)")
    return all_rules

# Function to get device name by device ID
def get_device_name(api_url, token, device_id):
    print(f"   🔍 Fetching device name for ID {device_id}...")
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    url = f"{api_url}/domain/1/device/{device_id}"
    logging.debug(f"API URL: {url}")
    
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"   ⚠️  WARNING: Could not fetch device name: {e}")
        logging.error(f"Error fetching device name for device ID {device_id}: %s", e)
        return f"device_{device_id}"
    
    if response.status_code == 200:
        try:
            data = response.json()
            device_name = data.get('name', f"device_{device_id}")
            device_name = "".join(c for c in device_name if c.isalnum() or c in (' ', '_', '-')).rstrip()
            logging.debug(f"Device ID {device_id} has name '{device_name}'")
            print(f"   ✅ Device name: {device_name}")
            return device_name
        except KeyError:
            print(f"   ⚠️  WARNING: Device name not found in response")
            logging.error(f"Device name not found in response for device ID {device_id}. Using device ID as name.")
            return f"device_{device_id}"
    else:
        print(f"   ⚠️  WARNING: Could not fetch device name (HTTP {response.status_code})")
        logging.error(f"Failed to fetch device name for device ID {device_id}: %s %s", response.status_code, response.text[:200])
        return f"device_{device_id}"

# Function to get all devices in the domain
def get_all_devices(api_url, token):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    url = f"{api_url}/domain/1/device"
    all_devices = []
    page = 0
    page_size = 100
    
    print(f"\n📊 Fetching all devices from domain...")
    
    while True:
        paged_url = f"{url}?page={page}&pageSize={page_size}"
        try:
            response = requests.get(paged_url, headers=headers, verify=False, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to fetch devices on page {page}: {e}")
            logging.error(f"Error fetching devices on page {page}: %s", e)
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                print(f"   📋 Fetched {len(devices)} devices from page {page}")
                logging.debug(f"Fetched {len(devices)} devices on page {page}")
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                print(f"❌ Invalid response structure - 'results' key not found")
                logging.error("Failed to parse devices from response. 'results' key not found.")
                sys.exit(1)
        else:
            print(f"❌ Failed to fetch devices (HTTP {response.status_code})")
            logging.error(f"Failed to fetch devices on page {page}: %s %s", response.status_code, response.text[:200])
            sys.exit(1)
    
    print(f"✅ Total devices fetched: {len(all_devices)}")
    logging.info(f"Total devices fetched: {len(all_devices)}")
    return all_devices

# Function to get devices by device group ID
def get_devices_by_group(api_url, token, group_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"devicegroup{{id={group_id}}}"
    encoded_query = requests.utils.quote(query)
    url = f"{api_url}/siql/device/paged-search?q={encoded_query}&page=0&pageSize=100&sort=name"
    all_devices = []
    page = 0
    page_size = 100
    
    print(f"\n📊 Fetching devices from group {group_id}...")
    
    while True:
        paged_url = f"{api_url}/siql/device/paged-search?q={encoded_query}&page={page}&pageSize={page_size}&sort=name"
        try:
            response = requests.get(paged_url, headers=headers, verify=False, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to fetch devices in group {group_id} on page {page}: {e}")
            logging.error(f"Error fetching devices in group ID {group_id} on page {page}: %s", e)
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                print(f"   📋 Fetched {len(devices)} devices from page {page}")
                logging.debug(f"Fetched {len(devices)} devices in group ID {group_id} on page {page}")
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                print(f"❌ Invalid response structure - 'results' key not found")
                logging.error(f"Failed to parse devices from response for group ID {group_id}. 'results' key not found.")
                sys.exit(1)
        else:
            print(f"❌ Failed to fetch devices (HTTP {response.status_code})")
            logging.error(f"Failed to fetch devices in group ID {group_id} on page {page}: %s %s", response.status_code, response.text[:200])
            sys.exit(1)
    
    print(f"✅ Total devices fetched in group {group_id}: {len(all_devices)}")
    logging.info(f"Total devices fetched in group {group_id}: {len(all_devices)}")
    return all_devices

# Process security rules to extract matrix data
def process_rules_for_matrix(rules, show_non_rfc1918=False):
    """Process rules and extract zone access information."""
    
    # Store detailed access information for each zone pair
    access_details = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'services': set(), 'applications': set(), 'has_non_rfc1918': False}))

    for index, rule in enumerate(rules):
        # Only process ACCEPT rules
        rule_action = rule.get('ruleAction') or rule.get('action') or 'Unknown'
        if rule_action != 'ACCEPT':
            continue

        # Extract zones
        src_context = rule.get('srcContext') or rule.get('source', {}) or {}
        dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
        src_zones = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
        dst_zones = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
        
        if not src_zones:
            src_zones = ['Any']
        if not dst_zones:
            dst_zones = ['Any']

        # Extract applications
        apps = rule.get('apps', [])
        app_names = []
        for app in apps:
            app_name = app.get('name', 'Unknown')
            if app_name != 'Any':
                app_names.append(app_name)

        # Extract services
        services_list = []
        services = rule.get('services') or rule.get('serviceList') or []
        
        for service in services:
            service_entries = service.get('services', []) or service.get('serviceEntries', [])
            if not service_entries:
                services_list.append(service.get('name', 'Any'))
            else:
                for srv in service_entries:
                    protocol = srv.get('type', 'Unknown').lower()
                    start_port = srv.get('startPort', '')
                    end_port = srv.get('endPort', '')
                    
                    if start_port and end_port:
                        if start_port == end_port:
                            services_list.append(f"{protocol}/{start_port}")
                        else:
                            services_list.append(f"{protocol}/{start_port}-{end_port}")
                    elif start_port:
                        services_list.append(f"{protocol}/{start_port}")
                    else:
                        services_list.append(f"{protocol}/Any")

        # Check if rule contains non-RFC1918 addresses
        has_non_rfc1918 = False
        if show_non_rfc1918:
            # Check source addresses
            src_addresses = extract_addresses_from_objects(rule.get('sources', []))
            dst_addresses = extract_addresses_from_objects(rule.get('destinations', []))
            
            # Check if any address is non-RFC1918
            for addr in src_addresses + dst_addresses:
                if addr != 'Any' and not is_rfc1918(addr):
                    has_non_rfc1918 = True
                    break
        
        # Update zone access details
        for src_zone in src_zones:
            for dst_zone in dst_zones:
                access_details[src_zone][dst_zone]['count'] += 1
                if services_list:
                    access_details[src_zone][dst_zone]['services'].update(services_list)
                if app_names:
                    access_details[src_zone][dst_zone]['applications'].update(app_names)
                if has_non_rfc1918:
                    access_details[src_zone][dst_zone]['has_non_rfc1918'] = True
    
    return access_details

# Process security rules to extract relevant data for CSV matrix format
def process_rules_to_csv_matrix(api_url, token, rules, output_file, obfuscate_ips=True, 
                                exclude_same_zone=False, show_non_rfc1918=False):
    print(f"\n📝 Generating CSV matrix report...")
    
    # Process rules to get access details
    access_details = process_rules_for_matrix(rules, show_non_rfc1918)
    
    # Get sorted list of all zones
    all_zones = set()
    for src in access_details:
        all_zones.add(src)
        for dst in access_details[src]:
            all_zones.add(dst)
    zones = sorted(all_zones)

    # Write CSV in matrix format with timestamp
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        # Write generation timestamp
        writer.writerow([f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
        if show_non_rfc1918:
            writer.writerow(["Note: [PUBLIC] indicates rules with public/external IP addresses"])
        writer.writerow([])  # Empty row for spacing
        
        # Write header row
        header = ['Source \\ Destination'] + zones
        writer.writerow(header)
        
        # Write each source zone row
        for src_zone in zones:
            row = [src_zone]
            for dst_zone in zones:
                # Check if same zone and should exclude
                if exclude_same_zone and src_zone == dst_zone:
                    row.append('N/A')
                else:
                    access_info = access_details.get(src_zone, {}).get(dst_zone, {})
                    count = access_info.get('count', 0)
                    
                    if count > 0:
                        services = sorted(list(access_info.get('services', [])))
                        apps = sorted(list(access_info.get('applications', [])))
                        has_non_rfc1918 = access_info.get('has_non_rfc1918', False)
                        
                        # Format cell content
                        cell_content = f"Rules: {count}"
                        if has_non_rfc1918 and show_non_rfc1918:
                            cell_content += " [PUBLIC]"
                        if services:
                            services_str = ', '.join(services[:5])  # Show first 5 services
                            if len(services) > 5:
                                services_str += f' (+{len(services)-5} more)'
                            cell_content += f" | Services: {services_str}"
                        if apps:
                            apps_str = ', '.join(apps[:3])  # Show first 3 apps
                            if len(apps) > 3:
                                apps_str += f' (+{len(apps)-3} more)'
                            cell_content += f" | Apps: {apps_str}"
                        row.append(cell_content)
                    else:
                        row.append('')  # Empty cell for no access
            
            writer.writerow(row)
    
    access_paths_count = sum(1 for src in access_details for dst in access_details[src] if access_details[src][dst]['count'] > 0)
    print(f"✅ CSV zone matrix report generated with {len(zones)}x{len(zones)} cells and {access_paths_count} access paths")

# Generate a clean access matrix HTML report with service/application details
def generate_html_matrix(rules, output_html, device_name, api_url, token, context_type='device', 
                        context_id=None, obfuscate_ips=True, exclude_same_zone=False,
                        show_non_rfc1918=False):
    """
    Generate HTML matrix report with page-level scrolling and sticky headers.
    """
    print(f"\n📊 Generating HTML matrix report...")
    
    # Extract base URL from api_url (remove /api part)
    base_url = api_url.replace('/securitymanager/api', '').replace('/api', '')
    
    # Process rules to get access details
    access_details = process_rules_for_matrix(rules, show_non_rfc1918)
    
    # Get sorted list of all zones
    all_zones = set()
    for src in access_details:
        all_zones.add(src)
        for dst in access_details[src]:
            all_zones.add(dst)
    zones = sorted(all_zones)

    # Generate HTML with modal for details and improved scrolling
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zone Access Matrix - {device_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            color: #333;
            /* Allow body to scroll naturally */
            overflow: auto;
        }}
        
        .header-info {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
            /* Keep header info fixed width */
            max-width: 100%;
        }}
        
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        
        .subtitle {{
            color: #7f8c8d;
            margin-bottom: 10px;
            font-size: 14px;
        }}
        
        .timestamp {{
            color: #95a5a6;
            margin-bottom: 10px;
            font-size: 12px;
            font-style: italic;
        }}
        
        .note {{
            color: #e74c3c;
            margin-bottom: 20px;
            font-size: 13px;
            padding: 8px;
            background: #fee;
            border-radius: 4px;
        }}
        
        .table-container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            /* Remove max-width to allow full page width */
            margin-bottom: 20px;
        }}
        
        table {{
            border-collapse: collapse;
            width: 100%;
            min-width: 600px;
            position: relative;
        }}
        
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: center;
            position: relative;
            font-size: 12px;
        }}
        
        /* Sticky header row */
        thead th {{
            background: #34495e;
            color: white;
            font-weight: 600;
            white-space: nowrap;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        /* Sticky first column header */
        thead th:first-child {{
            position: sticky;
            left: 0;
            z-index: 101;
            background: #2c3e50;
            text-align: left;
        }}
        
        /* Sticky first column cells */
        tbody td:first-child {{
            position: sticky;
            left: 0;
            background: #ecf0f1;
            font-weight: 600;
            text-align: left;
            font-size: 11px;
            z-index: 50;
            white-space: nowrap;
            border-right: 2px solid #bdc3c7;
        }}
        
        /* Add shadow to sticky elements when scrolling */
        thead th::after {{
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(to bottom, rgba(0,0,0,0.1), transparent);
        }}
        
        tbody td:first-child::after {{
            content: '';
            position: absolute;
            right: -1px;
            top: 0;
            bottom: 0;
            width: 1px;
            background: linear-gradient(to right, rgba(0,0,0,0.1), transparent);
        }}
        
        .non-rfc1918 {{
            background: #ffecdb !important;
            font-weight: bold;
        }}
        
        .access-cell {{
            background: #3498db;
            color: white;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        
        .access-cell:hover {{
            background: #2980b9;
        }}
        
        .same-zone-access {{
            background: #9b59b6;
            color: white;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        
        .same-zone-access:hover {{
            background: #8e44ad;
        }}
        
        .public-access {{
            background: #e74c3c;
            color: white;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: background-color 0.2s;
        }}
        
        .public-access:hover {{
            background: #c0392b;
        }}
        
        .no-access {{
            background: #95a5a6;
            color: #ecf0f1;
        }}
        
        .self-zone-na {{
            background: #7f8c8d;
            color: #bdc3c7;
            font-size: 18px;
            font-weight: bold;
        }}
        
        .legend {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-top: 20px;
        }}
        
        .legend-title {{
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        .legend-items {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .legend-box {{
            width: 24px;
            height: 24px;
            border: 1px solid #ddd;
        }}
        
        .legend-box.access {{
            background: #3498db;
        }}
        
        .legend-box.same-zone {{
            background: #9b59b6;
        }}
        
        .legend-box.public {{
            background: #e74c3c;
        }}
        
        .legend-box.no-access {{
            background: #95a5a6;
        }}
        
        .legend-box.self {{
            background: #7f8c8d;
            color: #bdc3c7;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }}
        
        /* Modal styles */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }}
        
        .modal-content {{
            background-color: #fefefe;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #888;
            border-radius: 8px;
            width: 80%;
            max-width: 600px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }}
        
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}
        
        .close:hover,
        .close:focus {{
            color: #000;
        }}
        
        .modal-title {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #2c3e50;
        }}
        
        .details-section {{
            margin-bottom: 15px;
        }}
        
        .details-label {{
            font-weight: 600;
            color: #34495e;
            margin-bottom: 5px;
        }}
        
        .details-list {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            max-height: 200px;
            overflow-y: auto;
        }}
        
        .details-item {{
            padding: 3px 0;
            color: #555;
        }}
        
        .view-rules-btn {{
            display: inline-block;
            margin-top: 10px;
            padding: 8px 16px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
        }}
        
        .view-rules-btn:hover {{
            background: #2980b9;
        }}
        
        /* Ensure smooth scrolling */
        html {{
            scroll-behavior: smooth;
        }}
        
        /* Add minimum height to ensure scrollbars appear when needed */
        body {{
            min-height: 100vh;
        }}
    </style>
</head>
<body>
    <div class="header-info">
        <h1>Zone Access Matrix</h1>
        <div class="subtitle">Device: {device_name} | Click on any cell to view details</div>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
    
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Source \\ Destination</th>
    """
    
    # Add column headers for destination zones
    for zone in zones:
        html_content += f'                    <th>{zone}</th>\n'
    
    html_content += """                </tr>
            </thead>
            <tbody>
    """
    
    # Add rows for each source zone
    for src_zone in zones:
        html_content += f'                <tr>\n'
        html_content += f'                    <td>{src_zone}</td>\n'
        
        for dst_zone in zones:
            access_info = access_details.get(src_zone, {}).get(dst_zone, {})
            count = access_info.get('count', 0)
            
            if exclude_same_zone and src_zone == dst_zone:
                # Same zone - mark as N/A if excluding
                html_content += '                    <td class="self-zone-na">✕</td>\n'
            elif count > 0:
                services_json = sorted(list(access_info.get('services', [])))
                apps_json = sorted(list(access_info.get('applications', [])))
                has_non_rfc1918 = access_info.get('has_non_rfc1918', False)
                
                # Generate FireMon URL based on context - FIX for "Any" zone
                if context_type == 'device' and context_id:
                    # Handle "Any" zone properly
                    src_condition = f"source.zone = '{src_zone}'" if src_zone != 'Any' else "source.zone.any = true"
                    dst_condition = f"destination.zone = '{dst_zone}'" if dst_zone != 'Any' else "destination.zone.any = true"
                    
                    siql = f"device {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND ({dst_condition}) AND ({src_condition}) }}"
                    url = f"{base_url}/securitymanager/#/domain/1/device/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(siql)}"
                    
                    # Generate NON-RFC1918 specific URL
                    non_rfc_condition = "((source is disjoint from '10.0.0.0/8') AND (source is disjoint from '172.16.0.0/12') AND (source is disjoint from '192.168.0.0/16')) OR ((destination is disjoint from '10.0.0.0/8') AND (destination is disjoint from '172.16.0.0/12') AND (destination is disjoint from '192.168.0.0/16'))"
                    non_rfc_siql = f"device {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND ({dst_condition}) AND ({src_condition}) AND ({non_rfc_condition}) }}"
                    non_rfc_url = f"{base_url}/securitymanager/#/domain/1/device/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(non_rfc_siql)}"
                    
                elif context_type == 'devicegroup' and context_id:
                    src_condition = f"source.zone = '{src_zone}'" if src_zone != 'Any' else "source.zone.any = true"
                    dst_condition = f"destination.zone = '{dst_zone}'" if dst_zone != 'Any' else "destination.zone.any = true"
                    
                    siql = f"devicegroup {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND ({dst_condition}) AND ({src_condition}) }}"
                    url = f"{base_url}/securitymanager/#/domain/1/devicegroup/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(siql)}"
                    
                    # Generate NON-RFC1918 specific URL
                    non_rfc_condition = "((source is disjoint from '10.0.0.0/8') AND (source is disjoint from '172.16.0.0/12') AND (source is disjoint from '192.168.0.0/16')) OR ((destination is disjoint from '10.0.0.0/8') AND (destination is disjoint from '172.16.0.0/12') AND (destination is disjoint from '192.168.0.0/16'))"
                    non_rfc_siql = f"devicegroup {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND ({dst_condition}) AND ({src_condition}) AND ({non_rfc_condition}) }}"
                    non_rfc_url = f"{base_url}/securitymanager/#/domain/1/devicegroup/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(non_rfc_siql)}"
                    
                else:  # all devices
                    src_condition = f"source.zone = '{src_zone}'" if src_zone != 'Any' else "source.zone.any = true"
                    dst_condition = f"destination.zone = '{dst_zone}'" if dst_zone != 'Any' else "destination.zone.any = true"
                    
                    siql = f"domain {{ id = 1 }} AND rule {{ action = 'ACCEPT' AND ({src_condition}) AND ({dst_condition}) }}"
                    url = f"{base_url}/securitymanager/#/domain/1/listrules?page=1&count=20&advancedMode=0&siql={urllib.parse.quote(siql)}"
                    
                    # Generate NON-RFC1918 specific URL
                    non_rfc_condition = "((source is disjoint from '10.0.0.0/8') AND (source is disjoint from '172.16.0.0/12') AND (source is disjoint from '192.168.0.0/16')) OR ((destination is disjoint from '10.0.0.0/8') AND (destination is disjoint from '172.16.0.0/12') AND (destination is disjoint from '192.168.0.0/16'))"
                    non_rfc_siql = f"domain {{ id = 1 }} AND rule {{ action = 'ACCEPT' AND ({src_condition}) AND ({dst_condition}) AND ({non_rfc_condition}) }}"
                    non_rfc_url = f"{base_url}/securitymanager/#/domain/1/listrules?page=1&count=20&advancedMode=0&siql={urllib.parse.quote(non_rfc_siql)}"
                
                # Escape quotes for JavaScript
                services_str = str(services_json).replace("'", "\\'")
                apps_str = str(apps_json).replace("'", "\\'")
                
                # Determine cell class based on type of traffic
                if has_non_rfc1918 and show_non_rfc1918:
                    cell_class = 'public-access'  # Red for zone cells with non-RFC1918 traffic
                elif src_zone == dst_zone:
                    cell_class = 'same-zone-access'
                else:
                    cell_class = 'access-cell'
                
                # Add has_non_rfc1918 flag and non_rfc_url to onclick
                html_content += f'''                    <td class="{cell_class}" 
                    onclick="showDetails('{src_zone}', '{dst_zone}', {count}, '{services_str}', '{apps_str}', '{url}', {str(has_non_rfc1918).lower()}, '{non_rfc_url if show_non_rfc1918 else ''}')"
                    title="{'⚠️ Contains public IPs - ' if has_non_rfc1918 and show_non_rfc1918 else ''}Click to view details">{count}</td>\n'''
            else:
                html_content += '                    <td class="no-access"></td>\n'
        
        html_content += '                </tr>\n'
    
    html_content += """            </tbody>
        </table>
    </div>
    
    <div class="legend">
        <div class="legend-title">Legend</div>
        <div class="legend-items">
            <div class="legend-item">
                <div class="legend-box access"></div>
                <span>Cross-Zone Access (click for details)</span>
            </div>
            <div class="legend-item">
                <div class="legend-box same-zone"></div>
                <span>Same-Zone Access (click for details)</span>
            </div>"""
    
    if show_non_rfc1918:
        html_content += """
            <div class="legend-item">
                <div class="legend-box public"></div>
                <span>Contains Public/External IP Rules (non-RFC1918)</span>
            </div>"""
    
    html_content += """
            <div class="legend-item">
                <div class="legend-box no-access"></div>
                <span>No Access</span>
            </div>"""
    
    if exclude_same_zone:
        html_content += """
            <div class="legend-item">
                <div class="legend-box self">✕</div>
                <span>Same Zone (Excluded)</span>
            </div>"""
    
    html_content += """
        </div>
    </div>
    
    <!-- Modal for showing details -->
    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <div class="modal-title" id="modalTitle">Access Details</div>
            
            <div class="details-section">
                <div class="details-label">Zone Path:</div>
                <div id="zonePath" style="font-size: 16px; color: #2c3e50;"></div>
            </div>
            
            <div class="details-section">
                <div class="details-label">Number of Rules:</div>
                <div id="ruleCount" style="font-size: 16px; color: #2c3e50;"></div>
            </div>
            
            <div class="details-section">
                <div class="details-label">Allowed Services/Ports:</div>
                <div class="details-list" id="servicesList"></div>
            </div>
            
            <div class="details-section">
                <div class="details-label">Applications:</div>
                <div class="details-list" id="applicationsList"></div>
            </div>
            
            <a href="#" id="viewRulesLink" class="view-rules-btn" target="_blank">View All Rules in FireMon</a>
            <a href="#" id="viewNonRfc1918Link" class="view-rules-btn" style="display: none; background: #e74c3c; margin-left: 10px;" target="_blank">View Public IP Rules Only</a>
        </div>
    </div>
    
    <script>
        var modal = document.getElementById("detailsModal");
        var span = document.getElementsByClassName("close")[0];
        
        function showDetails(srcZone, dstZone, count, servicesStr, appsStr, url, hasNonRfc1918, nonRfcUrl) {
            // Parse the services and applications strings
            var services = eval(servicesStr);
            var apps = eval(appsStr);
            
            // Update modal content
            var pathText = srcZone + " → " + dstZone;
            if (srcZone === dstZone) {
                pathText += " (Same Zone)";
            }
            if (hasNonRfc1918) {
                pathText += " <span style='color: #e74c3c;'>⚠️ Contains Public IPs</span>";
            }
            document.getElementById("zonePath").innerHTML = pathText;
            document.getElementById("ruleCount").innerHTML = count + " rule(s)";
            
            // Update services list
            var servicesList = document.getElementById("servicesList");
            if (services && services.length > 0) {
                servicesList.innerHTML = services.map(function(s) {
                    return '<div class="details-item">• ' + s + '</div>';
                }).join('');
            } else {
                servicesList.innerHTML = '<div class="details-item">No specific services defined</div>';
            }
            
            // Update applications list
            var appsList = document.getElementById("applicationsList");
            if (apps && apps.length > 0) {
                appsList.innerHTML = apps.map(function(a) {
                    return '<div class="details-item">• ' + a + '</div>';
                }).join('');
            } else {
                appsList.innerHTML = '<div class="details-item">Any</div>';
            }
            
            // Update FireMon links
            document.getElementById("viewRulesLink").href = url;
            
            // Show/hide non-RFC1918 button based on hasNonRfc1918 flag
            var nonRfcLink = document.getElementById("viewNonRfc1918Link");
            if (hasNonRfc1918 && nonRfcUrl) {
                nonRfcLink.style.display = "inline-block";
                nonRfcLink.href = nonRfcUrl;
            } else {
                nonRfcLink.style.display = "none";
            }
            
            // Show modal
            modal.style.display = "block";
        }
        
        span.onclick = function() {
            modal.style.display = "none";
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }
    </script>
</body>
</html>
    """
    
    with open(output_html, 'w', encoding='utf-8') as file:
        file.write(html_content)
    
    access_paths_count = sum(1 for src in access_details for dst in access_details[src] if access_details[src][dst]['count'] > 0)
    print(f"✅ Generated {len(zones)}x{len(zones)} zone matrix with {access_paths_count} access paths")
    logging.info(f"HTML matrix report generated: {output_html}")

def sanitize_filename(name):
    """Sanitize the device name to be used as a filename."""
    return "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).rstrip()

def parse_zones_list(zones_str):
    """Parse comma-separated zones list."""
    if not zones_str:
        return None
    return [zone.strip() for zone in zones_str.split(',') if zone.strip()]

def parse_subnets_list(subnets_str):
    """Parse comma-separated subnets list."""
    if not subnets_str:
        return None
    return [subnet.strip() for subnet in subnets_str.split(',') if subnet.strip()]

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="FireMon Zone Access Matrix Report Generator")
    
    # Connection parameters
    parser.add_argument('--host', help="FireMon host (e.g., https://demo.firemon.xyz)")
    parser.add_argument('--username', help="FireMon username")
    parser.add_argument('--password', help="FireMon password")
    
    # Device selection
    parser.add_argument('--device-id', help="Single device ID")
    parser.add_argument('--device-ids', help="Comma-separated list of device IDs")
    parser.add_argument('--all-devices', action='store_true', help="Process all devices")
    parser.add_argument('--device-group', help="Device group ID")
    
    # Filtering options
    parser.add_argument('--zones', help="Comma-separated list of zones to include (e.g., Trust,DMZ,Untrust)")
    parser.add_argument('--src-subnets', help="Comma-separated list of source subnets to filter (e.g., 10.0.0.0/8,192.168.0.0/16)")
    parser.add_argument('--dst-subnets', help="Comma-separated list of destination subnets to filter")
    parser.add_argument('--exclude-same-zone', action='store_true', default=False, 
                       help="Exclude same-zone traffic from report (default: include same-zone)")
    parser.add_argument('--show-non-rfc1918', action='store_true', default=False,
                       help="Highlight zone combinations that have rules with public/external (non-RFC1918) IP addresses")
    
    # Report options
    parser.add_argument('--report-type', choices=['csv', 'html', 'both'], default='both', 
                       help="Type of report to generate")
    parser.add_argument('--output-dir', default='reports', help="Output directory for reports")
    
    # Other options
    parser.add_argument('--obfuscate-ips', action='store_true', default=True, 
                       help="Obfuscate IP addresses in logs")
    parser.add_argument('--no-obfuscate-ips', dest='obfuscate_ips', action='store_false', 
                       help="Disable IP obfuscation")
    parser.add_argument('--non-interactive', action='store_true', 
                       help="Run in non-interactive mode (for cron)")
    
    args = parser.parse_args()

    obfuscate_ips = args.obfuscate_ips

    print("=" * 60)
    print("       FIREMON ZONE ACCESS MATRIX REPORT GENERATOR")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Get connection parameters
    if args.non_interactive:
        # Non-interactive mode - require all parameters
        if not all([args.host, args.username, args.password]):
            print("Error: In non-interactive mode, --host, --username, and --password are required")
            sys.exit(1)
        
        api_host = args.host
        username = args.username
        password = args.password
        
        # Require device selection in non-interactive mode
        if not any([args.device_id, args.device_ids, args.all_devices, args.device_group]):
            print("Error: In non-interactive mode, you must specify device selection")
            print("Use --device-id, --device-ids, --all-devices, or --device-group")
            sys.exit(1)
    else:
        # Interactive mode - prompt for missing values
        api_host = args.host or input("Enter FireMon host (e.g., https://demo.firemon.xyz): ").strip()
        if not api_host:
            api_host = "https://localhost"
        
        username = args.username or input("Enter FireMon username: ")
        password = args.password or getpass.getpass("Enter FireMon password: ")

    device_ids = []
    api_url = api_host.rstrip('/') + '/securitymanager/api'
    context_type = 'device'
    context_id = None
    group_id = None

    # Authenticate and get token
    token = authenticate(api_url, username, password)
    logging.info("Authentication successful.")

    # Parse filtering options
    zone_filter = parse_zones_list(args.zones) if args.zones else None
    src_subnets = parse_subnets_list(args.src_subnets) if args.src_subnets else None
    dst_subnets = parse_subnets_list(args.dst_subnets) if args.dst_subnets else None
    
    if zone_filter:
        print(f"📋 Zone filter applied: {', '.join(zone_filter)}")
    if src_subnets:
        print(f"📋 Source subnet filter applied: {', '.join(src_subnets)}")
    if dst_subnets:
        print(f"📋 Destination subnet filter applied: {', '.join(dst_subnets)}")
    if args.exclude_same_zone:
        print(f"📋 Excluding same-zone traffic from report")
    else:
        print(f"📋 Including same-zone traffic in report (default)")
    if args.show_non_rfc1918:
        print(f"📋 Highlighting zones with public/external IP rules (non-RFC1918)")

    # Device selection
    if args.device_id:
        if args.device_id.isdigit():
            device_ids.append(args.device_id)
            context_type = 'device'
            context_id = args.device_id
        else:
            logging.error("Invalid device ID. Must be a numeric value.")
            print("❌ Invalid device ID. Must be a numeric value.")
            sys.exit(1)
    elif args.device_ids:
        device_id_list = [id.strip() for id in args.device_ids.split(',') if id.strip().isdigit()]
        if not device_id_list:
            logging.error("No valid device IDs entered.")
            print("❌ No valid device IDs entered.")
            sys.exit(1)
        device_ids.extend(device_id_list)
        context_type = 'all'
    elif args.all_devices:
        logging.info("Fetching all devices...")
        devices = get_all_devices(api_url, token)
        device_ids = [str(device['id']) for device in devices]
        if not device_ids:
            logging.error("No devices found in the domain.")
            print("❌ No devices found in the domain.")
            sys.exit(1)
        logging.info(f"Total devices fetched: {len(device_ids)}")
        context_type = 'all'
    elif args.device_group:
        group_id = args.device_group
        if group_id.isdigit():
            logging.info(f"Fetching devices in group ID {group_id}...")
            devices_in_group = get_devices_by_group(api_url, token, group_id)
            device_ids = [str(device['id']) for device in devices_in_group]
            if not device_ids:
                logging.error(f"No devices found in device group ID {group_id}.")
                print(f"❌ No devices found in device group ID {group_id}.")
                sys.exit(1)
            logging.info(f"Total devices fetched in group {group_id}: {len(device_ids)}")
            context_type = 'devicegroup'
            context_id = group_id
        else:
            logging.error("Invalid device group ID. Must be a numeric value.")
            print("❌ Invalid device group ID. Must be a numeric value.")
            sys.exit(1)
    elif not args.non_interactive:
        # Interactive device selection
        print("\n📋 Select Device Selection Option:")
        print("1. Single Device ID")
        print("2. List of Device IDs (comma-separated)")
        print("3. All Devices")
        print("4. Device Group ID")
        selection = input("Enter option (1/2/3/4): ").strip()

        if selection == '1':
            device_id = input("\nEnter the device ID: ").strip()
            if device_id.isdigit():
                device_ids.append(device_id)
                context_type = 'device'
                context_id = device_id
            else:
                logging.error("Invalid device ID. Must be a numeric value.")
                print("❌ Invalid device ID. Must be a numeric value.")
                sys.exit(1)
        elif selection == '2':
            device_id_input = input("\nEnter the device IDs (comma-separated): ").strip()
            device_id_list = [id.strip() for id in device_id_input.split(',') if id.strip().isdigit()]
            if not device_id_list:
                logging.error("No valid device IDs entered.")
                print("❌ No valid device IDs entered.")
                sys.exit(1)
            device_ids.extend(device_id_list)
            context_type = 'all'
        elif selection == '3':
            logging.info("Fetching all devices...")
            devices = get_all_devices(api_url, token)
            device_ids = [str(device['id']) for device in devices]
            if not device_ids:
                logging.error("No devices found in the domain.")
                print("❌ No devices found in the domain.")
                sys.exit(1)
            logging.info(f"Total devices fetched: {len(device_ids)}")
            context_type = 'all'
        elif selection == '4':
            group_id = input("\nEnter the device group ID: ").strip()
            if group_id.isdigit():
                logging.info(f"Fetching devices in group ID {group_id}...")
                devices_in_group = get_devices_by_group(api_url, token, group_id)
                device_ids = [str(device['id']) for device in devices_in_group]
                if not device_ids:
                    logging.error(f"No devices found in device group ID {group_id}.")
                    print(f"❌ No devices found in device group ID {group_id}.")
                    sys.exit(1)
                logging.info(f"Total devices fetched in group {group_id}: {len(device_ids)}")
                context_type = 'devicegroup'
                context_id = group_id
            else:
                logging.error("Invalid device group ID. Must be a numeric value.")
                print("❌ Invalid device group ID. Must be a numeric value.")
                sys.exit(1)
        else:
            logging.error("Invalid selection.")
            print("❌ Invalid selection.")
            sys.exit(1)

    # Report generation options
    if args.report_type:
        report_type = args.report_type
    elif not args.non_interactive:
        print("\n📊 Select Report Type to Generate:")
        print("1. CSV")
        print("2. HTML")
        print("3. Both CSV and HTML")
        report_selection = input("Enter option (1/2/3): ").strip()
        
        if report_selection == '1':
            report_type = 'csv'
        elif report_selection == '2':
            report_type = 'html'
        elif report_selection == '3':
            report_type = 'both'
        else:
            logging.error("Invalid selection.")
            print("❌ Invalid selection.")
            sys.exit(1)
    else:
        report_type = 'both'

    generate_csv = report_type in ['csv', 'both']
    generate_html = report_type in ['html', 'both']

    # Create output directory
    reports_dir = args.output_dir
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"\n📁 Created reports directory: {reports_dir}")

    # Aggregate rules from all devices
    all_rules = []
    device_names = []
    
    print(f"\n🔄 Processing {len(device_ids)} device(s)...")
    print("-" * 40)
    
    for idx, device_id in enumerate(device_ids, 1):
        print(f"\n📍 Device {idx}/{len(device_ids)} - ID: {device_id}")
        logging.info(f"Processing Device ID: {device_id}")
        device_name = get_device_name(api_url, token, device_id)
        device_names.append(device_name)
        logging.info(f"Device Name: {device_name}")

        # Get security rules for the device with filtering
        rules = get_security_rules(api_url, token, device_id, zone_filter, src_subnets, dst_subnets)
        logging.info(f"Number of security rules fetched for device ID {device_id}: {len(rules)}")
        all_rules.extend(rules)

    print("-" * 40)
    print(f"✅ Total rules collected: {len(all_rules)}")

    # Determine output filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if len(device_ids) == 1:
        sanitized_device_name = sanitize_filename(device_names[0]).replace(' ', '_')
        report_name = f"{sanitized_device_name}_{timestamp}"
        display_name = device_names[0]
    elif context_type == 'devicegroup':
        report_name = f"device_group_{group_id}_{timestamp}"
        display_name = f"Device Group {group_id}"
    else:
        report_name = f"all_devices_{timestamp}"
        display_name = f"All Devices ({len(device_ids)} devices)"

    OUTPUT_FILE = os.path.join(reports_dir, f'zone_access_matrix_{report_name}.csv')
    OUTPUT_HTML = os.path.join(reports_dir, f'zone_access_matrix_{report_name}.html')

    print("\n" + "=" * 60)
    print("                 GENERATING REPORTS")
    print("=" * 60)

    # Process and save rules to CSV matrix format
    if generate_csv:
        process_rules_to_csv_matrix(api_url, token, all_rules, OUTPUT_FILE, 
                                   obfuscate_ips=obfuscate_ips, 
                                   exclude_same_zone=args.exclude_same_zone,
                                   show_non_rfc1918=args.show_non_rfc1918)
        logging.info(f"CSV matrix report generated: {OUTPUT_FILE}")

    # Generate HTML matrix report
    if generate_html:
        generate_html_matrix(all_rules, OUTPUT_HTML, display_name, api_url, token, 
                           context_type=context_type, context_id=context_id, 
                           obfuscate_ips=obfuscate_ips,
                           exclude_same_zone=args.exclude_same_zone,
                           show_non_rfc1918=args.show_non_rfc1918)
        logging.info(f"HTML report generated: {OUTPUT_HTML}")

    # Final summary
    print("\n" + "=" * 60)
    print("              REPORT GENERATION COMPLETE!")
    print("=" * 60)
    print("\n📊 Summary:")
    print(f"   • Devices processed: {len(device_ids)}")
    print(f"   • Total rules analyzed: {len(all_rules)}")
    print(f"   • Matrix type: Zone-based")
    if args.show_non_rfc1918:
        print(f"   • Public IP detection: Enabled (non-RFC1918 rules highlighted)")
    if zone_filter:
        print(f"   • Zones filtered: {', '.join(zone_filter)}")
    if src_subnets or dst_subnets:
        print(f"   • Subnet filtering applied")
    print(f"   • Same-zone traffic: {'Excluded' if args.exclude_same_zone else 'Included (default)'}")
    print(f"   • Reports generated:")
    
    if generate_csv:
        print(f"\n   📄 CSV Report:")
        print(f"      Location: {OUTPUT_FILE}")
        print(f"      Size: {os.path.getsize(OUTPUT_FILE):,} bytes")
    
    if generate_html:
        print(f"\n   🌐 HTML Report:")
        print(f"      Location: {OUTPUT_HTML}")
        print(f"      Size: {os.path.getsize(OUTPUT_HTML):,} bytes")
    
    print(f"\n   📁 Reports saved in: {os.path.abspath(reports_dir)}/")
    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    logging.info("All selected reports have been generated successfully.")
    logging.info(f"Base FireMon URL used for links: {api_host}")
