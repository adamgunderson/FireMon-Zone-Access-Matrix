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

# Set up logging configuration near the top
logging.basicConfig(
    filename='script.log',
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
    login_url = f"{api_url}/authentication/login"  # FIXED: Removed duplicate /securitymanager/api
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

# Function to get security rules from a device
def get_security_rules(api_url, token, device_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"device {{ id = {device_id} }}"
    all_rules = []
    page = 0
    page_size = 100  # Use 100 per page for more manageable chunks
    
    print(f"   📋 Fetching security rules for device {device_id}...")
    
    while True:
        url = f"{api_url}/siql/secrule/paged-search?q={query}&page={page}&pageSize={page_size}"  # FIXED: Removed duplicate /securitymanager/api
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
                    break  # No more rules to fetch
                all_rules.extend(rules)
                logging.debug(f"Fetched {len(rules)} security rules for device ID {device_id} on page {page}")
                if len(rules) < page_size:
                    break  # Last page
                page += 1
            except KeyError:
                logging.error(f"Security rules fetched for device ID {device_id} but 'results' key not found in response.")
                sys.exit(1)
        else:
            logging.error(f"Failed to fetch security rules for device ID {device_id} on page {page}: %s %s", response.status_code, response.text)
            print(f"   ❌ Failed to fetch rules (HTTP {response.status_code})")
            sys.exit(1)
    
    logging.info(f"Total security rules fetched for device ID {device_id}: {len(all_rules)}")
    print(f"   ✅ Fetched {len(all_rules)} security rules")
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

# Function to get the FireMon Object service name by port and protocol
def get_service_name(api_url, token, protocol, port, portEnd=None, protocol_number=None):
    global service_name_cache

    protocol = protocol.upper()

    if portEnd:
        cache_key = (protocol, portEnd, 'portEnd')
    elif port:
        cache_key = (protocol, port, 'port')
    elif protocol_number:
        cache_key = (protocol, protocol_number, 'protocol_number')
    else:
        cache_key = ("Unknown", "Unknown", "unknown")

    if cache_key in service_name_cache:
        return service_name_cache[cache_key]

    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }

    # FIXED: Removed duplicate /securitymanager/api from all three URL constructions
    if portEnd:
        url = f"{api_url}/domain/1/service?type={protocol}&useWildcardSearch=true&portEnd={portEnd}&page=0&pageSize=20&sort=name"
    elif port:
        url = f"{api_url}/domain/1/service?type={protocol}&useWildcardSearch=true&port={port}&page=0&pageSize=20&sort=name"
    elif protocol_number:
        url = f"{api_url}/domain/1/service?type={protocol}&useWildcardSearch=true&protocol={protocol_number}&page=0&pageSize=20&sort=name"
    else:
        service_name_cache[cache_key] = "Unknown"
        return "Unknown"

    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching service name for {protocol}/ {'portEnd' if portEnd else 'port'} {portEnd if portEnd else port}: %s", e)
        service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
        return service_name_cache[cache_key]
    
    if response.status_code == 200:
        data = response.json()
        if data.get('count', 0) > 0:
            try:
                service_name = data['results'][0]['name']
                service_name_cache[cache_key] = service_name
                logging.debug(f"Service name found for {protocol}/{port or portEnd or protocol_number}: {service_name}")
                return service_name
            except (KeyError, IndexError):
                service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
                logging.debug(f"No service name found, using {service_name_cache[cache_key]}")
                return service_name_cache[cache_key]
    service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
    logging.debug(f"No service found in API response, using {service_name_cache[cache_key]}")
    return service_name_cache[cache_key]

# Process security rules to extract relevant data for CSV - FIXED to avoid duplicates
def process_rules_to_csv(api_url, token, rules, output_file, obfuscate_ips=True):
    print(f"\n📝 Generating CSV report...")
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Source Zone', 'Destination Zone', 'Protocol/Port', 'Protocol', 'Start Port', 'End Port', 'Service Name', 'Applications', 'Action'])

        # Use a set to track written rows and avoid duplicates
        written_rows = set()
        row_count = 0

        for index, rule in enumerate(rules):
            # Only process ACCEPT rules
            rule_action = rule.get('ruleAction') or rule.get('action') or 'Unknown'
            if rule_action != 'ACCEPT':
                continue
                
            if obfuscate_ips:
                rule_for_logging = obfuscate_ip_addresses(rule)
            else:
                rule_for_logging = rule
            logging.debug(f"Processing rule {index}: {rule_for_logging}")

            rule_id = rule.get('id') or rule.get('ruleId') or 'Unknown'
            
            # Extract source and destination contexts
            src_context = rule.get('srcContext') or rule.get('source', {}) or {}
            dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
            src_zones = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
            if not src_zones:
                src_zones = ['Any']
            dst_zones = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
            if not dst_zones:
                dst_zones = ['Any']

            # Extract applications
            apps = rule.get('apps', [])
            app_names = []
            for app in apps:
                app_name = app.get('name', 'Unknown')
                if app_name != 'Any':
                    app_names.append(app_name)
            app_string = ', '.join(app_names) if app_names else 'Any'

            services = rule.get('services') or rule.get('serviceList') or []
            
            # Handle case where there are applications but no specific services
            if not services or all(s.get('name') == 'Any' for s in services):
                if app_names:
                    for src_zone in src_zones:
                        for dst_zone in dst_zones:
                            row_tuple = (
                                src_zone,
                                dst_zone,
                                'App-Based',
                                'App',
                                'Any',
                                'Any',
                                'Application-Default',
                                app_string,
                                rule_action
                            )
                            if row_tuple not in written_rows:
                                writer.writerow(row_tuple)
                                written_rows.add(row_tuple)
                                row_count += 1
                    continue

            # Process services
            for service in services:
                service_entries = service.get('services', []) or service.get('serviceEntries', [])
                if not service_entries:
                    # Service without specific entries
                    for src_zone in src_zones:
                        for dst_zone in dst_zones:
                            row_tuple = (
                                src_zone,
                                dst_zone,
                                'Any',
                                'Any',
                                'Any',
                                'Any',
                                service.get('name', 'Any'),
                                app_string,
                                rule_action
                            )
                            if row_tuple not in written_rows:
                                writer.writerow(row_tuple)
                                written_rows.add(row_tuple)
                                row_count += 1
                    continue
                    
                for srv in service_entries:
                    protocol = srv.get('type', 'Unknown').lower()
                    start_port = srv.get('startPort', '')
                    end_port = srv.get('endPort', '')

                    if start_port and end_port:
                        if start_port == end_port:
                            protocol_port = f"{protocol}/{start_port}"
                        else:
                            protocol_port = f"{protocol}/{start_port}-{end_port}"
                    elif start_port:
                        protocol_port = f"{protocol}/{start_port}"
                    else:
                        protocol_port = f"{protocol}/Any"

                    for src_zone in src_zones:
                        for dst_zone in dst_zones:
                            row_tuple = (
                                src_zone,
                                dst_zone,
                                protocol_port,
                                protocol,
                                start_port if start_port else 'Any',
                                end_port if end_port else 'Any',
                                'N/A',
                                app_string,
                                rule_action
                            )
                            if row_tuple not in written_rows:
                                writer.writerow(row_tuple)
                                written_rows.add(row_tuple)
                                row_count += 1

    print(f"✅ CSV report generated with {row_count} rows")

# Process security rules to extract relevant data for CSV matrix format
def process_rules_to_csv_matrix(api_url, token, rules, output_file, obfuscate_ips=True):
    print(f"\n📝 Generating CSV matrix report...")
    
    # Store detailed access information for each zone pair
    zone_access_details = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'services': set(), 'applications': set()}))

    for index, rule in enumerate(rules):
        # Only process ACCEPT rules
        rule_action = rule.get('ruleAction') or rule.get('action') or 'Unknown'
        if rule_action != 'ACCEPT':
            continue
            
        if obfuscate_ips:
            rule_for_logging = obfuscate_ip_addresses(rule)
        else:
            rule_for_logging = rule

        # Extract source and destination contexts
        src_context = rule.get('srcContext') or rule.get('source', {}) or {}
        dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
        src_zones_list = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
        if not src_zones_list:
            src_zones_list = ['Any']
        dst_zones_list = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
        if not dst_zones_list:
            dst_zones_list = ['Any']

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

        # Update zone access details
        for src_zone in src_zones_list:
            for dst_zone in dst_zones_list:
                zone_access_details[src_zone][dst_zone]['count'] += 1
                if services_list:
                    zone_access_details[src_zone][dst_zone]['services'].update(services_list)
                if app_names:
                    zone_access_details[src_zone][dst_zone]['applications'].update(app_names)

    # Get sorted list of all zones
    all_zones = set()
    for src in zone_access_details:
        all_zones.add(src)
        for dst in zone_access_details[src]:
            all_zones.add(dst)
    zones = sorted(all_zones)

    # Write CSV in matrix format
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        # Write header row with destination zones
        header = ['Source \\ Destination'] + zones
        writer.writerow(header)
        
        # Write each source zone row
        for src_zone in zones:
            row = [src_zone]
            for dst_zone in zones:
                if src_zone == dst_zone:
                    # Same zone - mark as N/A
                    row.append('N/A')
                else:
                    access_info = zone_access_details.get(src_zone, {}).get(dst_zone, {})
                    count = access_info.get('count', 0)
                    
                    if count > 0:
                        services = sorted(list(access_info.get('services', [])))
                        apps = sorted(list(access_info.get('applications', [])))
                        
                        # Format cell content
                        cell_content = f"Rules: {count}"
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
    
    access_paths_count = len([1 for src in zone_access_details for dst in zone_access_details[src] if zone_access_details[src][dst]['count'] > 0])
    print(f"✅ CSV matrix report generated with {len(zones)}x{len(zones)} cells and {access_paths_count} access paths")

# Generate a clean access matrix HTML report with service/application details
def generate_html_matrix(rules, output_html, device_name, api_url, token, context_type='device', context_id=None, obfuscate_ips=True):
    """
    Generate HTML matrix report with clickable cells showing services/applications.
    """
    print(f"\n📊 Generating HTML matrix report...")
    
    # Extract base URL from api_url (remove /api part)
    base_url = api_url.replace('/securitymanager/api', '').replace('/api', '')
    
    # Store detailed access information for each zone pair
    zone_access_details = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'services': set(), 'applications': set()}))

    for index, rule in enumerate(rules):
        # Only process ACCEPT rules
        rule_action = rule.get('ruleAction') or rule.get('action') or 'Unknown'
        if rule_action != 'ACCEPT':
            continue
            
        if obfuscate_ips:
            rule_for_logging = obfuscate_ip_addresses(rule)
        else:
            rule_for_logging = rule

        rule_id = rule.get('id') or rule.get('ruleId') or 'Unknown'
        
        # Extract source and destination contexts
        src_context = rule.get('srcContext') or rule.get('source', {}) or {}
        dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
        src_zones_list = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
        if not src_zones_list:
            src_zones_list = ['Any']
        dst_zones_list = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
        if not dst_zones_list:
            dst_zones_list = ['Any']

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

        # Update zone access details
        for src_zone in src_zones_list:
            for dst_zone in dst_zones_list:
                zone_access_details[src_zone][dst_zone]['count'] += 1
                if services_list:
                    zone_access_details[src_zone][dst_zone]['services'].update(services_list)
                if app_names:
                    zone_access_details[src_zone][dst_zone]['applications'].update(app_names)

    # Get sorted list of all zones (including "Any")
    all_zones = set()
    for src in zone_access_details:
        all_zones.add(src)
        for dst in zone_access_details[src]:
            all_zones.add(dst)
    zones = sorted(all_zones)

    # Generate HTML with modal for details and improved scrolling
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Matrix - {device_name}</title>
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
        }}
        
        .container {{
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
        }}
        
        h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        
        .subtitle {{
            color: #7f8c8d;
            margin-bottom: 20px;
            font-size: 14px;
        }}
        
        .table-wrapper {{
            margin-top: 20px;
            position: relative;
        }}
        
        table {{
            border-collapse: collapse;
            width: 100%;
            min-width: 600px;
        }}
        
        thead {{
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: center;
            position: relative;
        }}
        
        th {{
            background: #34495e;
            color: white;
            font-weight: 600;
            font-size: 12px;
            white-space: nowrap;
        }}
        
        thead th:first-child {{
            position: sticky;
            left: 0;
            z-index: 11;
            background: #2c3e50;
            text-align: left;
        }}
        
        tbody td:first-child {{
            position: sticky;
            left: 0;
            background: #ecf0f1;
            font-weight: 600;
            text-align: left;
            font-size: 12px;
            z-index: 9;
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
        
        .no-access {{
            background: #95a5a6;
            color: #ecf0f1;
        }}
        
        .self-zone {{
            background: #7f8c8d;
            color: #bdc3c7;
            font-size: 18px;
            font-weight: bold;
        }}
        
        .legend {{
            margin-top: 20px;
            padding: 15px;
            background: #ecf0f1;
            border-radius: 4px;
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
    </style>
</head>
<body>
    <div class="container">
        <h1>Zone Access Matrix</h1>
        <div class="subtitle">Device: {device_name} | Click on any cell to view details</div>
        
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Source \\ Destination</th>
    """
    
    # Add column headers for destination zones
    for zone in zones:
        html_content += f'                        <th>{zone}</th>\n'
    
    html_content += """                    </tr>
                </thead>
                <tbody>
    """
    
    # Add rows for each source zone
    for src_zone in zones:
        html_content += f'                    <tr>\n'
        html_content += f'                        <td>{src_zone}</td>\n'
        
        for dst_zone in zones:
            if src_zone == dst_zone:
                # Self-zone reference - show X
                html_content += '                        <td class="self-zone">✕</td>\n'
            else:
                access_info = zone_access_details.get(src_zone, {}).get(dst_zone, {})
                count = access_info.get('count', 0)
                
                if count > 0:
                    services_json = sorted(list(access_info.get('services', [])))
                    apps_json = sorted(list(access_info.get('applications', [])))
                    
                    # Generate FireMon URL based on context
                    if context_type == 'device' and context_id:
                        siql = f"device {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND (destination.zone.any = false AND (destination.zone = '{dst_zone}')) AND (source.zone.any = false AND (source.zone = '{src_zone}')) }}"
                        url = f"{base_url}/securitymanager/#/domain/1/device/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(siql)}"
                    elif context_type == 'devicegroup' and context_id:
                        siql = f"devicegroup {{ id = {context_id} }} AND rule {{ action = 'ACCEPT' AND (destination.zone.any = false AND (destination.zone = '{dst_zone}')) AND (source.zone.any = false AND (source.zone = '{src_zone}')) }}"
                        url = f"{base_url}/securitymanager/#/domain/1/devicegroup/{context_id}/listrules?page=1&count=20&advancedMode=1&siql={urllib.parse.quote(siql)}"
                    else:  # all devices
                        siql = f"domain {{ id = 1 }} AND rule {{ action = 'ACCEPT' AND (source.zone.any = false AND (source.zone = '{src_zone}')) AND (destination.zone.any = false AND (destination.zone = '{dst_zone}')) }}"
                        url = f"{base_url}/securitymanager/#/domain/1/listrules?page=1&count=20&advancedMode=0&siql={urllib.parse.quote(siql)}"
                    
                    # Escape quotes for JavaScript
                    services_str = str(services_json).replace("'", "\\'")
                    apps_str = str(apps_json).replace("'", "\\'")
                    
                    html_content += f'''                        <td class="access-cell" 
                            onclick="showDetails('{src_zone}', '{dst_zone}', {count}, '{services_str}', '{apps_str}', '{url}')"
                            title="Click to view details">{count}</td>\n'''
                else:
                    html_content += '                        <td class="no-access"></td>\n'
        
        html_content += '                    </tr>\n'
    
    html_content += """                </tbody>
            </table>
        </div>
        
        <div class="legend">
            <div class="legend-title">Legend</div>
            <div class="legend-items">
                <div class="legend-item">
                    <div class="legend-box access"></div>
                    <span>Access Available (click for details)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-box no-access"></div>
                    <span>No Access</span>
                </div>
                <div class="legend-item">
                    <div class="legend-box self">✕</div>
                    <span>Same Zone (N/A)</span>
                </div>
            </div>
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
            
            <a href="#" id="viewRulesLink" class="view-rules-btn" target="_blank">View Rules in FireMon</a>
        </div>
    </div>
    
    <script>
        var modal = document.getElementById("detailsModal");
        var span = document.getElementsByClassName("close")[0];
        
        function showDetails(srcZone, dstZone, count, servicesStr, appsStr, url) {
            // Parse the services and applications strings
            var services = eval(servicesStr);
            var apps = eval(appsStr);
            
            // Update modal content
            document.getElementById("zonePath").innerHTML = srcZone + " → " + dstZone;
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
            
            // Update FireMon link
            document.getElementById("viewRulesLink").href = url;
            
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
    
    access_paths_count = len([1 for src in zone_access_details for dst in zone_access_details[src] if zone_access_details[src][dst]['count'] > 0])
    print(f"✅ Generated {len(zones)}x{len(zones)} matrix with {access_paths_count} access paths")
    logging.info(f"HTML matrix report generated: {output_html}")

def sanitize_filename(name):
    """Sanitize the device name to be used as a filename."""
    return "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).rstrip()

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="FireMon Zone Access Matrix Report")
    parser.add_argument('--obfuscate-ips', action='store_true', default=True, help="Obfuscate IP addresses in logs (default: True)")
    parser.add_argument('--no-obfuscate-ips', dest='obfuscate_ips', action='store_false', help="Disable IP obfuscation")
    args = parser.parse_args()

    obfuscate_ips = args.obfuscate_ips

    print("=" * 60)
    print("       FIREMON ZONE ACCESS MATRIX REPORT GENERATOR")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Prompt user for inputs
    api_host = input("Enter FireMon host (e.g., https://demo.firemon.xyz): ").strip()
    if not api_host:
        api_host = "https://localhost"
    
    username = input("Enter FireMon username: ")
    password = getpass.getpass("Enter FireMon password: ")

    # Device selection options
    print("\n📋 Select Device Selection Option:")
    print("1. Single Device ID")
    print("2. List of Device IDs (comma-separated)")
    print("3. All Devices")
    print("4. Device Group ID")
    selection = input("Enter option (1/2/3/4): ").strip()

    device_ids = []
    api_url = api_host.rstrip('/') + '/securitymanager/api'
    context_type = 'device'
    context_id = None
    group_id = None

    # Authenticate and get token
    token = authenticate(api_url, username, password)
    logging.info("Authentication successful.")

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
        context_type = 'all'  # Multiple devices, treat as all
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
        logging.error("Invalid selection. Please enter 1, 2, 3, or 4.")
        print("❌ Invalid selection. Please enter 1, 2, 3, or 4.")
        sys.exit(1)

    # Report generation options
    print("\n📊 Select Report Type to Generate:")
    print("1. CSV")
    print("2. HTML")
    print("3. Both CSV and HTML")
    report_selection = input("Enter option (1/2/3): ").strip()

    generate_csv = False
    generate_html = False

    if report_selection == '1':
        generate_csv = True
    elif report_selection == '2':
        generate_html = True
    elif report_selection == '3':
        generate_csv = True
        generate_html = True
    else:
        logging.error("Invalid selection. Please enter 1, 2, or 3.")
        print("❌ Invalid selection. Please enter 1, 2, or 3.")
        sys.exit(1)

    # Create a directory to store reports
    reports_dir = 'reports'
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        print(f"\n📁 Created reports directory: {reports_dir}")

    # Aggregate rules from all devices if multiple
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

        # Get security rules for the device
        rules = get_security_rules(api_url, token, device_id)
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

    OUTPUT_FILE = os.path.join(reports_dir, f'access_matrix_{report_name}.csv')
    OUTPUT_HTML = os.path.join(reports_dir, f'access_matrix_{report_name}.html')

    print("\n" + "=" * 60)
    print("                 GENERATING REPORTS")
    print("=" * 60)

    # Process and save rules to CSV matrix format
    if generate_csv:
        process_rules_to_csv_matrix(api_url, token, all_rules, OUTPUT_FILE, obfuscate_ips=obfuscate_ips)
        logging.info(f"CSV matrix report generated: {OUTPUT_FILE}")

    # Generate HTML matrix report
    if generate_html:
        generate_html_matrix(all_rules, OUTPUT_HTML, display_name, api_url, token, 
                           context_type=context_type, context_id=context_id, obfuscate_ips=obfuscate_ips)
        logging.info(f"HTML report generated: {OUTPUT_HTML}")

    # Final summary
    print("\n" + "=" * 60)
    print("              REPORT GENERATION COMPLETE!")
    print("=" * 60)
    print("\n📊 Summary:")
    print(f"   • Devices processed: {len(device_ids)}")
    print(f"   • Total rules analyzed: {len(all_rules)}")
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
