#!/usr/bin/env python3
"""
Scans RHEL 8 legacy network scripts (`ifcfg`) for 'team' interface configurations,
parses them, and generates the equivalent NetworkManager keyfile content for
'bond' interfaces. This facilitates migrating from teamd/ifcfg to native
NetworkManager bonding.

This version handles:
- IP aliases defined using IPADDRn/PREFIXn/NETMASKn variables within the main ifcfg-team file.
- Static IPv4 routes defined in corresponding route-<teamN> files (parses
  'ADDRESS/PREFIX via NEXT_HOP [metric METRIC]' format).
- Allows specifying input and output directories via command-line arguments.
- Outputs results, warnings, and errors in JSON format to STDOUT.
- Exits with specific codes:
  - 0: Success, no warnings.
  - 1: Fatal error during setup or file writing.
  - 3: Success, but warnings were generated during processing.

*** This version writes the generated .nmconnection files to the directory
*** specified by the --output-dir argument (defaults to CWD). ***
"""

import os
import re
import json
import sys
import ipaddress
import uuid
import argparse # Import argparse for command-line arguments
from typing import Dict, List, Tuple, Optional, Any, NamedTuple

# --- Configuration Constants (Defaults for argparse) ---
DEFAULT_IFCFG_PATH = "/etc/sysconfig/network-scripts/"
DEFAULT_OUTPUT_DIR = "." # Default to Current Working Directory

# Standard directory where NetworkManager stores system connection profiles (keyfiles).
# Used in final instructions (if manually constructed from JSON).
SYSTEM_NM_CONNECTIONS_DIR = "/etc/NetworkManager/system-connections/"
# Mapping from teamd runner names (found in TEAM_CONFIG) to NetworkManager bond modes.
TEAM_TO_BOND_MODE_MAP = {
    "roundrobin": "balance-rr",     # Round-robin load balancing
    "activebackup": "active-backup", # Active/standby failover
    "loadbalance": "balance-xor",    # XOR-based load balancing (common teamd 'loadbalance')
    "broadcast": "broadcast",        # Transmit everything on all slaves
    "lacp": "802.3ad",           # Link Aggregation Control Protocol (IEEE 802.3ad)
}
# Default bonding options to include in the generated keyfile, primarily for link monitoring.
DEFAULT_BOND_OPTIONS = "miimon=100"
# Maximum index to check for IP aliases (IPADDRn, PREFIXn, etc.)
MAX_IP_ALIAS_INDEX = 20

# --- Exit Codes ---
EXIT_SUCCESS = 0
EXIT_FATAL_ERROR = 1
EXIT_SUCCESS_WITH_WARNINGS = 3


# --- Data Structures ---
class IfcfgConfig(dict):
    """Simple wrapper class for type hinting dictionaries representing parsed ifcfg files."""
    pass

class Keyfile(NamedTuple):
    """Represents the data for a single generated NetworkManager keyfile."""
    filename: str
    content: str

class GenerationResult(NamedTuple):
    """Holds the results of generating keyfiles for one specific team interface."""
    keyfiles: List[Keyfile]
    warnings: List[str]
    team_device: str
    bond_device: str

class ParseResult(NamedTuple):
    """Holds the result of attempting to parse a single ifcfg file."""
    filepath: str
    config: Optional[IfcfgConfig]
    error: Optional[str]

class ParsedRoute(NamedTuple):
    """Holds the structured data for a successfully parsed static route."""
    destination: str
    prefix: int
    next_hop: str
    metric: Optional[int]

class ProcessedTeamInfo(NamedTuple):
    """Holds summary information about a processed team for JSON output."""
    team_device: str
    bond_device: str
    generated_files: List[str] # List of full paths to written files


# --- Pure Helper Functions ---
# (parse_ifcfg_line, netmask_to_prefix, parse_team_config_json remain unchanged)
def parse_ifcfg_line(line: str) -> Optional[Tuple[str, str]]:
    """Parses a single valid line from an ifcfg file."""
    line = line.strip()
    if not line or line.startswith('#'): return None
    match = re.match(r'^\s*(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^#\s]+))\s*(?:#.*)?$', line)
    if match:
        key = match.group(1).upper()
        value = next((g for g in match.groups()[1:] if g is not None), '')
        return key, value
    return None

def netmask_to_prefix(netmask: Optional[str]) -> Optional[int]:
    """Converts an IPv4 netmask to its prefix length."""
    if not netmask: return None
    try: return ipaddress.ip_network(f'0.0.0.0/{netmask}', strict=False).prefixlen
    except ValueError: return None

def parse_team_config_json(config_str: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parses the TEAM_CONFIG JSON string."""
    if not config_str: return None
    try:
        processed_str = config_str
        if config_str.startswith("'") and config_str.endswith("'"): processed_str = config_str[1:-1]
        elif config_str.startswith('"') and config_str.endswith('"'): processed_str = config_str[1:-1]
        processed_str = processed_str.replace('\\"', '"')
        return json.loads(processed_str)
    except (json.JSONDecodeError, Exception): return None

# --- Core Logic Functions (Minimize Side Effects) ---
# (read_and_parse_ifcfg, parse_route_file, generate_single_keyfile_content remain unchanged)
def read_and_parse_ifcfg(filepath: str) -> ParseResult:
    """Reads and parses an ifcfg file, returning config or error."""
    config = IfcfgConfig()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                parsed_line = parse_ifcfg_line(line)
                if parsed_line: config[parsed_line[0]] = parsed_line[1]
        return ParseResult(filepath=filepath, config=config, error=None)
    except FileNotFoundError:
        return ParseResult(filepath=filepath, config=None, error=f"File not found: {filepath}")
    except Exception as e:
        return ParseResult(filepath=filepath, config=None, error=f"Could not parse file {filepath}: {e}")

def parse_route_file(filepath: str) -> Tuple[List[ParsedRoute], List[str]]:
    """
    Parses a route-<interface> file for static IPv4 routes.
    Specifically looks for lines matching: ADDRESS/PREFIX via NEXT_HOP [metric METRIC]
    Ignores 'default' routes and lines that don't match.
    """
    parsed_routes: List[ParsedRoute] = []
    warnings: List[str] = []
    route_pattern = re.compile(r"^\s*(\S+)\s+via\s+(\S+)(?:\s+metric\s+(\d+))?.*$")
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): continue
                match = route_pattern.match(line)
                if match:
                    target = match.group(1); next_hop_str = match.group(2); metric_str = match.group(3)
                    if target.lower() == 'default':
                        warnings.append(f"L{line_num}: Ignoring 'default' route found in {filepath}; use GATEWAY in ifcfg file."); continue
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                        if network.version != 4: warnings.append(f"L{line_num}: Ignoring non-IPv4 target '{target}' in {filepath}."); continue
                        destination = str(network.network_address); prefix = network.prefixlen
                    except ValueError: warnings.append(f"L{line_num}: Could not parse route target '{target}' in {filepath}. Skipping line."); continue
                    try: ipaddress.ip_address(next_hop_str)
                    except ValueError: warnings.append(f"L{line_num}: Invalid next hop '{next_hop_str}' for target '{target}' in {filepath}. Skipping line."); continue
                    metric: Optional[int] = None
                    if metric_str:
                        try: metric = int(metric_str)
                        except ValueError: warnings.append(f"L{line_num}: Invalid metric value '{metric_str}' for target '{target}' in {filepath}. Ignoring metric.")
                    parsed_routes.append(ParsedRoute(destination=destination, prefix=prefix, next_hop=next_hop_str, metric=metric))
                else: warnings.append(f"L{line_num}: Could not parse route line format in {filepath}: '{line}'")
    except FileNotFoundError: warnings.append(f"Route file not found: {filepath}") # Should be caught in main
    except Exception as e: warnings.append(f"Error reading route file {filepath}: {e}")
    return parsed_routes, warnings

def generate_single_keyfile_content(
    team_master_config: IfcfgConfig,
    member_configs: List[Tuple[str, IfcfgConfig]],
    static_routes: List[ParsedRoute] # Added parameter for parsed routes
) -> GenerationResult:
    """
    Generates the keyfile content (as strings) for a single bond master interface
    and its corresponding slave interfaces, based on the parsed team configuration.
    Handles multiple IP addresses (aliases) using IPADDRn/PREFIXn/NETMASKn convention.
    Includes static routes passed via the static_routes parameter.
    """
    keyfiles: List[Keyfile] = []
    warnings: List[str] = []
    team_device = team_master_config.get("DEVICE")
    if not team_device:
        warnings.append("Skipping team config without DEVICE.")
        return GenerationResult(keyfiles=[], warnings=warnings, team_device="UNKNOWN", bond_device="UNKNOWN")
    bond_device = team_device.replace("team", "bond")
    bond_con_name = bond_device
    master_keyfile_lines: List[str] = []
    master_filename = f"{bond_con_name}.nmconnection"

    # 1. Determine Bonding Mode
    team_config_str = team_master_config.get("TEAM_CONFIG")
    team_details = parse_team_config_json(team_config_str)
    team_runner = None
    if not team_details: warnings.append(f"Could not parse TEAM_CONFIG JSON for {team_device}: '{team_config_str}'")
    elif isinstance(team_details.get("runner"), dict): team_runner = team_details["runner"].get("name")
    if not team_runner:
        warnings.append(f"Could not determine runner for {team_device}. Skipping generation for this team.")
        return GenerationResult(keyfiles=[], warnings=warnings, team_device=team_device, bond_device=bond_device)
    bond_mode = TEAM_TO_BOND_MODE_MAP.get(team_runner)
    if not bond_mode:
        warnings.append(f"No mapping found for team runner '{team_runner}' for {team_device}. Skipping generation.")
        return GenerationResult(keyfiles=[], warnings=warnings, team_device=team_device, bond_device=bond_device)

    # 2. Build [connection] Section
    master_keyfile_lines.extend(["[connection]", f"id={bond_con_name}", f"uuid={uuid.uuid4()}", "type=bond", f"interface-name={bond_device}"])
    onboot = team_master_config.get("ONBOOT", "yes").lower()
    master_keyfile_lines.append(f"autoconnect={'true' if onboot == 'yes' else 'false'}")
    master_keyfile_lines.append("")

    # 3. Build [bond] Section
    master_keyfile_lines.append("[bond]")
    bond_options_list = [f"mode={bond_mode}", f"miimon={DEFAULT_BOND_OPTIONS.split('=')[1]}"]
    if bond_mode == "802.3ad" and team_details:
         lacp_rate = team_details.get("runner", {}).get("lacp_rate")
         if lacp_rate == "fast": bond_options_list.append("lacp_rate=fast")
    master_keyfile_lines.extend(bond_options_list)
    master_keyfile_lines.append("")

    # 4. Build [ethernet] Section
    master_keyfile_lines.extend(["[ethernet]", ""])

    # 5. Build [ipv4] Section
    master_keyfile_lines.append("[ipv4]")
    bootproto = team_master_config.get("BOOTPROTO", "none").lower()
    if bootproto == "dhcp":
        master_keyfile_lines.append("method=auto")
        dhcp_hostname = team_master_config.get("DHCP_HOSTNAME") or team_master_config.get("HOSTNAME")
        if dhcp_hostname: master_keyfile_lines.append(f"dhcp-hostname={dhcp_hostname}")
        peerdns = team_master_config.get("PEERDNS", "yes").lower()
        master_keyfile_lines.append(f"ignore-auto-dns={'true' if peerdns == 'no' else 'false'}")
    elif bootproto in ["static", "none"]:
        ip_address_list: List[str] = []
        for i in range(MAX_IP_ALIAS_INDEX + 1):
            ip_key = f"IPADDR{i}"; prefix_key = f"PREFIX{i}"; netmask_key = f"NETMASK{i}"
            if i == 0: ip_addr = team_master_config.get(ip_key) or team_master_config.get("IPADDR"); prefix_val = team_master_config.get(prefix_key) or team_master_config.get("PREFIX"); netmask_val = team_master_config.get(netmask_key) or team_master_config.get("NETMASK")
            else: ip_addr = team_master_config.get(ip_key); prefix_val = team_master_config.get(prefix_key); netmask_val = team_master_config.get(netmask_key)
            if not ip_addr: break
            prefix = None
            if prefix_val:
                try: prefix = int(prefix_val)
                except ValueError: warnings.append(f"Invalid PREFIX value '{prefix_val}' for {ip_key} on {team_device}. Skipping this address."); continue
            elif netmask_val:
                prefix = netmask_to_prefix(netmask_val)
                if prefix is None: warnings.append(f"Invalid NETMASK value '{netmask_val}' for {ip_key} on {team_device}. Cannot determine prefix. Skipping this address."); continue
            else: warnings.append(f"Missing PREFIX or NETMASK for {ip_key} ({ip_addr}) on {team_device}. Skipping this address."); continue
            ip_address_list.append(f"{ip_addr}/{prefix}")

        if not ip_address_list:
            warnings.append(f"BOOTPROTO is static/none for {team_device}, but no valid IPADDRn/PREFIXn pairs found. Setting ipv4.method=disabled.")
            master_keyfile_lines.append("method=disabled")
        else:
            master_keyfile_lines.append("method=manual")
            master_keyfile_lines.append(f"addresses={';'.join(ip_address_list)};")
            gateway = team_master_config.get("GATEWAY"); dns1 = team_master_config.get("DNS1"); dns2 = team_master_config.get("DNS2"); domain = team_master_config.get("DOMAIN")
            if gateway: master_keyfile_lines.append(f"gateway={gateway}")
            dns_servers = [d for d in [dns1, dns2] if d]
            if dns_servers: master_keyfile_lines.append(f"dns={';'.join(dns_servers)};"); master_keyfile_lines.append("ignore-auto-dns=true")
            else: master_keyfile_lines.append("ignore-auto-dns=true")
            if domain: master_keyfile_lines.append(f"dns-search={domain};")
    else:
        warnings.append(f"Unsupported BOOTPROTO '{bootproto}' for {team_device}. Setting ipv4.method=disabled.")
        master_keyfile_lines.append("method=disabled")

    # Add Static Routes
    if static_routes:
        master_keyfile_lines.append(f"# Static routes from route-{team_device}")
        for index, route in enumerate(static_routes, start=1):
            route_str = f"route{index}={route.destination}/{route.prefix},{route.next_hop}"
            if route.metric is not None: route_str += f",{route.metric}"
            master_keyfile_lines.append(route_str)
    master_keyfile_lines.append("")

    # 6. Build [ipv6] Section
    master_keyfile_lines.append("[ipv6]")
    if team_master_config.get("IPV6INIT", "no").lower() == "yes":
        ipv6_bootproto = team_master_config.get("IPV6_AUTOCONF", "yes").lower()
        master_keyfile_lines.append("method=auto" if ipv6_bootproto == "yes" else "disabled")
    else: master_keyfile_lines.append("method=ignore")
    master_keyfile_lines.append("")

    # 7. Build [proxy] Section
    master_keyfile_lines.extend(["[proxy]", ""])
    keyfiles.append(Keyfile(filename=master_filename, content="\n".join(master_keyfile_lines)))

    # Generate Slave Keyfiles
    if not member_configs: warnings.append(f"No member interfaces found for team {team_device}.")
    else:
        for member_iface, member_config in member_configs:
            slave_keyfile_lines: List[str] = []; member_con_name = f"{member_iface}-slave-{bond_device}"; slave_filename = f"{member_con_name}.nmconnection"
            slave_keyfile_lines.extend(["[connection]", f"id={member_con_name}", f"uuid={uuid.uuid4()}", "type=ethernet", f"interface-name={member_iface}", f"master={bond_device}", "slave-type=bond", f"autoconnect={'true' if onboot == 'yes' else 'false'}", "", "[ethernet]", "", "[ipv4]", "method=disabled", "", "[ipv6]", "method=disabled", "", "[proxy]", ""])
            keyfiles.append(Keyfile(filename=slave_filename, content="\n".join(slave_keyfile_lines)))

    return GenerationResult(keyfiles=keyfiles, warnings=warnings, team_device=team_device, bond_device=bond_device)


# --- Main Execution (Handles I/O and Orchestration) ---
def main():
    """ Main function to orchestrate the process. """

    # *** Setup Argument Parser ***
    parser = argparse.ArgumentParser(
        description="Convert RHEL ifcfg team configurations to NetworkManager bond keyfiles.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i", "--input-dir",
        default=DEFAULT_IFCFG_PATH,
        help="Directory containing the source ifcfg-* and route-* files."
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where generated *.nmconnection keyfiles will be written."
    )
    # Verbose flag removed as output is now JSON
    args = parser.parse_args() # Parse command-line arguments

    # Use parsed arguments for paths
    ifcfg_input_path = args.input_dir
    output_dir = args.output_dir

    # --- Data Collection for JSON Output ---
    all_warnings: List[str] = []
    fatal_errors: List[str] = [] # Keep track of fatal errors encountered before exit
    write_errors: List[str] = []
    processed_teams_summary: List[ProcessedTeamInfo] = []
    all_generation_results: List[GenerationResult] = [] # Define before potential use
    final_status = "success" # Assume success initially
    final_exit_code = EXIT_SUCCESS

    # *** Ensure output directory exists ***
    try:
        if not os.path.isdir(output_dir):
            # Attempt to create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        # Fatal error if output directory cannot be accessed/created
        error_msg = f"Error: Could not create or access output directory '{output_dir}': {e}"
        # Print JSON error and exit immediately for fatal setup errors
        print(json.dumps({"status": "fatal_error", "errors": [error_msg]}, indent=2), file=sys.stdout)
        sys.exit(EXIT_FATAL_ERROR)

    # 1. Scan for ifcfg files in the specified input directory
    try:
        all_files_in_input = os.listdir(ifcfg_input_path)
        ifcfg_filenames = [f for f in all_files_in_input
                           if os.path.isfile(os.path.join(ifcfg_input_path, f)) and f.startswith('ifcfg-')]
    except FileNotFoundError:
        error_msg = f"Error: Network script input directory not found: {ifcfg_input_path}"
        print(json.dumps({"status": "fatal_error", "errors": [error_msg]}, indent=2), file=sys.stdout)
        sys.exit(EXIT_FATAL_ERROR)
    except OSError as e:
        error_msg = f"Error: Cannot access network script input directory {ifcfg_input_path}: {e}"
        print(json.dumps({"status": "fatal_error", "errors": [error_msg]}, indent=2), file=sys.stdout)
        sys.exit(EXIT_FATAL_ERROR)

    # 2. Parse all found ifcfg files
    parse_results = [read_and_parse_ifcfg(os.path.join(ifcfg_input_path, f)) for f in ifcfg_filenames]

    # 3. Process parsing results
    valid_configs: Dict[str, IfcfgConfig] = {}; parsing_errors: List[str] = []
    for result in parse_results:
        if result.config is not None: key = result.config.get("DEVICE", result.filepath); valid_configs[key] = result.config
        elif result.error: parsing_errors.append(result.error)
    all_warnings.extend(parsing_errors) # Add parsing errors to warnings list

    # 4. Identify team masters and map members
    team_configs: Dict[str, IfcfgConfig] = {}; member_map: Dict[str, List[Tuple[str, IfcfgConfig]]] = {}; member_assignment_warnings: List[str] = []
    for device_or_path, config in valid_configs.items():
        devicetype = config.get("DEVICETYPE", "").lower(); device = config.get("DEVICE")
        if devicetype == "team" and device: team_configs[device] = config; member_map[device] = [] # Found a team master
    for device_or_path, config in valid_configs.items():
         team_master = config.get("TEAM_MASTER"); device = config.get("DEVICE")
         if team_master and device:
             if team_master in member_map: member_map[team_master].append((device, config)) # Found a member
             else: member_assignment_warnings.append(f"Member {device} found for team {team_master}, but master config was not found or is invalid.")
    all_warnings.extend(member_assignment_warnings) # Add assignment warnings

    # 5. Generate keyfile content for each identified team
    all_keyfiles_to_write: List[Keyfile] = [] # Collect all files to be written
    if not team_configs and not all_warnings: # Only report 'no teams found' if no other errors/warnings exist yet
        all_warnings.append("No Team interfaces (DEVICETYPE=Team) found in valid ifcfg files.")
    elif team_configs: # Only proceed if teams were found
        # This loop populates all_generation_results
        for team_device, master_config in team_configs.items():
            members = member_map.get(team_device, [])
            static_routes: List[ParsedRoute] = []
            route_filename = f"route-{team_device}"; route_filepath = os.path.join(ifcfg_input_path, route_filename)
            if os.path.isfile(route_filepath):
                parsed_routes, route_warnings = parse_route_file(route_filepath)
                if route_warnings: all_warnings.extend([f"[{team_device}/Routes] {w}" for w in route_warnings])
                if parsed_routes: static_routes = parsed_routes

            result = generate_single_keyfile_content(master_config, members, static_routes)
            all_generation_results.append(result) # Append result here
            all_warnings.extend([f"[{result.team_device} -> {result.bond_device}] {w}" for w in result.warnings])
            all_keyfiles_to_write.extend(result.keyfiles)

    # 6. Write Keyfiles to Specified Output Directory
    written_files_summary: Dict[str, List[str]] = {} # Store successfully written files per team
    if all_keyfiles_to_write:
        for keyfile in all_keyfiles_to_write:
            output_filepath = os.path.join(output_dir, keyfile.filename)
            try:
                with open(output_filepath, 'w') as f: f.write(keyfile.content)
                # Store successfully written file path, associating with bond device name
                # Infer bond name from filename (handle master and slave cases)
                base_filename = keyfile.filename.split('.')[0]
                if "-slave-" in base_filename:
                     bond_device_name = base_filename.split('-slave-')[1]
                else:
                     bond_device_name = base_filename # Assume it's the master bond file

                if bond_device_name not in written_files_summary:
                     written_files_summary[bond_device_name] = []
                written_files_summary[bond_device_name].append(output_filepath)
            except (IOError, OSError) as e:
                error_msg = f"Error writing file {output_filepath}: {e}"
                write_errors.append(error_msg) # Collect write errors

    # 7. Populate Processed Teams Summary for JSON Output
    # *** FIX: Ensure this loop runs only if teams were processed ***
    if team_configs: # Check if team_configs was populated
        for res in all_generation_results: # Now all_generation_results is guaranteed to exist if team_configs was not empty
            processed_teams_summary.append(ProcessedTeamInfo(
                team_device=res.team_device,
                bond_device=res.bond_device,
                generated_files=written_files_summary.get(res.bond_device, []) # Get files written for this bond
            ))

    # 8. Determine Final Status and Exit Code
    unique_warnings = sorted(list(set(all_warnings)))
    all_errors = fatal_errors + write_errors # fatal_errors is currently always empty here, only write_errors matter

    if all_errors:
        final_status = "fatal_error"
        final_exit_code = EXIT_FATAL_ERROR
    elif unique_warnings:
        final_status = "success_with_warnings"
        final_exit_code = EXIT_SUCCESS_WITH_WARNINGS
    else:
        final_status = "success"
        final_exit_code = EXIT_SUCCESS

    # 9. Construct Final JSON Output
    json_output = {
        "status": final_status,
        "output_directory": output_dir,
        "processed_teams": [info._asdict() for info in processed_teams_summary],
        "warnings": unique_warnings,
        "errors": all_errors,
    }

    # Print the final JSON result to stdout
    print(json.dumps(json_output, indent=2))

    # Exit with the appropriate code
    sys.exit(final_exit_code)


# Standard Python entry point check
if __name__ == "__main__": main()
