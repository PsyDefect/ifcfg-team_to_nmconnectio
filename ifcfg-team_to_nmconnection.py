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
- Includes a --verbose flag to control the display of detailed final instructions.
- Exits with specific codes (see --help for details).

*** This version writes the generated .nmconnection files to the directory
*** specified by the --output-dir argument (defaults to CWD). ***

The script focuses on a functional approach, separating parsing, generation logic,
and I/O operations. It outputs status messages and warnings to standard output/error
and writes the keyfiles to the specified output directory.
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
# Used in instructions for the user on where to move the generated files.
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
# (Data structures IfcfgConfig, Keyfile, GenerationResult, ParseResult, ParsedRoute remain unchanged)
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
    # Define epilog text for help message
    epilog_text = f"""
Exit Codes:
  {EXIT_SUCCESS}: Success without warnings.
  {EXIT_FATAL_ERROR}: Fatal error during setup (e.g., cannot access directories).
  {EXIT_SUCCESS_WITH_WARNINGS}: Success, but warnings were generated during processing.
"""
    parser = argparse.ArgumentParser(
        description="Convert RHEL ifcfg team configurations to NetworkManager bond keyfiles.",
        formatter_class=argparse.RawDescriptionHelpFormatter, # Use RawDescriptionHelpFormatter to preserve epilog formatting
        epilog=epilog_text # Add epilog to the help message
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
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", # Sets args.verbose to True if flag is present
        help="Print detailed instructions for next steps after writing files."
    )
    args = parser.parse_args() # Parse command-line arguments

    # Use parsed arguments for paths
    ifcfg_input_path = args.input_dir
    output_dir = args.output_dir

    # *** Print effective paths ***
    print(f"Using ifcfg script input path: {ifcfg_input_path}")
    print(f"Using output directory: {output_dir}")
    print("-" * 30)

    # *** Ensure output directory exists ***
    try:
        if not os.path.isdir(output_dir):
            print(f"Output directory '{output_dir}' does not exist. Creating it...")
            os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create output directory '{output_dir}': {e}", file=sys.stderr)
        sys.exit(EXIT_FATAL_ERROR) # Exit with fatal error code

    # 1. Scan for ifcfg files in the specified input directory
    try:
        all_files = os.listdir(ifcfg_input_path)
        ifcfg_filenames = [f for f in all_files
                           if os.path.isfile(os.path.join(ifcfg_input_path, f)) and f.startswith('ifcfg-')]
    except FileNotFoundError: print(f"Error: Network script input directory not found: {ifcfg_input_path}", file=sys.stderr); sys.exit(EXIT_FATAL_ERROR)
    except OSError as e: print(f"Error: Cannot access network script input directory {ifcfg_input_path}: {e}", file=sys.stderr); sys.exit(EXIT_FATAL_ERROR)
    print(f"Scanning {len(ifcfg_filenames)} ifcfg-* files in {ifcfg_input_path}...")

    # 2. Parse all found ifcfg files
    parse_results = [read_and_parse_ifcfg(os.path.join(ifcfg_input_path, f)) for f in ifcfg_filenames]

    # 3. Process parsing results
    valid_configs: Dict[str, IfcfgConfig] = {}; parsing_errors: List[str] = []
    for result in parse_results:
        if result.config is not None: key = result.config.get("DEVICE", result.filepath); valid_configs[key] = result.config
        elif result.error: parsing_errors.append(result.error)

    # 4. Identify team masters and map members
    team_configs: Dict[str, IfcfgConfig] = {}; member_map: Dict[str, List[Tuple[str, IfcfgConfig]]] = {}; member_assignment_warnings: List[str] = []
    for device_or_path, config in valid_configs.items():
        devicetype = config.get("DEVICETYPE", "").lower(); device = config.get("DEVICE")
        if devicetype == "team" and device: print(f"Found Team Master: {device}"); team_configs[device] = config; member_map[device] = []
    for device_or_path, config in valid_configs.items():
         team_master = config.get("TEAM_MASTER"); device = config.get("DEVICE")
         if team_master and device:
             if team_master in member_map: print(f"Found Member: {device} for Team: {team_master}"); member_map[team_master].append((device, config))
             else: member_assignment_warnings.append(f"Member {device} found for team {team_master}, but master config was not found or is invalid.")

    # 5. Generate keyfile content for each identified team
    all_generation_results: List[GenerationResult] = []; all_warnings: List[str] = parsing_errors + member_assignment_warnings; write_errors: List[str] = []
    if not team_configs: print("\nNo Team interfaces (DEVICETYPE=Team) found in valid ifcfg files.")
    else:
        print(f"\nGenerating NetworkManager keyfile content for {len(team_configs)} team(s)...")
        for team_device, master_config in team_configs.items():
            members = member_map.get(team_device, [])
            print(f"--- Processing Team: {team_device} ---")
            static_routes: List[ParsedRoute] = []
            route_filename = f"route-{team_device}"; route_filepath = os.path.join(ifcfg_input_path, route_filename) # Use input path
            if os.path.isfile(route_filepath):
                print(f"Found and parsing route file: {route_filepath}")
                parsed_routes, route_warnings = parse_route_file(route_filepath)
                if route_warnings: all_warnings.extend([f"[{team_device}/Routes] {w}" for w in route_warnings])
                if parsed_routes: print(f"  Found {len(parsed_routes)} static routes in {route_filename}."); static_routes = parsed_routes
            result = generate_single_keyfile_content(master_config, members, static_routes)
            all_generation_results.append(result)
            all_warnings.extend([f"[{result.team_device} -> {result.bond_device}] {w}" for w in result.warnings])

    # 6. Print Warnings (Consolidated)
    # Make warnings unique before printing
    unique_warnings = sorted(list(set(all_warnings)))
    if unique_warnings:
        print("\n" + "="*70); print("=== Warnings Encountered ==="); print("="*70)
        for warning in unique_warnings: print(f"- {warning}", file=sys.stderr)
        print("="*70)

    # 7. Write Keyfiles to Specified Output Directory
    all_keyfiles: List[Keyfile] = [kf for res in all_generation_results for kf in res.keyfiles]
    if all_keyfiles:
        print("\n" + "="*70); print(f"=== Writing Generated Keyfiles ==="); print(f"Output Directory: {output_dir}")
        print("Warning: Ensure you have write permissions in this directory."); print("="*70 + "\n")
        for keyfile in all_keyfiles:
            output_filepath = os.path.join(output_dir, keyfile.filename) # Use output_dir
            try:
                with open(output_filepath, 'w') as f: f.write(keyfile.content)
                print(f"Successfully wrote: {output_filepath}")
            except (IOError, OSError) as e: error_msg = f"Error writing file {output_filepath}: {e}"; print(error_msg, file=sys.stderr); write_errors.append(error_msg)

        # Print final instructions only if verbose flag is set
        if args.verbose: # *** Check verbose flag ***
            print("\n" + "="*70)
            if write_errors: print("=== File Writing Errors ==="); print("="*70); [print(f"- {error}", file=sys.stderr) for error in write_errors]; print("="*70 + "\n")
            print("=== Next Steps (Verbose) ==="); print("="*70); print("# IMPORTANT:")
            print(f"# 1. Review the generated '.nmconnection' files in '{output_dir}'.")
            print("#    **Verify that IP addresses, bond settings, AND static routes (if any) were converted correctly.**")
            print(f"# 2. If correct, move the generated files from '{output_dir}' to '{SYSTEM_NM_CONNECTIONS_DIR}'.")
            print(f"#    Example: sudo mv {os.path.join(output_dir, '*.nmconnection')} {SYSTEM_NM_CONNECTIONS_DIR}/")
            print(f"# 3. Ensure files in '{SYSTEM_NM_CONNECTIONS_DIR}' are owned by root:")
            print(f"#    `sudo chown root:root {SYSTEM_NM_CONNECTIONS_DIR}/*.nmconnection`")
            print(f"# 4. Ensure files have permissions 600:")
            print(f"#    `sudo chmod 600 {SYSTEM_NM_CONNECTIONS_DIR}/*.nmconnection`")
            print("# 5. Reload NetworkManager: `sudo nmcli connection reload`")
            print("# 6. Bring up the new connection: `sudo nmcli connection up <bond_con_name>` (e.g., 'bond0')")
            print("# 7. Verify connectivity and configuration (`ip route`, `nmcli d`, etc.).")
            print("# 8. Have console access during changes.")
            print(f"# 9. Back up '{ifcfg_input_path}' first.")
            print("# 10. After success, remove or archive old ifcfg and route-* files for the team/members.")
            print("="*70)
        else:
            # Provide minimal confirmation if not verbose
            print("\n" + "="*70)
            print("Keyfile generation complete. Files written to:", output_dir)
            if unique_warnings or write_errors:
                 print("NOTE: Warnings or errors were encountered during execution (see details above).")
            print("Run with -v or --verbose to see detailed next steps.")
            print("="*70)

    elif not team_configs: pass
    else: print("\nNo keyfile content was generated. Check warnings above for details.")

    # *** Final Exit Code Determination ***
    final_exit_code = EXIT_SUCCESS # Default to success
    if write_errors:
        # If file writing failed, it's arguably a fatal error for the script's goal
        print("\nExiting with error code due to file writing failures.", file=sys.stderr)
        final_exit_code = EXIT_FATAL_ERROR
    elif unique_warnings:
        # If warnings occurred but files were written (or no files needed writing)
        print("\nExiting with warning code.", file=sys.stderr)
        final_exit_code = EXIT_SUCCESS_WITH_WARNINGS
    else:
        # If no warnings and no write errors
        print("\nExiting successfully.")
        final_exit_code = EXIT_SUCCESS

    sys.exit(final_exit_code)


# Standard Python entry point check
if __name__ == "__main__": main()
