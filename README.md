# ifcfg Team to NetworkManager Bond Converter

## Overview

This Python script facilitates the migration of network configurations on RHEL 8+ systems from the legacy `ifcfg`/`network-scripts` format using `teamd` interfaces to the modern NetworkManager native bonding format using keyfiles (`.nmconnection`).

It reads `ifcfg` files defining team masters and their members, along with associated static route files (`route-*`), parses the relevant parameters, and generates corresponding NetworkManager keyfiles for bond interfaces.

**Note:** This script generates configuration files but **does not** apply them to the system automatically. Careful review and manual application steps are required.

## Features

* **Team to Bond Conversion:** Translates `DEVICETYPE=Team` configurations to NetworkManager `type=bond` connections.
* **Member Handling:** Identifies `TEAM_MASTER` entries in member `ifcfg` files and creates corresponding slave connections.
* **Runner/Mode Mapping:** Maps common `teamd` runner names (e.g., `activebackup`, `lacp`) to NetworkManager bond modes (e.g., `active-backup`, `802.3ad`).
* **IP Configuration:** Handles both static (`BOOTPROTO=static` or `none`) and DHCP (`BOOTPROTO=dhcp`) configurations.
* **IP Alias Support:** Parses and includes multiple IPv4 addresses defined using `IPADDRn`/`PREFIXn` or `IPADDRn`/`NETMASKn` conventions within the master `ifcfg` file.
* **Static Route Handling:** Parses IPv4 static routes from corresponding `route-<teamN>` files (specifically the `ADDRESS/PREFIX via NEXT_HOP [metric METRIC]` format) and adds them to the bond master keyfile.
* **Command-Line Arguments:** Allows specifying input and output directories.
* **Verbose Output:** Provides detailed instructions via a `--verbose` flag.
* **Exit Codes:** Returns specific exit codes to indicate success, success with warnings, or fatal errors.

## Requirements

* Python 3.x (typically standard on RHEL 8+)
* Standard Python libraries: `os`, `re`, `json`, `sys`, `ipaddress`, `uuid`, `argparse` (no external packages needed).
* Read access to the input directory containing `ifcfg`/`route` files.
* Write access to the specified output directory.

## Usage

```bash
python <script_name>.py [options]
```

## Command-Line Arguments:

* `-h`, `--help`: Show the help message and exit.
* `-i INPUT_DIR`, `--input-dir INPUT_DIR`: Directory containing the source ifcfg-* and route-* files. (Default: /etc/sysconfig/* network-scripts/)
* `-o OUTPUT_DIR`, `--output-dir OUTPUT_DIR`: Directory where generated *.nmconnection keyfiles will be written. (Default: .)
* `-v`, `--verbose`: Print detailed instructions for next steps after writing files.

## Examples:

1. Process default system path, output to ./nm_files, show detailed instructions:
```bash
python team_to_bond_converter.py -o ./nm_files -v
```
1. Process files from a test directory, output to ./converted_configs:
```bash
python team_to_bond_converter.py -i /tmp/test_ifcfg -o ./converted_configs
```
## Input Files

The script expects to find files in the specified `--input-dir` with the following naming conventions and relevant content:
* `ifcfg-<team_device>`: Defines the team master (e.g., `ifcfg-team0`). Must contain `DEVICETYPE=Team`, `DEVICE=<team_device>`, `TEAM_CONFIG`, IP configuration (`BOOTPROTO`, `IPADDRn`, `PREFIXn`/`NETMASKn`, `GATEWAY`, `DNSn`), etc.
* `ifcfg-<member_device>`: Defines member interfaces (e.g., `ifcfg-eth0`). Must contain `DEVICE=<member_device>` and `TEAM_MASTER=<team_device>`.
* `route-<team_device>`: (Optional) Defines static IPv4 routes for the team interface (e.g., `route-team0`). The script specifically parses lines in the format `ADDRESS/PREFIX via NEXT_HOP [metric METRIC]`.

## Output

The script generates NetworkManager keyfiles (`.nmconnection`) in the specified `--output-dir` (defaults to the current directory).
* One file is created for each bond master (e.g., `bond0.nmconnection`).
* One file is created for each member interface designated as a slave (e.g., `eth0-slave-bond0.nmconnection`).

The script prints status messages during processing, lists any warnings encountered (e.g., unparseable lines, missing parameters) to standard error, and confirms which files were successfully written.

## Workflow / Next Steps

After running the script successfully:
1. **Review Generated Files:** Carefully examine the `.nmconnection` files created in the output directory. Verify IP addresses, bond modes, member interfaces, static routes, and other settings.
1. **Backup:** Ensure you have backed up your existing `/etc/sysconfig/network-scripts/` directory and potentially `/etc/NetworkManager/system-connections/`.
1. **Move Files:** If the generated files are correct, move them to the NetworkManager system connections directory:
```bash
sudo mv /path/to/output_dir/*.nmconnection /etc/NetworkManager/system-connections/
```
1. **Set Permissions:** Ensure the files have the correct ownership and permissions:
```bash
sudo chown root:root /etc/NetworkManager/system-connections/*.nmconnection
sudo chmod 600 /etc/NetworkManager/system-connections/*.nmconnection
```
1. **Reload NetworkManager:** Apply the new configuration:
```bash
sudo nmcli connection reload
```
1. **Activate Connection(s):** Bring up the new bond interface(s):
```bash
sudo nmcli connection up <bond_connection_name> # e.g., bond0
```
1. **Verify:** Thoroughly check network connectivity, IP configuration (`ip addr`), routing (`ip route`), and NetworkManager status (`nmcli device status`, `nmcli connection show`).
1. **Cleanup (Optional but Recommended):** Once you are certain the new bond configuration is working correctly and persists after reboot, you can remove or archive the old `ifcfg-*` and `route-*` files for the converted team interfaces and their members from `/etc/sysconfig/network-scripts/` to avoid potential conflicts.

*Use the --verbose flag when running the script to see these steps printed.*

## Exit Codes

The script uses the following exit codes:
* `0`: Success without warnings.
* `1`: Fatal error during setup (e.g., cannot access input/output directories).
* `3`: Success, but warnings were generated during processing (check stderr output).

## Limitations
* **Route Parsing:** Only parses IPv4 static routes in the specific `ADDRESS/PREFIX via NEXT_HOP [metric METRIC]` format from `route-<interface>` files. Does not handle `route6-<interface>` files or other route formats. `default` routes in route files are ignored.
* **ifcfg Complexity:** May not handle all possible obscure or non-standard `ifcfg` parameters.
* `TEAM_CONFIG`: Primarily parses the `runner.name` from the JSON. Other complex team configurations within the JSON might not be fully translated.
* **Error Handling:** While it attempts to catch common errors and generate warnings, edge cases in file formats might not be handled gracefully.