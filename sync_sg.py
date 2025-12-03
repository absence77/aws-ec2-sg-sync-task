#!/usr/bin/env python3
"""
EC2 Security Group HTTP Sync Script

High-level responsibilities:
- Discover AWS region and Security Group ID dynamically via IMDSv2 (no hard-coded values).
- Fetch Cloudflare IPv4 ranges from the official endpoint.
- Build the desired HTTP CIDR set: { HOME_IP_CIDR } ∪ { Cloudflare ranges }.
- Sync the EC2 Security Group rules for HTTP (80/tcp) to match this set.
- Keep SSH (22/tcp) open to 0.0.0.0/0 (do not touch SSH rules).
- Update a YAML file (security-group.yaml) so it mirrors the final desired HTTP sources.
- Optionally perform git add/commit/push if run inside a git repository.
"""

import os
import sys
import json
import logging
import subprocess
from datetime import datetime
from typing import List, Set

import boto3
import requests
import yaml

# ====== CONFIGURATION ======
# Your home IP /32 (treated as a constant according to the assignment requirements).
# This IP will always be allowed to access HTTP (port 80) on the EC2 instance.
HOME_IP_CIDR = "94.158.60.231/32"

# Path to the YAML file that represents the desired Security Group rules.
YAML_PATH = "security-group.yaml"

# Optional informational constant, not strictly required by the script logic.
# The script discovers region and SG dynamically from metadata instead.
INSTANCE_PUBLIC_IP = "52.215.116.12"

# ====== LOGGING SETUP ======
# Structured logging to make script behavior and decisions visible.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ====== IMDSv2 SUPPORT ======
# IMDSv2 requires us to first get a token via PUT, then use it in all metadata GET requests.
_metadata_token: str | None = None


def get_imds_token() -> str:
    """
    Retrieve and cache an IMDSv2 token.

    This function:
    - Sends a PUT request to the IMDSv2 token endpoint.
    - Uses a TTL of 6 hours (21600 seconds).
    - Caches the token in the module-level variable `_metadata_token`.

    Returns:
        A string token that must be sent in the X-aws-ec2-metadata-token header
        for subsequent metadata requests.
    """
    global _metadata_token
    if _metadata_token is not None:
        return _metadata_token

    url = "http://169.254.169.254/latest/api/token"
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    resp = requests.put(url, headers=headers, timeout=2)
    resp.raise_for_status()
    _metadata_token = resp.text
    return _metadata_token


def get_instance_metadata(path: str) -> str:
    """
    Read EC2 instance metadata using IMDSv2.

    This function:
    - Ensures we have a valid IMDSv2 token.
    - Sends a GET request to the metadata endpoint with the token header.
    - Raises HTTPError if metadata cannot be accessed.

    Args:
        path: Relative metadata path (e.g. "dynamic/instance-identity/document").

    Returns:
        The raw text content of the metadata response.
    """
    base_url = "http://169.254.169.254/latest"
    url = f"{base_url}/{path}"

    token = get_imds_token()
    headers = {"X-aws-ec2-metadata-token": token}

    resp = requests.get(url, headers=headers, timeout=2)
    resp.raise_for_status()
    return resp.text


def detect_region_from_metadata() -> str:
    """
    Discover the AWS region from the instance identity document.

    This avoids hard-coding the region and makes the script portable
    across different regions.

    Returns:
        The AWS region string (e.g. "eu-west-1").
    """
    doc = get_instance_metadata("dynamic/instance-identity/document")
    data = json.loads(doc)
    region = data["region"]
    logger.info(f"Detected region: {region}")
    return region


def detect_sg_id_from_metadata() -> str:
    """
    Discover the primary Security Group ID using instance metadata.

    Steps:
    - List all MAC addresses of network interfaces.
    - Pick the first MAC (sufficient for this single-SG use case).
    - Read the associated `security-group-ids`.
    - Use the first Security Group ID from that list.

    Returns:
        The Security Group ID string (e.g. "sg-0e7381ae7a120cc15").
    """
    macs = get_instance_metadata("meta-data/network/interfaces/macs/").strip().splitlines()
    if not macs:
        raise RuntimeError("No MACs found in metadata")

    # Take the first MAC address; we assume a single relevant network interface for this task.
    mac = macs[0].strip("/")
    path = f"meta-data/network/interfaces/macs/{mac}/security-group-ids"
    sg_ids = get_instance_metadata(path).strip().splitlines()
    if not sg_ids:
        raise RuntimeError("No Security Group IDs found in metadata")

    sg_id = sg_ids[0].strip()
    logger.info(f"Detected Security Group ID from metadata: {sg_id}")
    return sg_id


# ====== CLOUDFLARE RANGES ======
def fetch_cloudflare_ipv4_ranges() -> List[str]:
    """
    Fetch the current Cloudflare IPv4 ranges from the official URL.

    Returns:
        A list of CIDR strings representing Cloudflare IPv4 address ranges.
    """
    url = "https://www.cloudflare.com/ips-v4"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    ranges = [line.strip() for line in resp.text.splitlines() if line.strip()]
    logger.info(f"Fetched {len(ranges)} Cloudflare IPv4 ranges")
    return ranges


# ====== YAML STATE HANDLING ======
def load_yaml_rules(path: str) -> dict:
    """
    Load the YAML state file that represents the desired SG rules.

    Behavior:
    - If the file does not exist, return a default structure with:
      - SSH open to 0.0.0.0/0
      - an empty HTTP list
    - If the file exists, load it via PyYAML.

    Args:
        path: Path to the YAML file.

    Returns:
        A Python dict representing the YAML content.
    """
    if not os.path.exists(path):
        logger.warning(f"YAML file {path} not found, creating a new one with default SSH rule.")
        return {
            "name": "security-group",
            "rules": {
                "ssh": ["0.0.0.0/0"],
                "http": [],
            },
        }
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    # Handle the case where the YAML file exists but is empty (None).
    return data or {}


def save_yaml_rules(path: str, data: dict):
    """
    Persist the updated SG rules back to the YAML file.

    Args:
        path: Path to the YAML file.
        data: Dict containing updated SG rules to be written.
    """
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


# ====== EC2 / SECURITY GROUP OPERATIONS ======
def get_current_http_cidrs(ec2, sg_id: str) -> Set[str]:
    """
    Inspect the current HTTP (port 80) ingress CIDRs for the given Security Group.

    Args:
        ec2: Boto3 EC2 client.
        sg_id: The Security Group ID to inspect.

    Returns:
        A set of CIDR strings representing all current HTTP(80) ingress sources.
    """
    resp = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = resp["SecurityGroups"][0]
    cidrs: Set[str] = set()
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == "tcp" and perm.get("FromPort") == 80 and perm.get("ToPort") == 80:
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp")
                if cidr:
                    cidrs.add(cidr)
    logger.info(f"Current HTTP(80) CIDRs in SG {sg_id}: {len(cidrs)}")
    return cidrs


def sync_http_rules(ec2, sg_id: str, desired_cidrs: Set[str]):
    """
    Synchronize HTTP (port 80) ingress rules on the Security Group.

    Steps:
    - Read the current HTTP CIDRs.
    - Compute the desired vs current difference:
      - to_add    = desired - current
      - to_remove = current - desired
    - Call authorize_security_group_ingress for CIDRs to add.
    - Call revoke_security_group_ingress for CIDRs to remove.
    - Log the final HTTP CIDR count.

    This logic ensures idempotency: re-running the script converges the state
    toward the desired set without creating duplicates.
    """
    current_cidrs = get_current_http_cidrs(ec2, sg_id)

    to_add = desired_cidrs - current_cidrs
    to_remove = current_cidrs - desired_cidrs

    logger.info(f"Desired HTTP CIDRs: {len(desired_cidrs)}")
    logger.info(f"To add: {len(to_add)}, To remove: {len(to_remove)}")

    if to_add:
        logger.info(f"Adding CIDRs: {sorted(to_add)}")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in to_add],
            }]
        )

    if to_remove:
        logger.info(f"Removing CIDRs: {sorted(to_remove)}")
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in to_remove],
            }]
        )

    # Re-read HTTP rules after changes to log the final state.
    final_cidrs = get_current_http_cidrs(ec2, sg_id)
    logger.info(f"Final HTTP(80) CIDR count in SG {sg_id}: {len(final_cidrs)}")


def update_yaml(yaml_data: dict, desired_cidrs: Set[str]) -> dict:
    """
    Update the YAML data structure with the final desired CIDRs.

    Behavior:
    - Keep SSH rule as-is if present, otherwise default to 0.0.0.0/0.
    - Replace `rules.http` with the sorted list of desired CIDRs.

    Args:
        yaml_data: Existing YAML data structure.
        desired_cidrs: Final desired set of HTTP CIDRs.

    Returns:
        The updated YAML data structure.
    """
    if "rules" not in yaml_data:
        yaml_data["rules"] = {}

    # SSH rule is intentionally not touched beyond setting a safe default.
    ssh_rules = yaml_data["rules"].get("ssh", ["0.0.0.0/0"])
    yaml_data["rules"]["ssh"] = ssh_rules

    # HTTP list mirrors the final desired CIDRs (home IP + Cloudflare ranges).
    http_list = sorted(list(desired_cidrs))
    yaml_data["rules"]["http"] = http_list

    return yaml_data


# ====== GIT INTEGRATION (OPTIONAL) ======
def git_commit_and_push(message: str):
    """
    If the current directory is a git repository, perform add/commit/push.

    This is optional and will be skipped if:
    - `.git` directory is not present
    - or git commands fail for any reason.

    Args:
        message: Commit message to use if a commit is created.
    """
    if not os.path.isdir(".git"):
        logger.info("No .git directory found, skipping git commit/push.")
        return

    try:
        subprocess.run(["git", "add", YAML_PATH, "sync_sg.py"], check=True)
        subprocess.run(["git", "status"], check=False)

        subprocess.run(["git", "commit", "-m", message], check=True)
        subprocess.run(["git", "push"], check=True)
        logger.info("Git commit and push completed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git command failed: {e}")
        # Do not fail the main script because of git issues; just log the error.


# ====== MAIN ENTRYPOINT ======
def main():
    """
    Main orchestration function.

    Execution flow:
    1. Log startup and the configured home IP CIDR.
    2. Discover region and Security Group ID via IMDSv2.
    3. Initialize a regional EC2 client via boto3.
    4. Fetch Cloudflare IPv4 ranges.
    5. Build the desired CIDR set: { HOME_IP_CIDR } ∪ { Cloudflare ranges }.
    6. Sync the Security Group HTTP rules (port 80) to match the desired set.
    7. Load YAML state, update it to mirror the desired CIDRs, and save it.
    8. Optionally commit and push changes if run inside a git repository.
    """
    logger.info("Starting SG sync script")
    logger.info(f"Home IP CIDR: {HOME_IP_CIDR}")

    # 1. Detect AWS region and Security Group from instance metadata (no hard-coded values).
    region = detect_region_from_metadata()
    sg_id = detect_sg_id_from_metadata()

    session = boto3.Session(region_name=region)
    ec2 = session.client("ec2")

    # 2. Fetch Cloudflare IPv4 ranges.
    cf_ranges = fetch_cloudflare_ipv4_ranges()
    cf_set = set(cf_ranges)

    # 3. Build the desired HTTP CIDR set (home IP + Cloudflare).
    desired_cidrs = {HOME_IP_CIDR} | cf_set

    # 4. Synchronize Security Group HTTP(80) rules with the desired set.
    sync_http_rules(ec2, sg_id, desired_cidrs)

    # 5. Update YAML state to reflect the final desired HTTP sources.
    yaml_data = load_yaml_rules(YAML_PATH)
    yaml_data = update_yaml(yaml_data, desired_cidrs)
    save_yaml_rules(YAML_PATH, yaml_data)

    logger.info("YAML updated with desired HTTP CIDRs")

    # 6. Optionally perform git commit & push if this directory is a git repository.
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    git_message = f"Sync SG rules from script at {ts}"
    git_commit_and_push(git_message)


if __name__ == "__main__":
    # Entrypoint for the script when executed from the command line.
    main()
