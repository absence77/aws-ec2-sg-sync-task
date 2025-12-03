#!/usr/bin/env python3
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

# ====== НАСТРОЙКИ ======
# Твой домашний IP /32 (по условию задачи — константа)
HOME_IP_CIDR = "94.158.60.231/32"

# Путь к YAML-файлу
YAML_PATH = "security-group.yaml"

# (Не обязателен, оставим для информации)
INSTANCE_PUBLIC_IP = "52.215.116.12"

# ====== ЛОГИ ======
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ====== IMDSv2 SUPPORT ======
_metadata_token = None


def get_imds_token() -> str:
    """
    Получаем токен для IMDSv2.
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
    Чтение metadata с поддержкой IMDSv2.
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
    Берём region из instance-identity-document.
    """
    doc = get_instance_metadata("dynamic/instance-identity/document")
    data = json.loads(doc)
    region = data["region"]
    logger.info(f"Detected region: {region}")
    return region


def detect_sg_id_from_metadata() -> str:
    """
    Берём Security Group через metadata → mac → security-group-ids.
    """
    macs = get_instance_metadata("meta-data/network/interfaces/macs/").strip().splitlines()
    if not macs:
        raise RuntimeError("No MACs found in metadata")

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
    url = "https://www.cloudflare.com/ips-v4"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    ranges = [line.strip() for line in resp.text.splitlines() if line.strip()]
    logger.info(f"Fetched {len(ranges)} Cloudflare IPv4 ranges")
    return ranges


# ====== YAML ======
def load_yaml_rules(path: str) -> dict:
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
    return data or {}


def save_yaml_rules(path: str, data: dict):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


# ====== EC2 / SG ======
def get_current_http_cidrs(ec2, sg_id: str) -> Set[str]:
    resp = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = resp["SecurityGroups"][0]
    cidrs = set()
    for perm in sg.get("IpPermissions", []):
        if perm.get("IpProtocol") == "tcp" and perm.get("FromPort") == 80 and perm.get("ToPort") == 80:
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp")
                if cidr:
                    cidrs.add(cidr)
    logger.info(f"Current HTTP(80) CIDRs in SG {sg_id}: {len(cidrs)}")
    return cidrs


def sync_http_rules(ec2, sg_id: str, desired_cidrs: Set[str]):
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

    # Перечитаем для логов итоговое количество
    final_cidrs = get_current_http_cidrs(ec2, sg_id)
    logger.info(f"Final HTTP(80) CIDR count in SG {sg_id}: {len(final_cidrs)}")


def update_yaml(yaml_data: dict, desired_cidrs: Set[str]) -> dict:
    # SSH правило не трогаем
    if "rules" not in yaml_data:
        yaml_data["rules"] = {}

    ssh_rules = yaml_data["rules"].get("ssh", ["0.0.0.0/0"])
    yaml_data["rules"]["ssh"] = ssh_rules

    http_list = sorted(list(desired_cidrs))
    yaml_data["rules"]["http"] = http_list

    return yaml_data


# ====== GIT ======
def git_commit_and_push(message: str):
    """
    Если текущая директория — git-репозиторий, делаем add/commit/push.
    Если нет — просто логируем и пропускаем.
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
        # Не валим скрипт, просто лог.



# ====== MAIN ======
def main():
    logger.info("Starting SG sync script")
    logger.info(f"Home IP CIDR: {HOME_IP_CIDR}")

    # 1. detect region & SG from metadata (динамически, без хардкода)
    region = detect_region_from_metadata()
    sg_id = detect_sg_id_from_metadata()

    session = boto3.Session(region_name=region)
    ec2 = session.client("ec2")

    # 2. fetch Cloudflare ranges
    cf_ranges = fetch_cloudflare_ipv4_ranges()
    cf_set = set(cf_ranges)

    # 3. desired CIDRs
    desired_cidrs = {HOME_IP_CIDR} | cf_set

    # 4. sync SG HTTP(80)
    sync_http_rules(ec2, sg_id, desired_cidrs)

    # 5. update YAML
    yaml_data = load_yaml_rules(YAML_PATH)
    yaml_data = update_yaml(yaml_data, desired_cidrs)
    save_yaml_rules(YAML_PATH, yaml_data)

    logger.info("YAML updated with desired HTTP CIDRs")

    # 6. git commit & push (если это git-репозиторий)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    git_message = f"Sync SG rules from script at {ts}"
    git_commit_and_push(git_message)


if __name__ == "__main__":
    main()

