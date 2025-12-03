Готово — ниже полностью оформленный, чистый, профессиональный **README.md** на английском, как в настоящих инженерных репозиториях.
Можно просто скопировать и вставить в `README.md` в GitHub.

---

# 📘 **README.md**

```markdown
# AWS EC2 Security Group Sync Task

This repository contains a Python script that dynamically syncs the HTTP ingress rules of an EC2 instance's Security Group based on:
- A constant *home IP address* (`/32`), and  
- The current Cloudflare IPv4 ranges fetched from the official Cloudflare endpoint.

The script ensures that HTTP (port 80) is accessible **only** from:
1. The engineer’s home IP, and  
2. Cloudflare IP ranges  

while leaving SSH (port 22) fully open as required.

This task was completed for the 2bcloud DevOps home assignment.

---

## 📁 **Repository Structure**

```

aws-ec2-sg-sync-task/
├── sync_sg.py              # Main Python script
└── security-group.yaml     # YAML state file representing desired SG rules

````

---

## 🧠 **What the Script Does**

1. **Discovers AWS region dynamically**
   - Uses IMDSv2 (`instance-identity/document`)  
   - No hard-coded region

2. **Discovers Security Group ID dynamically**
   - Uses metadata path:
     `/meta-data/network/interfaces/macs/.../security-group-ids`
   - No hard-coded SG ID

3. **Fetches Cloudflare IPv4 IP ranges**
   - From: `https://www.cloudflare.com/ips-v4`

4. **Builds the desired HTTP CIDR set**
   - `{ HOME_IP_CIDR } ∪ Cloudflare_IPv4_Ranges`

5. **Synchronizes HTTP (80/tcp) rules**
   - Adds missing CIDRs
   - Removes stale CIDRs
   - Ensures idempotency: re-running script does not create duplicates

6. **Never modifies SSH rules**
   - SSH (`22/tcp`) remains `0.0.0.0/0` as required

7. **Updates the YAML file**
   - Writes the final desired state into `security-group.yaml`  
   - YAML mirrors the actual Security Group state

8. **Optionally commits and pushes updates**
   - If the script is executed inside a git repository

---

## 🛠️ **How to Run**

### **Prerequisites**
- Python 3.8+
- The following Python packages:
  ```bash
  pip install boto3 requests pyyaml
````

* AWS permission:

  * `ec2:DescribeSecurityGroups`
  * `ec2:AuthorizeSecurityGroupIngress`
  * `ec2:RevokeSecurityGroupIngress`

The script is intended to be run **from the EC2 instance itself**, so it automatically uses the instance’s IAM role.

---

## ▶️ **Run the Script**

From inside the EC2 instance:

```bash
chmod +x sync_sg.py
./sync_sg.py
```

Sample output:

```
[INFO] Starting SG sync script
[INFO] Home IP CIDR: 94.158.60.231/32
[INFO] Detected region: eu-west-1
[INFO] Detected Security Group ID from metadata: sg-XXXXXXXX
[INFO] Fetched 15 Cloudflare IPv4 ranges
[INFO] Current HTTP(80) CIDRs: 0
[INFO] Adding CIDRs: [...]
[INFO] YAML updated with desired HTTP CIDRs
```

---

## 🧩 **YAML State Structure (`security-group.yaml`)**

```yaml
name: security-group
rules:
  ssh:
    - 0.0.0.0/0
  http:
    - 94.158.60.231/32
    - 103.21.244.0/22
    - 103.22.200.0/22
    - ...
```

* `ssh` is **never** modified by the script
* `http` always reflects the exact desired state

---

## 🔒 **Idempotency**

The script is fully idempotent:

* Running it multiple times does **not** create duplicate rules
* State is always converged toward `{home IP} ∪ Cloudflare}`
* Differences are detected using set operations (`desired - current` and `current - desired`)

---

## 🌐 **Network Access Test**

From a machine whose IP matches the configured home IP:

```bash
curl -I http://2bcloud.io
```

Expected:

```
HTTP/1.1 200 OK
Server: nginx/1.28.0
...
```

If DNS does not yet point to the EC2 instance, the domain can be mapped locally using:

```
/etc/hosts
52.215.116.12   2bcloud.io
```

---

## ✨ **Key Features Summary**

* Dynamic region discovery
* Dynamic SG discovery
* IMDSv2 support
* Cloudflare IPv4 fetch
* HTTP-only SG synchronization
* Correct idempotent behavior
* YAML kept in sync with EC2 SG
* Optional git auto-commit & push
* Fully deterministic and reproducible

---

## 👨‍💻 **Author**

**Ahmad (absence77)**
DevOps Engineer
[https://github.com/absence77/aws-ec2-sg-sync-task](https://github.com/absence77/aws-ec2-sg-sync-task)


                         ┌───────────────────────────────────────────┐
                         │               EC2 Instance                 │
                         │     (Script executed inside instance)      │
                         └───────────────────────────────────────────┘
                                         │
                                         ▼
                       ┌────────────────────────────────────┐
                       │     IMDSv2 Metadata Service        │
                       │   169.254.169.254/latest/…        │
                       └────────────────────────────────────┘
                                         │
                                         ▼
            ┌────────────────────────────┬─────────────────────────────┐
            │                            │                             │
            ▼                            ▼                             ▼
┌─────────────────────┐      ┌────────────────────────┐     ┌─────────────────────────┐
│ Get Metadata Token  │      │ Get Region             │     │ Get Security Group IDs  │
│ PUT /api/token      │      │ instance-identity/... │     │ network/interfaces/...   │
└─────────────────────┘      └────────────────────────┘     └─────────────────────────┘
            │                            │                             │
            └─────────── Combined into EC2 runtime context ────────────┘
                                         │
                                         ▼
        ┌──────────────────────────────────────────────────────────┐
        │ Fetch Cloudflare IPv4 ranges                             │
        │ https://www.cloudflare.com/ips-v4                        │
        └──────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                          ┌───────────────────────────────────┐
                          │ Build “desired_HTTP_CIDRs” set:   │
                          │    { HOME_IP/32 } ∪ CF_RANGES     │
                          └───────────────────────────────────┘
                                         │
                                         ▼
                    ┌────────────────────────────────────────────┐
                    │ Read existing SG HTTP ingress (port 80)   │
                    │ boto3.describe_security_groups()          │
                    └────────────────────────────────────────────┘
                                         │
                                         ▼
                     ┌─────────────────────────────────────────────┐
                     │ Compute DIFF (idempotent):                  │
                     │   ADD = desired − current                   │
                     │   REMOVE = current − desired                │
                     └─────────────────────────────────────────────┘
                                         │
                                         ▼
               ┌──────────────────────────────────────────────┬─────────────────────────────────────┐
               │                                              │                                     │
               ▼                                              ▼                                     ▼
   ┌─────────────────────┐                        ┌─────────────────────────┐           ┌────────────────────────┐
   │ boto3.authorize…    │                        │ boto3.revoke…          │           │ Update YAML State File │
   │ Add missing CIDRs   │                        │ Remove stale CIDRs     │           │ security-group.yaml    │
   └─────────────────────┘                        └─────────────────────────┘           └────────────────────────┘
               │                                              │                                     │
               └───────────────────────── Converged SG State ───────────────────────────────────────┘
                                         │
                                         ▼
                       ┌────────────────────────────────────────┐
                       │ (Optional) git add / commit / push     │
                       │ Auto-push updated state to GitHub      │
                       └────────────────────────────────────────┘
                                         │
                                         ▼
                         ┌──────────────────────────────────────┐
                         │                 END                  │
                         └──────────────────────────────────────┘
