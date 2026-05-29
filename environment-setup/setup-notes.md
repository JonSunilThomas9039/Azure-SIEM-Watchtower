# Cloud Infrastructure & Environment Setup Notes

This document provides a comprehensive technical log of the environment architecture built for this SOC lab, including resource provisioning, data streaming pipelines, and the structural networking and configuration challenges encountered during implementation.

---

## 🏗️ 1. Resource Provisioning & Architecture

To simulate a real-world enterprise attack and monitoring pipeline, the infrastructure was deployed within a unified Azure Resource Group named `Sentinel-Lab`. The architecture consists of four core building blocks:

1. **Victim-VM:** A standalone virtual machine running **Ubuntu 24.04 LTS** (`IP: 10.0.0.5`), acting as the primary target.
2. **Attacker-VM:** A separate Linux instance used to generate external simulation traffic.
3. **Log Analytics Workspace (LAW):** Named `Attacker-Victim-Logs`, serving as the central database repository where all raw telemetry is stored and indexed.
4. **Microsoft Sentinel:** Enabled on top of the LAW to act as the Cloud SIEM (Security Information and Event Management) orchestration and alerting engine.

👤 **Main Administrator Account Used:** `Jon`  
🌐 **Target Public IP Address:** `20.249.208.213`

📌 *Insert your overall resource infrastructure map here:* ![Azure Resource Group Components Layout](images/resource_group_layout.png)

---

## 🛑 2. Hardships Faced & Technical Rectifications

Building a cloud-native monitoring pipeline involves managing multiple overlapping layers of firewalls, translation protocols, and agent configurations. Below are the specific engineering hurdles encountered and resolved during setup:

### A. The Regional Disconnect (DCE & DCR Misalignment)
* **The Hardship:** After linking the Virtual Machine to the environment, custom terminal security logs were completely missing from the Log Analytics database tables. 
* **The Root Cause:** The resources were geographically split across separate cloud regions. The active **Data Collection Rule (DCR)** and Data Collection Endpoint (DCE) were mistakenly deployed in the *Central India* region, while the main Log Analytics Workspace sat in *Korea Central*. Because of this boundary split, the Azure Monitor Agent could not establish a valid ingestion handshake.
* **The Rectification:** The redundant Central India DCR was deleted. A localized Data Collection Rule named `Attacker-Victim-DCR` was engineered entirely within **Korea Central**, consolidating the pipeline fabric into a single geographic data lane.

### B. The Network Security Group (NSG) Source Port Trap
* **The Hardship:** SSH connections from the local management workstation directly to the Victim-VM timed out consistently, despite having an active "Allow SSH" firewall rule.
* **The Root Cause:** The inbound Network Security Group (NSG) rule was strictly configured with a Source Port Range of `22`. In networking, while a server listens on port `22`, a client operating system chooses a random, high-numbered dynamic/ephemeral port to originate outbound traffic. The firewall was dropping the inbound packets because they did not originate from port `22`.
* **The Rectification:** Modified the inbound NSG rule parameter, changing the **Source Port Range** to an asterisk (`*`) to accept incoming handshakes from any dynamic client port.

### C. The Post-NAT Destination Mismatch
* **The Hardship:** Even after correcting the source port range, Network Watcher diagnostic tools showed that incoming packets were still being dropped by the default `DenyAllInbound` security rule.
* **The Root Cause:** Azure’s routing edge performs Destination Network Address Translation (NAT). It converts the public IP address (`20.249.208.213`) into the private virtual network IP (`10.0.0.5`) *before* the traffic is handed to the NSG firewall rules on the NIC. The initial rule explicitly looked for a destination matching the public IP header, causing the post-NAT packet to fail validation.
* **The Rectification:** Updated the NSG rule's **Destination** field to target `Any` (or the explicit private subnet IP `10.0.0.5`), aligning the firewall check perfectly with the post-NAT packet structure.

📌 *Insert your finalized firewall configuration layout here:* ![Network Security Group Inbound Security Rules Tab](images/nsg_rules_configuration.png)

---

## ⚙️ 3. OS Hardening & Telemetry Valve Calibration

### A. Bypassing Web Portal UI Locks via ARM API
During configuration modifications, local user password permissions inside the VM needed an administrative reset. The standard Azure web console became unresponsive—the "Run Command" button locked up due to an interface focus-state glitch and a processing queue block on the internal Linux Guest Agent daemon (`waagent`).

* **The Rectification:** Bypassed the browser graphical interface completely by initializing the browser-integrated **Azure Cloud Shell** and issuing an explicit put-request using the Azure CLI to rewrite credentials directly via the core Azure Resource Manager (ARM) API:

```bash
az vm user update -g Sentinel-Lab -n Victim-VM --username Jon --password "Hotwater12345"
```

To prevent the background cloud extension from rolling back password capabilities during subsequent service recycles, a persistent backend shell patch was applied directly to the configuration file:

```bash
sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### B. Local Workstation Key Security Compliance
When testing connectivity using an asymmetric private key file (`.pem`) from a Linux workstation, the terminal threw an `UNPROTECTED PRIVATE KEY FILE!` warning and rejected the key. 

* **The Reason:** Linux file permissions default to `0664` upon download, leaving the key readable by other system processes. The local SSH client blocks usage of loose keys for safety, falling back to password prompt mode.
* **The Fix:** Enforced strict user-restricted read access permissions on the local host machine before executing the connection string:

```bash
chmod 400 Victim-VM-Pavillion_key.pem
```

### C. Opening the Syslog Facility Faucet
Initially, the `Syslog` database table inside the Log Analytics Workspace only showed internal Azure Linux Agent logs (`ExtHandler`), missing manual user commands. This was because the DCR's facility mapping matrix was configured to a minimum log level filter of `None`.

* **The Rectification:** Opened the main facility filter by setting the collection threshold to `LOG_DEBUG` across the workspace. The following distinct facilities were manually checked to capture attack data while omitting background system cron noise:
  * **`LOG_AUTH` / `LOG_AUTHPRIV`:** Captures authentication handshakes, `sshd` interactions, and `pam_unix` session creation events.
  * **`LOG_USER`:** Captures standard user-space command terminal payloads injected via the `logger` shell utility.

📌 *Insert the image of your checked and active DCR facility boxes here:* ![Data Collection Rule Facilities Setup](images/dcr_facilities_setup.png)
