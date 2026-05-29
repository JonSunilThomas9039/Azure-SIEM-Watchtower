# My First SOC Lab: Building a Mini-Detection Pipeline in Azure Sentinel

## 📌 Project Overview
As a hands-on learning project, I engineered a miniature **Security Operations Center (SOC)** detection pipeline from scratch. The goal was to simulate a three-stage attack sequence on a cloud target, capture the telemetry via an active collection agent, and configure a SIEM to aggregate the data and trigger alerts.

### The Attack Chain:
1. **Reconnaissance:** A multi-port automated scan.
2. **Compromise:** A successful administrative log-in over SSH.
3. **Action on Objective:** Exfiltrating host data out of the network via a web command.

---

## 🗺️ Part 1: The Initial Plan vs. Why It Failed

### The Original Objective (Watchlist Approach)
Our initial design strategy relied on utilizing **Azure Sentinel Watchlists** to handle tracking. The plan was to create a custom watchlist named `ScannedIPs` to serve as a persistent threat intelligence cache. 

When Rule 1 triggered, it was supposed to automatically compile the attacker's source IP address into this watchlist. Then, our subsequent rules would simply query that static list to find matches.

### The Initial KQL Drafts

* **Initial Rule 1 (Reconnaissance Search):**
  ```kusto
  Syslog
  | where TimeGenerated > ago(15m)
  | where ProcessName == "sshd" and SyslogMessage contains "Invalid user"
  ```
* **Initial Rule 2 (Access Validation utilizing Watchlist):**
  ```kusto
  let ScannedIPs = _GetWatchlist('ScannedIPs') | project SearchKey;
  Syslog
  | where TimeGenerated > ago(15m)
  | where Computer == "Victim-VM"
  | where SyslogMessage has "sshd" and SyslogMessage has "session opened"
  | extend LoginIP = HostIP
  | where LoginIP in (ScannedIPs)
  ```
* **Initial Rule 3 (Data Exfiltration Search):**
  ```kusto
  Syslog
  | where TimeGenerated > ago(15m)
  | where ProcessName == "curl"
  | where SyslogMessage contains "outbound connection initiated"
  ```

### Why the Initial Plan Failed
1. **The Watchlist Write Overhead:** In a basic testing lab without Logic Apps or advanced Microsoft Graph API playbooks configured, Sentinel cannot natively write or append raw IP strings to a Watchlist on the fly directly from an analytics rule query. The watchlist approach expected data to be there without a mechanism to input it automatically during the attack.
2. **The Ingestion Window Blindspot:** Setting a rigid 15-minute lookback loop (`ago(15m)`) for live scheduled analytics rules caused the queries to return zero results. This occurred because cloud pipelines suffer from systemic ingestion latency (the time it takes for a virtual machine agent to buffer, batch, transport, and index a log entry into the database). By the time Sentinel processed the query, the original log's timestamp sat outside the tight 15-minute execution net.
3. **Query Target Filtering Mismatches:** Our tracking queries were looking for alert headers prefixed with static naming conventions (e.g., `"Rule1:..."`, `"Rule2:..."`), but the actual rules were saved under clean display names. The query engine failed to find the missing prefix tags, returning blank tables.

---

## 🔄 Part 2: The Updated Operational Plan

To fix these structural failures, we shifted our strategy from a Watchlist framework to live **Multi-Stage Attack Correlation Engineering via Cross-Table Joins**. 

Instead of routing data through an external watchlist cache, the updated architecture leverages subqueries to dynamically pull recent events from the `SecurityAlert` table, parse the raw JSON data inside the SIEM on the fly, and project the results into our active `Syslog` evaluation line within an expanded time window.

📌 *Insert your overall resource infrastructure map here:* ![Azure Resource Group Components Layout](images/resource_group_layout.png)

---

## ⚡ Part 3: Security Rules Implementation & Final KQL

Here is the complete, finalized detection logic successfully deployed inside the Microsoft Sentinel Analytics engine:

### 🔍 Rule 1: Port Scan Detected
* **Goal:** Catch multiple rapid connection requests targeting invalid or alternative application ports from an external source within a brief window.
* **Live Test Execution String:**
  ```bash
  logger -t sshd "Invalid user admin from 10.0.0.5 port 21"
  logger -t sshd "Invalid user admin from 10.0.0.5 port 80"
  logger -t sshd "Invalid user admin from 10.0.0.5 port 443"
  ```
* **Production KQL Query:**
  ```kusto
  Syslog
  | where TimeGenerated > ago(50m)
  | where ProcessName == "sshd"
  | where SyslogMessage contains "Invalid user"
  | summarize Count = count() by Computer, HostIP
  | where Count >= 3
  ```

### 🔐 Rule 2: Successful Login After Scan
* **Goal:** Look back through the `SecurityAlert` table to isolate a confirmed "Port Scan Detected" event, dynamically parse out the attacker's source IP address entity using `todynamic()`, and verify if that identical IP successfully established an open SSH session inside the `Syslog` table.
* **Production KQL Query:**
  ```kusto
  let ScannedIPs = 
  SecurityAlert
  | where AlertName == "Port Scan Detected"
  | where TimeGenerated > ago(50m)
  | extend EntitiesDynamic = todynamic(Entities)
  | mvexpand EntitiesDynamic
  | extend AlertIP = tostring(EntitiesDynamic.Address)
  | where isnotempty(AlertIP)
  | project AlertIP;
  Syslog
  | where TimeGenerated > ago(50m)
  | where Computer == "Victim-VM"
  | where SyslogMessage has "sshd" and SyslogMessage has "session opened"
  | extend LoginIP = HostIP
  | where LoginIP in (ScannedIPs)
  | project TimeGenerated, Computer, LoginIP, SyslogMessage
  ```

📌 *Insert the image of your successful Rule 2 log output grid here:* ![Successful Cross-Table KQL Query Grid Output](images/rule2_kql_output.png)

### 🚨 Rule 3: Outbound Data Exfiltration
* **Goal:** Detect unauthorized outbound command signatures indicating staging and shipping protocols routing data out of the localized network interface card.
* **Live Test Execution String:**
  ```bash
  logger -t curl "outbound connection initiated to external backup server via curl"
  ```
* **Production KQL Query:**
  ```kusto
let CompromisedIPs = 
    SecurityAlert
    | where AlertName == "Post-Scan Successful Login"
    | where TimeGenerated > ago(50m)
    | extend EntitiesDynamic = todynamic(Entities)
    | mvexpand EntitiesDynamic
    | extend AlertIP = tostring(EntitiesDynamic.Address)
    | where isnotempty(AlertIP)
    | project AlertIP;
Syslog
| where TimeGenerated > ago(50m)
| where Computer == "Victim-VM" and (SyslogMessage has "curl" or SyslogMessage has "wget")
| extend ExfilIP = HostIP
| where ExfilIP in (CompromisedIPs)
| project TimeGenerated, Computer, ExfilIP, ExfilDetail = SyslogMessage
  ```

---

## ⚙️ Part 4: How We Set It All Up

### 1. Cloud Assets Provisioning
All infrastructure was anchored within a single Azure Resource Group named `Sentinel-Lab` to maintain a unified security boundary.
* **Target Architecture:** Deployed a standalone virtual machine running **Ubuntu 24.04 LTS** named `Victim-VM` (`Internal Private IP: 10.0.0.5`, `Public Routing IP: 20.249.208.213`).
* **SIEM Core Repository:** Provisioned a central **Log Analytics Workspace** (`Attacker-Victim-Logs`) and initialized **Microsoft Sentinel** on top of the instance to manage incident tracking.

### 2. The Telemetry Collection Pipeline
To stream kernel and user-space text events directly from the target operating system into the SIEM database, we configured an active collection pipeline:
* An Azure Monitor **Data Collection Endpoint (DCE)** was stood up to handle inbound agent data handshakes.
* A **Data Collection Rule (DCR)** named `Attacker-Victim-DCR` was engineered to explicitly map Linux OS event streams. 
* The default facility ingestion valves were changed from `None` to `LOG_DEBUG` across the **`LOG_AUTH`**, **`LOG_AUTHPRIV`**, and **`LOG_USER`** parameters. This enabled the workspace to explicitly index user-space execution blocks and system access validations.

📌 *Insert the image of your checked and active DCR facility boxes here:* ![Data Collection Rule Edit Data Source Facilities Panel](images/dcr_facilities_setup.png)

---

## 🛠️ Part 5: Mistakes Made & How They Were Rectified

### 1. The Regional Data Splitting Error
* **The Mistake:** Initial validation tests returned completely empty logs. The system agent was running, but no telemetry was hitting the SIEM database.
* **The Correction:** Discovered a regional mismatch during deployment—the core Log Analytics Workspace sat in **Korea Central**, but the active Data Collection Rule had been created inside **Central India**. The isolated India DCR was deleted, and a localized pipeline was engineered entirely inside Korea Central, fixing the broken pipeline routing.

### 2. The Network Security Group Inbound Locks
* **The Mistake:** Remote terminal initialization commands to the target public IP consistently timed out during connection handshakes.
* **The Correction:** Resolved two separate firewall configuration traps inside the Network Security Group (NSG):
  * **Source Port Range Block:** The inbound rule was originally restricted to source port `22`. It was adjusted to an asterisk (`*`) to allow incoming packets originating from the management machine's random high-numbered dynamic/ephemeral client ports.
  * **Post-NAT Destination Mismatch:** The firewall was initially configured to look for the public IP address as the destination. Because Azure's edge router performs Destination Network Address Translation (NAT) to `10.0.0.5` *before* hitting the NIC firewall, packets were dropped. The NSG rule destination parameter was modified to target `Any` to safely process the post-NAT packet state.

📌 *Insert your finalized firewall configuration layout here:* ![Network Security Group Inbound Security Rules Tab](images/nsg_rules_configuration.png)

### 3. Web Console Focus and Agent Queue Jams
* **The Mistake:** While attempting to fix local password variables on the VM, the Azure Portal UI became completely unresponsive, leaving the administrative "Run Command" panel frozen and greyed out.
* **The Correction:** Bypassed the browser presentation layer by opening the **Azure Cloud Shell** CLI and sending an explicit put-request directly to the Azure Resource Manager (ARM) API to rewrite system credentials:
  ```bash
  az vm user update -g Sentinel-Lab -n Victim-VM --username Jon --password "Hotwater12345"
  ```
  The internal configuration file was then patched to guarantee password handshakes remained active alongside public keys:
  ```bash
  sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
  sudo systemctl restart sshd
  ```

### 4. Local Workspace File Permission Fallbacks
* **The Mistake:** The local management notebook threw a critical warning (`WARNING: UNPROTECTED PRIVATE KEY FILE!`), ignored the private `.pem` key, and forced password authentication.
* **The Correction:** Linux systems default downloaded file states to permissions layout `0664`, which leaves keys readable by other local profiles. Run this local command to tighten file permissions so the SSH client accepts the key:
  ```bash
  chmod 400 Victim-VM-Pavillion_key.pem
  ```

### 5. The Analytics Engine Lookback Truncation
* **The Mistake:** Rule 2 successfully matched attack data during manual log hunting, but failed to trigger automatically as a scheduled rule.
* **The Correction:** Discovered a timing mismatch in the rule scheduler configuration wizard. The **"Lookup data from the last"** slider was set to a narrow 15 minutes, which cut off data before the cross-table KQL join could run. Changing the scheduling lookup setting in the analytics wizard to **50 minutes** successfully accounted for cloud ingestion latency, allowing the multi-stage correlation to trigger.
