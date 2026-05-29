# My First SOC Lab: Building a Mini-Detection Pipeline in Azure Sentinel

## 📌 Project Overview
As a hands-on learning project, I built a miniature **Security Operations Center (SOC)** detection pipeline from scratch. The goal was to simulate a basic three-stage attack sequence on a cloud target, capture the activity, and configure a SIEM to recognize and flag the behavior.

### The Attack Chain:
1. **Reconnaissance:** A multi-port automated scan.
2. **Compromise:** A successful administrative log-in over SSH.
3. **Objective:** Exfiltrating host data out of the network via a web command.

---

## 🛠️ Part 1: Infrastructure & Environment Setup

This section outlines how the lab environment was built and the specific configuration barriers encountered while getting cloud data to flow smoothly.

### 1. The Virtual Network & Outer Edge NAT Issue
The target machine is a standalone **Ubuntu 24.04 LTS** virtual machine. When first attempting to verify connectivity from my local laptop terminal via SSH, connections consistently timed out. Two specific cloud networking rules were causing the block:

* **The Ephemeral Source Port Oversight:** The inbound Network Security Group (NSG) rule was initially configured to look for a restricted source port of `22`. Because a client operating system initiates an outbound connection using a random high-numbered dynamic/ephemeral port, the firewall dropped it.
  * **The Fix:** Changed the *Source Port Range* to an asterisk (`*`) to accept connections originating from any dynamic client port.
* **The Post-NAT Destination Misalignment:** Azure’s routing fabric performs Network Address Translation (NAT) at the cloud edge. This automatically converts the VM's public IP (`20.249.208.213`) into its internal private IP (`10.0.0.5`) before it hits the network interface card (NIC). The initial firewall rule was validating the public IP destination *after* this translation had already occurred.
  * **The Fix:** Updated the *Destination* field to target `Any` or the explicit private address space (`10.0.0.5`) so it successfully passed the internal validity check.

> 💡 **Network Packet Flow:**
> `[Laptop Client]` ──(Ephemeral Port)──> `[Azure Edge Router (NAT)]` ──(Translates to Private IP)──> `[NSG Rules Check]` ──> `[Victim-VM]`

### 2. Overriding Web Portal System Locks
While adjusting authentication variables, local user password configurations needed a reset. The standard Azure web console became unresponsive—the "Run" button froze due to an interface focus-state glitch and a queue lock on the underlying Linux Guest Agent daemon (`waagent`).

* **The Fix:** Bypassed the browser graphical user interface completely by initializing the **Azure Cloud Shell** terminal and running an explicit put-request using the Azure CLI to rewrite the credentials directly via the core ARM API:
  ```bash
  az vm user update -g Sentinel-Lab -n Victim-VM --username Jon --password "Hotwater12345"
