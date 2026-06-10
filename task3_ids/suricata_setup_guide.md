# Enterprise Network Intrusion Detection (NIDS) Setup Guide: Suricata

While a Python-based NIDS is ideal for customization and educational projects, production networks rely on robust compiled NIDS engines like **Suricata** or **Snort**. 

This guide details how to install, configure, write custom rules for, and visualize alerts using Suricata.

---

## 1. What is Suricata?
Suricata is a high-performance, open-source Network Threat Detection engine capable of:
- **Intrusion Detection (IDS)**: Analyzing traffic and logging anomalies.
- **Intrusion Prevention (IPS)**: Dropping malicious packets inline (active response).
- **Network Security Monitoring (NSM)**: Logging protocol sessions, transactions, and file extractions.

---

## 2. Installation on Windows

1. **Download the Installer**:
   - Navigate to the official [Suricata Downloads](https://suricata.io/download/) page.
   - Download the Windows MSI installer package (e.g., `Suricata-X.X.X-64.msi`).

2. **Run the Installer**:
   - Double-click the MSI file and complete the installation wizard.
   - By default, Suricata installs to `C:\Program Files\Suricata`.

3. **Install packet drivers**:
   - Ensure **Npcap** is installed on your Windows machine with "Install Npcap in WinPcap API-compatible mode" enabled.

4. **Verify Path variables**:
   - Open Command Prompt as Administrator and run:
     ```cmd
     suricata --build-info
     ```
   - If not found, add `C:\Program Files\Suricata` to your System Environment variables PATH.

---

## 3. Configuration (`suricata.yaml`)

Suricata is configured using a YAML file located at `C:\Program Files\Suricata\suricata.yaml` (or the folder where you installed it).

### Step 1: Set home network variables
Inside `suricata.yaml`, find the `vars` section and set your local subnet:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24]" # Change to your network CIDR
    EXTERNAL_NET: "!$HOME_NET"
```

### Step 2: Configure Network interface
Select your sniffing network card interface. Run the command:
```cmd
suricata --list-nics
```
Find the UUID or Name of your active interface (e.g., `\Device\NPF_{...}`), and configure it in the `pcap` section of `suricata.yaml`:
```yaml
pcap:
  - interface: "\\Device\\NPF_{YOUR_NIC_UUID}"
```

---

## 4. Configuring Suricata Alert Rules

Rules are written in files with a `.rules` extension, typically stored in the `rules` subdirectory (e.g., `C:\Program Files\Suricata\rules\local.rules`).

### Rule Syntax Breakdown
A Suricata rule consists of a header and options:
```text
[action] [protocol] [source ip] [source port] -> [dest ip] [dest port] ([rule options])
```

### Example Rules for `local.rules`:
Open `local.rules` and write these signatures:

1. **Detecting ICMP flood (Ping attack)**:
   ```text
   alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP Flood Attempt Detected"; icode:0; itype:8; threshold: type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)
   ```

2. **Detecting Plaintext Password Submissions over HTTP**:
   ```text
   alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"HTTP Plaintext Password Transit"; content:"POST"; http_method; content:"passwd="; nocase; sid:1000002; rev:1;)
   ```

3. **Detecting TCP SYN Scan (Port Scanning)**:
   ```text
   alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TCP SYN Scan Detection"; flags:S; threshold: type threshold, track by_src, count 30, seconds 5; sid:1000003; rev:1;)
   ```

To activate your custom rules file, make sure the path `local.rules` is registered in the `rule-files` list in `suricata.yaml`:
```yaml
rule-files:
  - local.rules
```

---

## 5. Running Suricata

To run Suricata in IDS detection mode on your network card, execute the following in an Administrator Command Prompt:
```cmd
suricata -c suricata.yaml -i \Device\NPF_{YOUR_NIC_UUID}
```
Outputs are written to `C:\Program Files\Suricata\log\`:
- `fast.log`: Simple one-line text alerts.
- `eve.json`: Highly detailed JSON formatted event stream containing matches, flow transactions, and metadata.

---

## 6. Visualizing Alerts & Dashboard Setup

Reading raw json files can be tedious. In enterprise environments, Suricata is paired with tools to visualize traffic:

### Option A: EveBox (Recommended for quick setups)
[EveBox](https://evebox.org/) is a lightweight, open-source dashboard application specifically designed to parse and view Suricata `eve.json` events.
1. Download EveBox.
2. Run it pointing to your logs:
   ```cmd
   evebox -e C:\Program Files\Suricata\log\eve.json
   ```
3. Open a browser to `http://localhost:5636` to see a rich interface showing severity graphs, alerts, IP maps, and packet info.

### Option B: ELK Stack (Elasticsearch, Logstash, Kibana)
For advanced deployments, alerts are pushed from Suricata to an Elasticsearch instance:
1. **Filebeat**: Install Filebeat on the Suricata server and enable the `suricata` module to forward `eve.json` alerts.
2. **Elasticsearch**: Indexes and searches log data.
3. **Kibana**: Provides pre-built dashboards showing:
   - Alert maps (geolocating attacker IPs).
   - Bar charts of rules triggered.
   - Timeline flows of protocol events.
