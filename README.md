# Cybersecurity Projects

This repository contains 4 cybersecurity learning tasks implemented in Python and documented for local testing. 
Each task is separated into its own folder so it is easy to run, review, and explain.

> Important: Run these tools only on your own machine, your own lab network, or an environment where you have explicit permission. Packet capture and intrusion detection can expose sensitive network data, so i am not responsible if u face something bad during trying this in bad way

## Phishing awerness presentation ( task 4 )
a mini presentation about the phishing awerness here is a canva link to see th presentation
```text
[https://canva.link/tw6jes8k74ik16c](https://canva.link/p9o1ltnh2kv21ow)
```


## Project Structure

```text
cyber/
  task1_sniffer/
    sniffer.py
    sniffer_tutorial.ipynb

  task2_secure_review/
    init_db.py
    vulnerable_app.py
    secure_app.py
    secure_coding_review.md
    secure_coding_review.ipynb

  task3_ids/
    python_ids.py
    ids_rules.json
    suricata_setup_guide.md
    ids_guide.ipynb
```

## Task Completion Summary

| Task | Folder | Status | What Was Implemented |
| --- | --- | --- | --- |
| Basic Network Sniffer | `task1_sniffer/` | Python packet sniffer using Scapy. It captures visible network packets and prints source IP, destination IP, protocol, ports, and payload preview. |
| Secure Coding Review | `task2_secure_review/` | Flask login lab with a vulnerable SQL injection version, a secure fixed version, database setup script, and a written secure coding review report. |
| Network Intrusion Detection System | `task3_ids/` |  Python-based educational IDS with JSON rules, alerts, simulated response mechanism, alert logging, and a Suricata setup guide for a real IDS tool. |

## Requirements

- Python 3.10 or newer
- Administrator/root privileges for packet sniffing tasks
- Npcap installed on Windows for Scapy packet capture
- A local lab network or local machine for safe testing

Install Python dependencies:

```bash
pip install -r requirements.txt
```

If you prefer a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

On Linux/macOS, activate the virtual environment with:

```bash
source venv/bin/activate
```

## Task 1: Basic Network Sniffer

### Location

```text
task1_sniffer/sniffer.py
```

### Objective

This task builds a Python program that captures visible network packets and displays useful information about each packet. It helps explain how data flows through a network and introduces common protocols such as TCP, UDP, and ICMP.

### What Is Done

- Captures packets using Scapy.
- Checks whether each packet has an IP layer.
- Displays source IP and destination IP.
- Detects TCP, UDP, and ICMP traffic.
- Displays TCP/UDP source and destination ports.
- Shows a short payload preview when raw payload data exists.
- Handles permission errors and keyboard interruption.

### How To Test

Open a terminal as Administrator on Windows, then run:

```bash
cd task1_sniffer
python sniffer.py
```

While it is running, generate normal network traffic, for example:

```bash
ping 8.8.8.8
```

You can also open a browser and visit a website.

### What You Should Notice

The terminal should show packet lines similar to:

```text
[IP] 192.168.1.10 -> 8.8.8.8 | Protocol: ICMP
[IP] 192.168.1.10 -> 142.250.190.14 | Protocol: TCP (52344 -> 443)
```

You may not see traffic from every device on the network. On most modern switched or encrypted networks, your machine mainly sees its own traffic and some broadcast traffic.

## Task 2: Secure Coding Review

### Location

```text
task2_secure_review/
```

### Objective

This task audits a small Flask login application written in Python with SQLite. It demonstrates SQL injection in a vulnerable version, then fixes the issue using secure coding practices.

### What Is Done

- `init_db.py` creates a SQLite users database.
- `vulnerable_app.py` contains an intentionally vulnerable login form.
- `secure_app.py` contains the remediated login form.
- `secure_coding_review.md` documents the vulnerability, impact, recommendations, and remediation steps.
- The vulnerable app uses unsafe SQL string formatting.
- The secure app uses parameterized SQL queries.
- The secure app checks hashed passwords using Werkzeug.
- The secure app returns generic login errors instead of exposing database errors.

### How To Test

First initialize the database:

```bash
cd task2_secure_review
python init_db.py
```

Run the vulnerable app:

```bash
python vulnerable_app.py
```

Open:

```text
http://127.0.0.1:5001
```

Try a normal login:

```text
Username: admin
Password: admin123
```

Then try a SQL injection login in the vulnerable app:

```text
Username: admin' OR '1'='1' --
Password: anything
```

Stop the vulnerable app, then run the secure app:

```bash
python secure_app.py
```

Open:

```text
http://127.0.0.1:5002
```

Try the same normal login and SQL injection payload.

### What You Should Notice

In the vulnerable app:

- Normal credentials log in successfully.
- The SQL injection payload can bypass authentication.
- The executed SQL query is displayed for learning purposes.
- Database errors may be shown to the user.

In the secure app:

- Normal credentials still work.
- The SQL injection payload does not bypass authentication.
- Passwords are verified using password hashes.
- The user sees generic error messages.

## Task 3: Network Intrusion Detection System

### Location

```text
task3_ids/
```

### Objective

This task implements an educational network-based intrusion detection system. It monitors visible network packets, checks them against rules, generates alerts, writes alerts to a log file, and simulates a response mechanism.

### What Is Done

- `python_ids.py` monitors packets using Scapy.
- `ids_rules.json` stores detection rules and thresholds.
- Detects possible TCP SYN scan behavior.
- Detects possible ICMP ping flood behavior.
- Detects plaintext credential keywords in packet payloads.
- Writes alerts to `ids_alerts.log`.
- Simulates active response by adding suspicious IPs to an in-memory blacklist.
- `suricata_setup_guide.md` explains how to set up Suricata for a real IDS environment.

### How To Test

Open a terminal as Administrator on Windows, then run:

```bash
cd task3_ids
python python_ids.py
```

To generate ICMP traffic from another terminal:

```bash
ping 127.0.0.1
```

For stronger ICMP testing, use a safe local lab host that you own or control.

To test plaintext credential detection, run the vulnerable Flask app from Task 2 and submit a login over plain HTTP while the IDS is running.

### What You Should Notice

When suspicious traffic matches a rule, the terminal should display an alert similar to:

```text
[ALERT] [HIGH] Plaintext Credentials in Transit Detected | Source IP: 127.0.0.1 | Details: ...
```

The IDS should also write alert lines to:

```text
task3_ids/ids_alerts.log
```

The response mechanism is a simulation. It does not change the real Windows firewall. It stores suspicious IPs in memory and ignores later packets from those IPs while the script is running.

### Suricata Note

The Python IDS is useful for learning and demonstration. For a real network-based IDS, use Suricata or Snort. This project includes a Suricata guide here:

```text
task3_ids/suricata_setup_guide.md
```

## Recommended Testing Order

1. Install dependencies.
2. Run Task 2 database initialization.
3. Test the vulnerable Flask app.
4. Test the secure Flask app.
5. Run the packet sniffer.
6. Run the Python IDS.
7. Read the secure coding report and Suricata guide.


Replace `YOUR_USERNAME` and `YOUR_REPOSITORY` with your real GitHub username and repository name.
