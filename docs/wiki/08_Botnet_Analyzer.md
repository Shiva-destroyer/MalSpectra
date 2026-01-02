# Module 8: Botnet Traffic Analyzer

## Overview

The Botnet Traffic Analyzer is a network forensics tool that analyzes PCAP (Packet Capture) files to detect botnet command-and-control (C2) communication patterns. It identifies malicious network behavior including Domain Generation Algorithms (DGA), suspicious port usage, and periodic beaconing indicative of bot-to-C2 server communication.

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Status**: Production Ready 📡 Requires Scapy

---

## What is a Botnet?

### Definition

A **botnet** is a network of compromised computers (bots/zombies) controlled by an attacker (botmaster) through a command-and-control (C2) infrastructure. Botnets are used for:

- DDoS attacks
- Spam distribution
- Cryptocurrency mining
- Credential theft
- Ransomware deployment

### C2 Communication

Bots communicate with C2 servers to:
1. Receive commands
2. Exfiltrate data
3. Update malware
4. Report status (beaconing)

---

## Features

- **DGA Detection**: Identify Domain Generation Algorithm activity
- **Suspicious Port Analysis**: Detect known malware ports
- **Beacon Detection**: Find periodic C2 check-ins
- **PCAP Support**: Analyze `.pcap` and `.pcapng` files
- **Progress Indicators**: Rich progress bars during analysis
- **Threat Intelligence**: Actionable security recommendations

---

## Technical Details

### Components

#### 1. pcap_engine.py (PCAPAnalyzer Class)

**Purpose**: Core PCAP analysis engine

**Key Methods**:

- `load_pcap(file_path)`: Load packet capture file
- `detect_high_frequency_dns()`: Find DGA activity
- `detect_suspicious_ports()`: Identify malware ports
- `detect_beacons()`: Discover periodic connections
- `analyze_pcap(file_path)`: Complete analysis workflow

**Dependencies**: scapy, collections, datetime

#### 2. main.py (User Interface)

**Purpose**: Interactive PCAP analyzer

**Features**:
- File selection with preview
- Rich progress bars
- Tabular threat reports
- Color-coded threat levels
- Actionable recommendations

---

## Detection Techniques

### 1. DGA (Domain Generation Algorithm) Detection

**What is DGA?**

Domain Generation Algorithms are used by malware to dynamically generate domain names for C2 servers, making blacklist-based blocking ineffective.

**Example DGA Domains**:
```
asdkfjhaskdjfh.com
qwerzxcvbnmasdf.net
lkjhgfdsaqwerty.org
```

**Detection Algorithm**:

```python
1. Count DNS queries per source IP
   ↓
2. Calculate queries per minute
   ↓
3. If queries/minute > 50:
   → Flag as DGA activity
```

**Why 50 queries/minute?**

- Normal browsing: 1-10 queries/minute
- DGA malware: 50-1000 queries/minute
- Malware rapidly tries generated domains until one resolves

**Detection Code**:

```python
dns_queries = defaultdict(list)

for packet in packets:
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        src_ip = packet[IP].src
        query_name = packet[DNSQR].qname
        timestamp = float(packet.time)
        dns_queries[src_ip].append({'query': query_name, 'timestamp': timestamp})

# Calculate queries per minute
time_span = queries[-1]['timestamp'] - queries[0]['timestamp']
queries_per_minute = (len(queries) / time_span) * 60

if queries_per_minute > 50:
    # DGA detected!
```

**Real-World DGA Families**:

- **Conficker**: Generates 50,000 domains/day
- **Cryptolocker**: 1,000 domains/day
- **Zeus GameOver**: Time-based DGA
- **Necurs**: Multi-stage DGA

---

### 2. Suspicious Port Detection

**Known Malware Ports**:

| Port | Protocol | Malware/Service |
|------|----------|-----------------|
| 6667 | TCP | IRC (Traditional botnet C2) |
| 6666 | TCP | IRC Alternative |
| 4444 | TCP | Metasploit/RATs |
| 31337 | TCP | BackOrifice (Elite Hack) |
| 12345 | TCP | NetBus |
| 1234 | TCP | SubSeven |
| 9999 | TCP | Generic RAT |
| 8080 | TCP | HTTP Proxy/C2 |

**Detection Method**:

```python
for packet in packets:
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        if dst_port in SUSPICIOUS_PORTS:
            # Log connection
            log_suspicious_connection(src_ip, dst_ip, dst_port)
```

**Why These Ports?**

- **6667 (IRC)**: Traditional botnet C2 protocol
- **4444**: Default Metasploit reverse shell port
- **31337**: "Elite" in leetspeak, historical malware favorite
- **8080**: Common alternative HTTP port for C2

**Legitimate Uses**:

Some ports (like 8080) have legitimate uses, so context matters:
- Internal dev servers on 8080
- Corporate proxies
- Test environments

---

### 3. Beacon Detection

**What is Beaconing?**

Beaconing is periodic communication from a bot to its C2 server to:
- Check for new commands
- Report status ("I'm alive")
- Request configuration updates

**Characteristics**:

- **Periodic**: Connections at regular intervals
- **Consistent**: Same interval (e.g., every 60 seconds)
- **Persistent**: Continues over long periods

**Detection Algorithm**:

```
1. Track connection timestamps per IP pair
   ↓
2. Calculate time intervals between connections
   ↓
3. Compute average interval and standard deviation
   ↓
4. If std_dev < 2 seconds AND interval > 10 seconds:
   → Beacon detected
```

**Mathematical Analysis**:

```python
# Time intervals between connections
intervals = [t[i+1] - t[i] for i in range(len(timestamps)-1)]

# Average interval
avg_interval = sum(intervals) / len(intervals)

# Standard deviation
variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
std_dev = variance ** 0.5

# Beacon if consistent interval
if avg_interval > 10 and std_dev < 2:
    # This is beaconing!
```

**Example Beacon Patterns**:

- **TrickBot**: Beacons every 60 seconds
- **Emotet**: Beacons every 10-30 minutes
- **Cobalt Strike**: Default 60-second beacon
- **Metasploit**: Configurable (default 5 seconds)

**Visual Example**:

```
Normal Traffic:
|--10s--|-----25s-----|--3s-|--------40s--------|--1s-|

Beacon Traffic:
|--60s--|--60s--|--60s--|--60s--|--60s--|--60s--|
   ↑        ↑        ↑        ↑        ↑        ↑
Consistent intervals = SUSPICIOUS
```

---

## Usage

### Prerequisites

```bash
# Install scapy
pip install scapy

# May also need libpcap
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel     # RedHat/CentOS
```

### Basic Workflow

```bash
# 1. Start MalSpectra
python3 main.py

# 2. Select Module 8 (Botnet Analyzer)

# 3. Enter PCAP file path

# 4. Review threat intelligence report
```

### Example Session

```
═══ BOTNET TRAFFIC ANALYZER ═══
C2 Communication Detection

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com

Select PCAP File

Available PCAP files in data/:
  [1] test_traffic.pcap (45.23 KB)
  [2] capture_2025.pcap (128.50 KB)

Enter PCAP file path: data/capture_2025.pcap

✓ Selected file: data/capture_2025.pcap

Initializing PCAP analyzer...
✓ Analyzer ready

Analyzing network traffic...

⠋ Loading PCAP file...
⠙ Detecting DGA activity...
⠹ Scanning for suspicious ports...
⠸ Analyzing beacon patterns...

✓ Analysis complete

══════════════════════════════════════════════════════════════════

Analysis Statistics:

  • Total Packets Analyzed: 45,328
  • DGA Indicators: 2
  • Suspicious Port Connections: 5
  • C2 Beacons: 3
  • Overall Threat Level: CRITICAL

══════════════════════════════════════════════════════════════════

1. DGA (Domain Generation Algorithm) Detection
✗ THREAT DETECTED - 2 suspicious host(s)

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Source IP    ┃ Total Queries┃ Queries/Min ┃ Unique Domains ┃ Threat ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ 192.168.1.50 │ 1,234        │ 87.52       │ 456            │ HIGH   │
│ 192.168.1.75 │ 856          │ 62.31       │ 312            │ HIGH   │
└──────────────┴──────────────┴─────────────┴────────────────┴────────┘

Sample domains queried:
  192.168.1.50:
    • akjdhfkjashdf.com
    • zxcvbnmasdfgh.net
    • qwertyuioplkj.org
    • mnbvcxzaqwert.com
    • lkjhgfdsapoiu.net

────────────────────────────────────────────────────────────────────

2. Suspicious Port Detection
✗ THREAT DETECTED - 5 suspicious connection(s)

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Source IP    ┃ Destination IP┃ Packets┃ Ports ┃ Description      ┃ Threat   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ 192.168.1.50 │ 45.67.89.123  │ 234    │ 4444  │ Metasploit/RAT   │ CRITICAL │
│ 192.168.1.50 │ 45.67.89.123  │ 156    │ 6667  │ IRC (Botnet C2)  │ HIGH     │
│ 192.168.1.75 │ 98.76.54.321  │ 89     │ 31337 │ BackOrifice      │ CRITICAL │
└──────────────┴───────────────┴────────┴───────┴──────────────────┴──────────┘

────────────────────────────────────────────────────────────────────

3. C2 Beacon Detection
✗ THREAT DETECTED - 3 beacon(s) detected

┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃ Source IP    ┃ Destination IP┃ Connections┃ Avg Interval┃ Duration┃ Threat ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ 192.168.1.50 │ 45.67.89.123  │ 45         │ 60.00s      │ 2,700s  │ HIGH   │
│ 192.168.1.75 │ 98.76.54.321  │ 30         │ 120.50s     │ 3,615s  │ HIGH   │
└──────────────┴───────────────┴────────────┴─────────────┴─────────┴────────┘

Periodic connections indicate C2 check-ins

══════════════════════════════════════════════════════════════════

╔═══════════════════════════════════════╗
║   Threat Intelligence Report          ║
╠═══════════════════════════════════════╣
║ THREAT LEVEL: CRITICAL                ║
║                                       ║
║ Active botnet traffic detected!       ║
║ Immediate investigation required.     ║
╚═══════════════════════════════════════╝

Recommended Actions:

  • DGA Activity Detected:
    → Investigate source hosts for malware infection
    → Block suspicious domains at DNS level
    → Check for known DGA patterns

  • Malware Port Activity:
    → Block suspicious ports at firewall
    → Scan affected hosts for malware
    → Review firewall logs for more connections

  • C2 Beaconing Detected:
    → Isolate infected hosts immediately
    → Block destination IPs
    → Analyze malware samples on infected hosts

  • General recommendations:
    → Run full antivirus scan on affected systems
    → Check IOCs against threat intelligence feeds
    → Review firewall and IDS/IPS logs
    → Consider network segmentation
```

---

## Use Cases

### 1. Incident Response
Analyze captured traffic from suspected compromised networks.

### 2. Threat Hunting
Proactively search for botnet indicators in network traffic.

### 3. Forensic Analysis
Post-incident analysis to understand attack timeline and scope.

### 4. Security Monitoring
Regular PCAP analysis as part of security operations.

### 5. Malware Analysis
Study malware C2 communication patterns in sandbox.

---

## Creating Test PCAPs

### Using tcpdump

```bash
# Capture on interface eth0
sudo tcpdump -i eth0 -w capture.pcap

# Capture DNS traffic only
sudo tcpdump -i eth0 port 53 -w dns_only.pcap

# Capture for specific duration (60 seconds)
sudo timeout 60s tcpdump -i eth0 -w timed_capture.pcap
```

### Using Wireshark

1. Open Wireshark
2. Select network interface
3. Click "Start Capturing"
4. After collection, File → Save As → capture.pcap

### Sample PCAP Sources

- **Wireshark Samples**: https://wiki.wireshark.org/SampleCaptures
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **PacketLife**: https://packetlife.net/captures/

---

## Advanced Analysis

### DGA Family Identification

Different DGA families have distinct patterns:

```python
def identify_dga_family(domains):
    # Conficker: Long alphanumeric domains
    if all(len(d) > 20 for d in domains[:10]):
        return "Possible Conficker"
    
    # Cryptolocker: Specific TLDs
    tlds = [d.split('.')[-1] for d in domains]
    if set(tlds) == {'.com', '.net', '.org'}:
        return "Possible Cryptolocker"
    
    return "Unknown DGA"
```

### Beacon Jitter Analysis

Some malware adds randomness (jitter) to beacons:

```python
# Calculate jitter percentage
jitter = (std_dev / avg_interval) * 100

if jitter < 5:
    return "Precise beacon (likely automated)"
elif jitter < 20:
    return "Moderate jitter (evasion attempt)"
else:
    return "High jitter or irregular traffic"
```

### Protocol Analysis

Extend analysis to application protocols:

```python
def analyze_http_c2(packet):
    if packet.haslayer(HTTP):
        # Check User-Agent
        if 'User-Agent' in packet[HTTP].headers:
            ua = packet[HTTP].headers['User-Agent']
            if is_suspicious_ua(ua):
                log_suspicious_http(packet)
```

---

## Limitations

### Technical Limitations

- **Encrypted Traffic**: Cannot analyze HTTPS without TLS decryption
- **Large Files**: Memory-intensive for multi-GB PCAPs
- **False Positives**: Legitimate software may trigger alerts
- **Snapshot**: Only analyzes provided PCAP, not live traffic

### Detection Gaps

- **Slow DGA**: Malware using low query rates may evade detection
- **Non-Standard Ports**: C2 on common ports (80, 443) harder to detect
- **Irregular Beacons**: Randomized intervals evade beacon detection
- **Tunneling**: C2 over DNS or ICMP may bypass some checks

---

## Performance Optimization

### For Large PCAPs

```python
# Process in chunks
def analyze_large_pcap(file_path, chunk_size=10000):
    packets = rdpcap(file_path)
    for i in range(0, len(packets), chunk_size):
        chunk = packets[i:i+chunk_size]
        analyze_chunk(chunk)
```

### Memory Management

```python
# Use packet generator instead of loading all
from scapy.utils import PcapReader

with PcapReader(file_path) as pcap_reader:
    for packet in pcap_reader:
        process_packet(packet)
```

---

## Integration with SIEM

### Export to Splunk

```python
import json

def export_to_splunk(results):
    for finding in results['dga_detection']['findings']:
        event = {
            'timestamp': time.time(),
            'source': 'MalSpectra',
            'event_type': 'DGA_DETECTED',
            'src_ip': finding['ip'],
            'queries_per_minute': finding['queries_per_minute']
        }
        print(json.dumps(event))
```

### Export to ElasticSearch

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['localhost:9200'])

def index_findings(results):
    for finding in results['beacon_detection']['findings']:
        es.index(index='malspectra-beacons', body=finding)
```

---

## Troubleshooting

### "scapy is not installed"

**Solution**:
```bash
pip install scapy

# If errors occur:
sudo apt-get install python3-scapy
```

### "Permission denied" when reading PCAP

**Cause**: File permissions  
**Solution**:
```bash
chmod 644 capture.pcap
```

### "Failed to load PCAP"

**Causes**:
- Corrupted file
- Invalid format
- Partial capture

**Solution**: Try opening in Wireshark to verify integrity

### Memory Error with Large PCAPs

**Solution**: Use streaming or chunked processing

---

## References

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **PCAP Format**: https://wiki.wireshark.org/Development/LibpcapFileFormat
- **DGA Research**: https://www.endgame.com/blog/technical-blog/detecting-dgas-machine-learning
- **Beacon Detection**: https://www.sans.org/reading-room/whitepapers/detection/detecting-beaconing-malware-33778
- **Botnet Analysis**: https://www.cert.org/insider-threat/blog/posts/botnet-detection.cfm

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Botnet Traffic Analyzer  
**Version**: 1.0  
**Status**: 📡 Production Ready - Requires Scapy
