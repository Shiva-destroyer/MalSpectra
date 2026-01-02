# Module 10: Worm Propagation Simulator

**Developer:** Sai Srujan Murthy  
**Contact:** saisrujanmurthy@gmail.com  
**Category:** Network Security | Malware Behavior Simulation

---

## Overview

The **Worm Propagation Simulator** is an educational tool for modeling and analyzing how network worms spread across computer networks. Using graph theory and epidemiological models, this module provides insights into malware propagation patterns, critical network nodes, and effective containment strategies.

### What is a Computer Worm?

A **computer worm** is a standalone malware program that replicates itself to spread to other computers. Unlike viruses, worms do not need to attach themselves to existing programs. They exploit vulnerabilities in network protocols or operating systems to propagate automatically.

**Famous Worm Examples:**
- **Morris Worm (1988)**: First Internet worm, infected ~10% of Internet
- **Code Red (2001)**: Infected 359,000 servers in < 14 hours
- **SQL Slammer (2003)**: Peak infection in ~10 minutes
- **Conficker (2008)**: Infected 9-15 million computers
- **WannaCry (2017)**: Ransomware worm, 200,000+ victims globally

---

## Features

### 1. Network Topology Generation

Create realistic network structures:

#### **Random Networks (Erdős-Rényi)**
- Nodes connect with uniform probability
- Models ad-hoc networks
- Good for baseline simulations

#### **Scale-Free Networks (Barabási-Albert)**
- Power-law degree distribution
- Models real Internet topology
- Few "hub" nodes with many connections
- Most nodes have few connections

#### **Small-World Networks (Watts-Strogatz)**
- High clustering, short path lengths
- Models corporate/campus networks
- Local clusters with long-range shortcuts

### 2. SIR Epidemic Model

The simulator implements the **SIR (Susceptible-Infected-Recovered)** epidemiological model:

```
S → I → R
```

**States:**
- **S (Susceptible)**: Vulnerable to infection
- **I (Infected)**: Currently infected, can spread to neighbors
- **R (Recovered)**: Patched/immune, cannot be re-infected

**Transition Equations:**

```
dS/dt = -β × S × I / N
dI/dt = β × S × I / N - γ × I
dR/dt = γ × I
```

Where:
- `β` = infection rate (transmission probability)
- `γ` = recovery rate (patching probability)
- `N` = total population

### 3. Metrics Tracked

- **Total Infected**: Cumulative infection count
- **Peak Infected**: Maximum simultaneous infections
- **Infection Rate**: Percentage of network compromised
- **Average Infection Time**: Mean time to infection
- **R0 (Basic Reproduction Number)**: Expected infections per infected node

### 4. Network Analysis

#### **Betweenness Centrality**

Identifies critical nodes for worm spread:

```
Centrality(v) = Σ (σst(v) / σst)
```

Where:
- `σst` = total shortest paths from s to t
- `σst(v)` = shortest paths passing through v

**High centrality nodes are:**
- Network "bridges"
- Critical for propagation
- Priority targets for defense

---

## Usage

### Basic Workflow

1. **Launch Module**
   ```bash
   python3 main.py
   Select: 10 (Worm Propagation Simulator)
   ```

2. **Configure Parameters**
   - Network Size: 50-200 nodes
   - Topology: Random/Scale-Free/Small-World
   - Infection Rate: 10%-70%
   - Recovery Rate: 0%-10%

3. **Run Simulation**
   - Watch real-time propagation
   - View infection metrics
   - Analyze critical nodes

4. **Review Results**
   - Infection statistics
   - Network topology analysis
   - Security recommendations

### Example Output

```
═══ Network Topology Statistics ═══
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Metric            ┃ Value      ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Total Nodes       │ 100        │
│ Total Edges       │ 245        │
│ Average Degree    │ 4.90       │
│ Network Density   │ 0.0495     │
│ Connected         │ Yes        │
│ Diameter          │ 8          │
│ Avg Path Length   │ 3.24       │
└───────────────────┴────────────┘

Basic Reproduction Number (R0): 1.47 (Epidemic will spread)

═══ Simulation Progress ═══
  Step  0: I:  1 | S: 99 | R:  0
  Step  5: I: 12 | S: 88 | R:  0
  Step 10: I: 34 | S: 66 | R:  0
  Step 15: I: 61 | S: 39 | R:  0
  Step 20: I: 85 | S: 15 | R:  0
  Step 25: I: 94 | S:  6 | R:  0
  Step 30: I: 98 | S:  2 | R:  0

═══ Infection Statistics ═══
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Metric             ┃ Value   ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Total Nodes        │ 100     │
│ Total Infected     │ 98      │
│ Infection Rate     │ 98.0%   │
│ Peak Infected      │ 98      │
│ Peak Step          │ 30      │
│ Avg Infection Time │ 14.32   │
└────────────────────┴─────────┘

Assessment: CRITICAL
Worm achieved near-total network penetration

═══ Critical Network Nodes ═══
┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Rank ┃ Node ID ┃ Centrality Score  ┃ Impact      ┃
┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│  1   │   42    │ 0.1523            │ 🔴 CRITICAL │
│  2   │   17    │ 0.1289            │ 🔴 CRITICAL │
│  3   │   88    │ 0.1104            │ 🔴 CRITICAL │
│  4   │   55    │ 0.0876            │ 🟡 HIGH     │
│  5   │   31    │ 0.0654            │ 🟡 HIGH     │
└──────┴─────────┴───────────────────┴─────────────┘
```

---

## Mathematical Background

### R0 (Basic Reproduction Number)

The **basic reproduction number** predicts epidemic behavior:

```
R0 = β × k̄ / γ
```

Where:
- `β` = infection rate (per contact)
- `k̄` = average degree (connections per node)
- `γ` = recovery rate

**Interpretation:**
- **R0 > 1**: Epidemic spreads
- **R0 = 1**: Endemic equilibrium
- **R0 < 1**: Epidemic dies out

**Example:**
```
Network: 100 nodes, avg degree = 5
Infection rate = 30%
Recovery rate = 0% (no patching)

R0 = 0.30 × 5 / 0.01 = 150 (massive spread)
```

### Network Density

```
Density = 2E / (N × (N-1))
```

Where:
- `E` = number of edges
- `N` = number of nodes

**Impact on Spread:**
- High density → Faster spread
- Low density → Slower, contained spread

### Average Shortest Path Length

```
L = (1 / (N × (N-1))) × ΣΣ d(i,j)
```

Where `d(i,j)` = shortest path between nodes i and j

**Significance:**
- Small L → Rapid global spread
- Large L → Slow propagation

---

## Defense Strategies

### 1. Network Segmentation

**Goal:** Increase average path length, reduce density

**Implementation:**
- Divide network into isolated segments
- Use VLANs and firewalls
- Limit inter-segment connections
- Implement DMZ zones

**Effect:** Reduces R0, contains outbreaks

### 2. Critical Node Protection

**Goal:** Secure high-centrality nodes first

**Implementation:**
- Identify critical nodes (betweenness centrality)
- Priority patching for critical systems
- Enhanced monitoring on hub nodes
- Redundancy for critical services

**Effect:** Breaks propagation paths

### 3. Rapid Patching (Recovery Rate)

**Goal:** Increase γ (recovery rate)

**Implementation:**
- Automated patch management
- Fast vulnerability scanning
- Emergency patching procedures
- Patch testing infrastructure

**Effect:** Reduces infection window, lowers R0

### 4. Reducing Attack Surface (Infection Rate)

**Goal:** Decrease β (infection rate)

**Implementation:**
- Disable unnecessary services
- Firewall strict rules
- Network access control (NAC)
- Principle of least privilege

**Effect:** Makes transmission harder

### 5. Topology Optimization

**Goal:** Design worm-resistant networks

**Implementation:**
- Avoid hub-and-spoke topologies
- Minimize network diameter
- Regular topology audits
- Controlled redundancy

**Effect:** Limits propagation potential

---

## Real-World Case Studies

### Case 1: SQL Slammer (2003)

**Network Model:** Scale-Free (Internet)

**Parameters:**
- Infection Rate: ~90% (vulnerable MS SQL servers)
- Recovery Rate: ~5% (slow patching)
- R0: ≈ 2.0-3.0

**Timeline:**
- t=0: First infection
- t=10min: 75,000 infected
- t=30min: Peak 75,000 infections/sec

**Lessons:**
1. Rapid scanning = fast spread
2. Scale-free networks amplify spread
3. Small payloads spread faster (376 bytes)

**Defense Failures:**
- Patch available 6 months before
- No network segmentation
- Vulnerable UDP 1434 open

### Case 2: Morris Worm (1988)

**Network Model:** Small-World (Early Internet)

**Parameters:**
- Infection Rate: ~25% (multiple exploits)
- Recovery Rate: ~1% (manual cleanup)
- R0: ≈ 1.5-2.0

**Timeline:**
- t=0: Release from MIT
- t=15h: 10% of Internet infected (6,000 machines)
- t=72h: Cleanup begins

**Lessons:**
1. Multi-vector attacks increase β
2. Aggressive scanning causes DoS
3. No kill switch = uncontrolled spread

**Defense Successes:**
- Manual patching eventually stopped it
- Community cooperation
- Network partitioning helped contain

### Case 3: WannaCry (2017)

**Network Model:** Mixed (Global corporate networks)

**Parameters:**
- Infection Rate: ~40% (EternalBlue exploit)
- Recovery Rate: ~10% (AV + patching)
- R0: ≈ 2.0-4.0

**Timeline:**
- t=0: Initial infections
- t=12h: 230,000 infected in 150 countries
- t=24h: Kill switch activated (accidental)

**Lessons:**
1. NSA exploits in civilian hands
2. Unpatched systems = vulnerable
3. Kill switch domain registration stopped spread

**What Went Right:**
- Fast patch deployment
- Network segmentation limited damage
- Security researcher found kill switch

---

## Advanced Topics

### Targeted vs Random Infection

**Random Infection:**
- Worm picks targets randomly
- Slower initial spread
- Eventually covers network

**Targeted Infection:**
- Preferential attachment to high-degree nodes
- Rapid initial spread
- More efficient propagation

**Simulation Comparison:**
```
Random:   R0 = β × k̄ / γ
Targeted: R0 = β × k² / k̄γ  (much larger!)
```

### Adaptive Worms

Modern worms employ strategies:

1. **Hit-List Scanning**: Pre-compiled vulnerable target list
2. **Permutation Scanning**: Coordinate across infected nodes
3. **Topological Scanning**: Use local network info
4. **Subnet Scanning**: Prefer nearby addresses

**Impact:** Can achieve peak infection in < 10 minutes

### Network Immunization Strategies

**Random Immunization:**
- Patch random nodes
- Requires high coverage (>80%)

**Targeted Immunization:**
- Patch high-degree nodes first
- Requires only ~30% coverage for R0<1

**Acquaintance Immunization:**
- Ask random nodes for high-degree neighbors
- Patch neighbors
- Effective without global topology knowledge

---

## Limitations

### Simulation Limitations

1. **Simplified Model**: Real networks more complex
2. **Homogeneous Contacts**: Assumes all connections equal
3. **No Geographic Distance**: Ignores latency
4. **Perfect Information**: Nodes know all neighbors
5. **Static Topology**: Network doesn't change

### Real-World Complexity

- NAT/Firewalls create hidden topology
- Multi-stage infections (lateral movement)
- Human intervention (shutting down systems)
- Competing worms/patches
- Zero-day vs known vulnerabilities

---

## Educational Use Cases

### 1. Network Security Training

- Visualize attack propagation
- Understand topology impact
- Test defense strategies

### 2. Incident Response Planning

- Model outbreak scenarios
- Identify critical assets
- Practice containment

### 3. Risk Assessment

- Estimate infection timelines
- Calculate potential damage
- Justify security investments

### 4. Research

- Test new defense mechanisms
- Compare topology strategies
- Develop mathematical models

---

## Technical Implementation

### Dependencies

- **NetworkX**: Graph theory library
- **Rich**: Terminal UI
- **Python 3.8+**: Core language

### Key Classes

**NetworkTopology:**
- `create_network(nodes, topology)`: Generate graph
- `get_network_stats(graph)`: Calculate metrics

**WormSimulator:**
- `simulate_step(step, β, γ)`: Single propagation step
- `simulate_full(max_steps, β, γ)`: Complete simulation
- `get_infection_statistics()`: Final metrics

**WormAnalyzer:**
- `compare_topologies()`: Multi-topology comparison
- `calculate_r0(β, k, γ)`: Compute reproduction number

### Performance

- **50 nodes**: < 1 second
- **100 nodes**: < 2 seconds
- **200 nodes**: < 5 seconds
- **500 nodes**: ~15 seconds

---

## References

### Academic Papers

1. **Pastor-Satorras & Vespignani (2001)**: "Epidemic Spreading in Scale-Free Networks"
2. **Moore et al. (2003)**: "Inside the Slammer Worm"
3. **Staniford et al. (2002)**: "How to 0wn the Internet in Your Spare Time"
4. **Zou et al. (2003)**: "Monitoring and Early Warning for Internet Worms"

### Books

- **Anderson & May**: "Infectious Diseases of Humans"
- **Newman**: "Networks: An Introduction"
- **Barabási**: "Network Science"

### Online Resources

- CERT Coordination Center: https://www.cert.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- SANS Internet Storm Center: https://isc.sans.edu/

---

## Future Enhancements

- [ ] **3D Network Visualization**: Real-time propagation display
- [ ] **Multi-Worm Competition**: Simulate competing malware
- [ ] **Geographic Modeling**: Add latency and distance
- [ ] **Active Defense Simulation**: Model IDS/IPS interventions
- [ ] **Machine Learning**: Predict outbreak patterns
- [ ] **Export to SIEM**: Generate IoC feeds

---

## Conclusion

The Worm Propagation Simulator provides a safe, educational environment for understanding how network worms spread and how to defend against them. By modeling realistic network topologies and using established epidemiological models, users can gain intuition about:

- **What makes networks vulnerable**
- **Which nodes are critical**
- **How fast outbreaks occur**
- **Which defenses are most effective**

**Remember:** Simulation insights should guide real-world security strategies, but always validate in production environments with proper testing.

---

**Module Status:** ✅ Production Ready  
**Last Updated:** January 2026  
**Version:** 1.0 FINAL
