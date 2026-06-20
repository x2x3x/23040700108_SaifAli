# 23040700108_SaifAli – Digital Forensics: PCAP Integrity via Blockchain

**Student ID:** 23040700108
**Name:** Saif Ali Mohsen
**Course:** Blockchain Technology

---

## Project Overview

This project demonstrates how **blockchain technology** can be used to verify the **integrity of digital evidence** (PCAP network captures) in a forensic investigation context. Every evidence file is fingerprinted with SHA-256, sealed inside a custom-built blockchain, and re-checked against a permanently stored baseline every time the program runs — so any tampering, automated or manual, is detected immediately.

---

## Repository Structure

```
23040700108_SaifAli/
│
├── evidence/
│   ├── PCAP01_23040700108.pcap   (30 packets)
│   ├── PCAP02_23040700108.pcap   (50 packets)
│   ├── PCAP03_23040700108.pcap   (70 packets)
│   ├── PCAP04_23040700108.pcap   (90 packets)
│   └── PCAP05_23040700108.pcap   (100 packets)
│
├── sourcecode/
│   ├── blockchain_pcap.py        ← Main interactive program
│   └── generate_pcap.py          ← PCAP generator (no Scapy needed)
│
├── screenshot/
│   ├── verify_blockchain.png
│   ├── tamper_evidence.png
│   ├── merkle_root.png
│   └── generate_report.png
│
├── report/
│   └── laporan.pdf
│
├── baseline_hashes.json          ← Auto-generated on first run
└── README.md
```

---

## How to Run

### Requirements

```bash
python --version   # Python 3.10+ recommended
```

> No Scapy or Wireshark needed — PCAP files are generated using Python's built-in `struct` module.

### Step 1 – Generate the Evidence Files

```bash
python sourcecode/generate_pcap.py
```

This creates the five PCAP files inside `evidence/`.

### Step 2 – Run the Main Program

```bash
python sourcecode/blockchain_pcap.py
```

On first run, the program automatically computes the SHA-256 hash of every PCAP file and saves it to `baseline_hashes.json`. This file represents the **original, trusted state** of the evidence and is never overwritten automatically afterward — it is the permanent reference point every later check is compared against.

---

## Interactive Menu

```
=========================
BLOCKCHAIN MENU
=========================
1. Verify Blockchain
2. Tamper Evidence
3. Show Merkle Root
4. Generate Report
5. Exit

Choose option:
```

| Option | What it does |
|--------|---------------|
| **1. Verify Blockchain** | Re-reads every PCAP file from disk right now, recomputes its SHA-256, and compares it against the saved baseline. Returns `VALID` or `INVALID` dynamically — not from memory. |
| **2. Tamper Evidence** | Lets you choose **any** of the five evidence files. You may edit the file yourself in any external editor (a real, manual modification), let the program automatically flip one byte for a quick demo (`auto`), or simply re-check it unchanged (`skip`). The tool then shows the original hash vs. the current hash side by side and re-validates the whole chain. |
| **3. Show Merkle Root** | Builds a Merkle Tree from the five evidence hashes and prints every level up to the final Merkle Root — a single value that summarizes the integrity of the entire evidence set. |
| **4. Generate Report** | Prints the full report in one pass: hashing results, full blockchain (Genesis + 5 blocks), Merkle Tree, and validation result. |
| **5. Exit** | Closes the program. |

---

## Why Validation Is Dynamic, Not Cached

A key design decision in this project: **Option 1 and Option 2 always re-read the evidence files from disk** at the moment they are run, rather than trusting whatever was loaded into memory when the program started. This means:

- If a file is tampered with *after* the program has already started, the very next "Verify Blockchain" check will still catch it.
- If the file is later restored to its original bytes, the next check correctly returns to `VALID`.
- The comparison is always made against `baseline_hashes.json`, which is written once — on the very first run — and represents the true point of evidence acquisition.

This mirrors real chain-of-custody practice: the original hash recorded at intake never changes, and every later check is judged against that fixed reference.

---

## Key Concepts

| Concept | Implementation |
|---------|----------------|
| Evidence Acquisition | Synthetic PCAP files built with Python's `struct` module (valid libpcap format) |
| Hashing | SHA-256 via `hashlib`, read in 64 KB chunks |
| Blockchain | Genesis Block + 5 Evidence Blocks, each linked by `previous_hash` and sealed with a `block_hash` |
| Baseline Persistence | `baseline_hashes.json`, written once on first run, used as the permanent "original" reference |
| Validation | Re-hashes files from disk and compares against the baseline — fully dynamic, not a cached snapshot |
| Merkle Tree | Aggregates all 5 evidence hashes into a single Merkle Root for fast batch verification |
| Tampering Detection | Supports manual edits (hex/text editor), automatic single-byte flips, and file selection for any of the 5 evidence files |

---

## Example Output (Verify Blockchain)

```
=================================================================
  BLOCKCHAIN VALIDATION
=================================================================
  [OK]   Block 1: evidence_hash matches original record
  [OK]   Block 2: evidence_hash matches original record
  [OK]   Block 3: evidence_hash matches original record
  [OK]   Block 4: evidence_hash matches original record
  [OK]   Block 5: evidence_hash matches original record
=================================================================

  Blockchain Validation: VALID
```

After manually editing one byte of any evidence file and re-running Option 1:

```
  [FAIL] Block 1: evidence_hash differs from original record!
         File     : PCAP01_23040700108.pcap
         Original : 07f3e11a4a8971749f6e816ef0d5e29...
         Current  : e9af314caace3a8e8491fb4dcc60943...

  Blockchain Validation: INVALID
```
