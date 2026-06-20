"""
blockchain_pcap.py
Digital Forensics Project - PCAP Integrity via Blockchain

Student Name : Saif Ali Mohsen
Student ID   : 23040700108
"""

import hashlib
import json
import os
import struct
from datetime import datetime, timezone

STUDENT_NAME = "Saif Ali Mohsen"
STUDENT_ID = "23040700108"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
PCAP_FILES = [
    f"PCAP01_{STUDENT_ID}.pcap",
    f"PCAP02_{STUDENT_ID}.pcap",
    f"PCAP03_{STUDENT_ID}.pcap",
    f"PCAP04_{STUDENT_ID}.pcap",
    f"PCAP05_{STUDENT_ID}.pcap",
]

SEPARATOR = "=" * 65


def count_packets_pcap(filepath):
    count = 0
    with open(filepath, "rb") as f:
        raw_magic = f.read(4)
        magic = struct.unpack("<I", raw_magic)[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            raise ValueError(f"Not a valid PCAP file: {filepath}")

        f.read(20)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            incl_len = struct.unpack(f"{endian}I", hdr[8:12])[0]
            f.read(incl_len)
            count += 1
    return count


def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size_kb(filepath):
    return os.path.getsize(filepath) / 1024


BASELINE_FILE = os.path.join(BASE_DIR, "baseline_hashes.json")


def load_or_create_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)

    baseline = {}
    for filename in PCAP_FILES:
        filepath = os.path.join(EVIDENCE_DIR, filename)
        if os.path.exists(filepath):
            baseline[filename] = sha256_file(filepath)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    return baseline


class Block:
    def __init__(self, index, timestamp, evidence_file, packet_count, evidence_hash, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.evidence_file = evidence_file
        self.packet_count = packet_count
        self.evidence_hash = evidence_hash
        self.previous_hash = previous_hash
        self.block_hash = self._compute_hash()

    def _compute_hash(self):
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_file": self.evidence_file,
            "packet_count": self.packet_count,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
        }
        raw = json.dumps(block_content, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()

    def __str__(self):
        label = "Genesis Block" if self.index == 0 else f"Block {self.index}"
        lines = [
            f"  {label}",
            f"  {'-'*60}",
            f"  Index          : {self.index}",
            f"  Timestamp      : {self.timestamp}",
        ]
        if self.index == 0:
            lines.append(f"  Note           : {self.evidence_file}")
        else:
            lines += [
                f"  Evidence File  : {self.evidence_file}",
                f"  Packet Count   : {self.packet_count}",
                f"  Evidence Hash  : {self.evidence_hash[:32]}...",
                f"  Previous Hash  : {self.previous_hash[:32]}...",
                f"  Block Hash     : {self.block_hash[:32]}...",
            ]
        return "\n".join(lines)


class Blockchain:
    def __init__(self):
        self.chain = []
        self._create_genesis()

    def _create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            evidence_file="Genesis Block - Digital Forensics Chain of Custody",
            packet_count=0,
            evidence_hash="0" * 64,
            previous_hash="0" * 64,
        )
        self.chain.append(genesis)

    def add_evidence(self, evidence_file, packet_count, evidence_hash):
        previous_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            evidence_file=evidence_file,
            packet_count=packet_count,
            evidence_hash=evidence_hash,
            previous_hash=previous_block.block_hash,
        )
        self.chain.append(new_block)

    def validate_chain(self, verbose=True):
        if verbose:
            print("\n" + SEPARATOR)
            print("  BLOCKCHAIN VALIDATION")
            print(SEPARATOR)

        valid = True
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.previous_hash != previous.block_hash:
                if verbose:
                    print(f"  [FAIL] Block {i}: previous_hash mismatch!")
                valid = False
            else:
                if verbose:
                    print(f"  [OK]   Block {i}: previous_hash linkage")

            recomputed = current._compute_hash()
            if current.block_hash != recomputed:
                if verbose:
                    print(f"  [FAIL] Block {i}: block_hash tampered!")
                valid = False
            else:
                if verbose:
                    print(f"  [OK]   Block {i}: block_hash integrity")

        if verbose:
            print(SEPARATOR)
        result = "VALID" if valid else "INVALID"
        print(f"\n  Blockchain Validation: {result}\n")
        return valid


def merkle_parent(left, right):
    combined = (left + right).encode()
    return hashlib.sha256(combined).hexdigest()


def build_merkle_tree(leaf_hashes):
    levels = [leaf_hashes[:]]
    current_level = leaf_hashes[:]

    while len(current_level) > 1:
        next_level = []
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        for i in range(0, len(current_level), 2):
            parent = merkle_parent(current_level[i], current_level[i + 1])
            next_level.append(parent)

        levels.append(next_level)
        current_level = next_level

    return {
        "levels": levels,
        "root": current_level[0] if current_level else None,
    }


def print_merkle_tree(tree):
    print("\n" + SEPARATOR)
    print("  MERKLE TREE - EVIDENCE HASH AGGREGATION")
    print(SEPARATOR)

    levels = tree["levels"]
    for depth, level in enumerate(levels):
        label = "Leaves (PCAP file hashes)" if depth == 0 else f"Level {depth}"
        print(f"\n  {label}:")
        for i, h in enumerate(level):
            print(f"    [{i}] {h[:32]}...")

    print(f"\n  {'-'*60}")
    print(f"  MERKLE ROOT : {tree['root']}")
    print(SEPARATOR)


def load_evidence_and_build_chain():
    records = []
    bc = Blockchain()

    for filename in PCAP_FILES:
        filepath = os.path.join(EVIDENCE_DIR, filename)
        if not os.path.exists(filepath):
            print(f"[WARNING] File not found: {filepath}")
            continue

        packets = count_packets_pcap(filepath)
        digest = sha256_file(filepath)
        size_kb = file_size_kb(filepath)

        records.append({
            "file": filename,
            "packets": packets,
            "size_kb": size_kb,
            "sha256": digest,
        })

        bc.add_evidence(filename, packets, digest)

    return records, bc


def print_hashing_results(records):
    print("\n" + SEPARATOR)
    print("  SHA-256 HASHING RESULTS")
    print(SEPARATOR)
    for r in records:
        print(f"\n  File    : {r['file']}")
        print(f"  Packets : {r['packets']}")
        print(f"  Size    : {r['size_kb']:.1f} KB")
        print(f"  SHA-256 : {r['sha256']}")
    print()


def print_blockchain(bc):
    print(SEPARATOR)
    print("  BLOCKCHAIN - EVIDENCE CHAIN")
    print(SEPARATOR)
    for block in bc.chain:
        print()
        print(block)
    print()


def action_verify_blockchain(bc, baseline):
    print("\n" + SEPARATOR)
    print("  BLOCKCHAIN VALIDATION")
    print(SEPARATOR)

    chain_valid = True
    for i, filename in enumerate(PCAP_FILES, start=1):
        filepath = os.path.join(EVIDENCE_DIR, filename)
        if not os.path.exists(filepath):
            print(f"  [FAIL] Block {i}: file missing on disk ({filename})")
            chain_valid = False
            continue

        current_digest = sha256_file(filepath)
        original_digest = baseline.get(filename)

        if current_digest != original_digest:
            print(f"  [FAIL] Block {i}: evidence_hash differs from original record!")
            print(f"         File     : {filename}")
            print(f"         Original : {original_digest}")
            print(f"         Current  : {current_digest}")
            chain_valid = False
        else:
            print(f"  [OK]   Block {i}: evidence_hash matches original record")

    print(SEPARATOR)
    result = "VALID" if chain_valid else "INVALID"
    print(f"\n  Blockchain Validation: {result}\n")


def action_tamper_evidence(records, bc, baseline):
    print("\n" + SEPARATOR)
    print("  EVIDENCE INTEGRITY CHECK (Re-Verification)")
    print(SEPARATOR)

    print("\n  Select a file to check:")
    for idx, filename in enumerate(PCAP_FILES, start=1):
        print(f"    {idx}. {filename}")

    file_choice = input("\n  Enter file number (1-5): ").strip()
    try:
        file_index = int(file_choice) - 1
        target_name = PCAP_FILES[file_index]
    except (ValueError, IndexError):
        print("\n  [ERROR] Invalid selection. Returning to menu.\n")
        return

    target = os.path.join(EVIDENCE_DIR, target_name)
    if not os.path.exists(target):
        print(f"\n  [ERROR] File not found: {target}\n")
        return

    stored_hash = baseline.get(target_name)
    if stored_hash is None:
        print(f"\n  [ERROR] No baseline hash recorded for {target_name}.\n")
        return

    print(f"\n  Target evidence file : {target_name}")
    print(f"  Full path            : {target}")
    print(f"  Hash stored in blockchain (ORIGINAL, saved at first run):")
    print(f"    {stored_hash}")

    print(
        "\n  This tool does NOT modify the file by itself.\n"
        "  You may now edit the file yourself (e.g. open it in a hex editor\n"
        "  or any text editor and change one byte), save it, then come back here.\n"
    )

    choice = input(
        "  Press [Enter] once you have modified the file yourself,\n"
        "  or type 'auto' to let the program flip one byte automatically,\n"
        "  or type 'skip' to re-check the file with no changes: "
    ).strip().lower()

    if choice == "auto":
        with open(target, "rb") as f:
            data = bytearray(f.read())
        pos = 100
        old_byte = data[pos]
        new_byte = (old_byte + 1) % 256
        data[pos] = new_byte
        with open(target, "wb") as f:
            f.write(data)
        print(f"\n  [INFO] Byte at offset {pos} changed automatically: "
              f"0x{old_byte:02X} -> 0x{new_byte:02X}")

    current_hash = sha256_file(target)

    print("\n" + "-" * 60)
    print("  INTEGRITY RE-CHECK RESULT")
    print("-" * 60)
    print(f"  File checked                         : {target_name}")
    print(f"  Hash stored in blockchain (ORIGINAL) :")
    print(f"    {stored_hash}")
    print(f"  Hash recomputed from file (CURRENT)  :")
    print(f"    {current_hash}")

    if stored_hash == current_hash:
        print("\n  Result: Hashes MATCH -> Evidence file is UNCHANGED.")
    else:
        print("\n  Result: Hashes DO NOT MATCH -> Evidence file has been TAMPERED.")

    print("\n  Re-validating full blockchain against saved baseline hashes...")
    bc_check = Blockchain()
    for filename in PCAP_FILES:
        filepath = os.path.join(EVIDENCE_DIR, filename)
        packets = count_packets_pcap(filepath)
        digest = sha256_file(filepath)
        bc_check.add_evidence(filename, packets, digest)

    print("\n" + SEPARATOR)
    print("  BLOCKCHAIN VALIDATION")
    print(SEPARATOR)

    chain_valid = True
    for i, block in enumerate(bc_check.chain[1:], start=1):
        original_for_file = baseline.get(block.evidence_file)
        if block.evidence_hash != original_for_file:
            print(f"  [FAIL] Block {i}: evidence_hash differs from original record!")
            print(f"         File     : {block.evidence_file}")
            print(f"         Original : {original_for_file}")
            print(f"         Current  : {block.evidence_hash}")
            chain_valid = False
        else:
            print(f"  [OK]   Block {i}: evidence_hash matches original record")

        recomputed = block._compute_hash()
        if block.block_hash != recomputed:
            print(f"  [FAIL] Block {i}: block_hash tampered!")
            chain_valid = False
        else:
            print(f"  [OK]   Block {i}: block_hash integrity")

    print(SEPARATOR)
    result = "VALID" if chain_valid else "INVALID"
    print(f"\n  Blockchain Validation: {result}\n")

    if not chain_valid:
        restore = input(
            "  Restore the original evidence file now? (y/n): "
        ).strip().lower()
        if restore == "y":
            if choice == "auto":
                data[pos] = old_byte
                with open(target, "wb") as f:
                    f.write(data)
                print("  [INFO] Original evidence file restored.\n")
            else:
                print(
                    "  [INFO] You modified this file manually, so it must be\n"
                    "  restored manually as well (undo your edit in the editor\n"
                    "  you used, then save the file again).\n"
                )
        else:
            print("  [WARNING] File left in its TAMPERED state.\n")


def action_show_merkle_root(records):
    leaf_hashes = [r["sha256"] for r in records]
    tree = build_merkle_tree(leaf_hashes)
    print_merkle_tree(tree)


def action_generate_report(records, bc):
    print("\n" + SEPARATOR)
    print("  GENERATE REPORT")
    print(SEPARATOR)
    print_hashing_results(records)
    print_blockchain(bc)
    leaf_hashes = [r["sha256"] for r in records]
    tree = build_merkle_tree(leaf_hashes)
    print_merkle_tree(tree)
    bc.validate_chain(verbose=True)
    print("\n  [INFO] Full report generated above.\n")


def print_menu():
    print("\n" + "=" * 25)
    print("BLOCKCHAIN MENU")
    print("=" * 25)
    print("1. Verify Blockchain")
    print("2. Tamper Evidence")
    print("3. Show Merkle Root")
    print("4. Generate Report")
    print("5. Exit")


def main():
    print("\n" + SEPARATOR)
    print("  DIGITAL FORENSICS - PCAP INTEGRITY VIA BLOCKCHAIN")
    print(f"  Student Name : {STUDENT_NAME}")
    print(f"  Student ID   : {STUDENT_ID}")
    print(SEPARATOR)

    print("\n  Loading evidence files and building blockchain...")
    records, bc = load_evidence_and_build_chain()
    print(f"  Loaded {len(records)} evidence files into the blockchain.")

    baseline = load_or_create_baseline()
    print(f"  Baseline hashes ready ({len(baseline)} files) - see baseline_hashes.json")

    while True:
        print_menu()
        choice = input("\nChoose option: ").strip()

        if choice == "1":
            action_verify_blockchain(bc, baseline)
        elif choice == "2":
            action_tamper_evidence(records, bc, baseline)
        elif choice == "3":
            action_show_merkle_root(records)
        elif choice == "4":
            action_generate_report(records, bc)
        elif choice == "5":
            print("\n  Exiting program. Goodbye!\n")
            break
        else:
            print("\n  Invalid option. Please choose 1-5.")


if __name__ == "__main__":
    main()