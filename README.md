# Router Dataplane Implementation

A C++ implementation of a router's dataplane developed for the Communication Networks course. This project covers core networking mechanisms including packet forwarding, Longest Prefix Matching (LPM) via a Trie data structure, the Address Resolution Protocol (ARP), and Internet Control Message Protocol (ICMP) error handling.

---

## Features

- **IPv4 Packet Forwarding:** Decrements TTL, searches the routing table, buffers packets pending ARP resolution, and forwards frames using correct destination MAC addresses.
- **Efficient LPM (Longest Prefix Matching):** Implements a Trie data structure for route lookups with a worst-case time complexity of O(32), vastly outperforming linear route table searches (O(n)).
- **ARP Protocol Integration:** Handles ARP requests/replies, broadcast resolution, and maintains an ARP cache to avoid redundant lookups.
- **ICMP Error Handling:** Generates proper ICMP messages including `Time Exceeded` (when TTL hits 0) and `Destination Unreachable` (when no route matches).

---

## Architecture & Implementation Details

### 1. Packet Forwarding
- Receives packets and inspects headers.
- Decrements the packet's TTL. If TTL <= 0, discards the packet and generates an ICMP `Time Exceeded` message.
- Performs an LPM lookup to find the best next-hop gateway and outgoing interface.
- Resolves the next-hop MAC address using the ARP cache (sending an ARP broadcast if missing, and temporarily buffering the packet).

### 2. Trie-Based Longest Prefix Matching (LPM)
- **Structure:** Nodes contain a vector of 2 children (for bits 0 and 1) and a pointer to a valid route entry.
- **Building:** Inserts routes from the routing table into the Trie bit-by-bit up to the prefix length.
- **Lookup:** Traverses the Trie based on the bits of the target IP address, retaining the last valid route matched, resulting in a constant lookup depth of at most 32 steps.

### 3. ARP Cache & Protocol
- Resolves IP-to-MAC mappings dynamically.
- Caches entries to allow subsequent ping/data packets to bypass ARP requests, ensuring fast frame delivery.

### 4. ICMP Error Generation
- **Time Exceeded:** Triggered when a packet's TTL expires during forwarding.
- **Destination Unreachable:** Triggered when the router finds no matching route in the routing table for the destination IP.

---

## Building and Running

### Prerequisites
- GCC / G++ compiler with C++11 support (or higher)
- POSIX-compliant environment (Linux / WSL)
- Network emulation tools (e.g., Mininet) for testing dataplane behavior

### Compilation
Build the project using `make`:

```bash
make
```

### Testing
Run the router binary within your network topology environment:
```bash
./router
```
