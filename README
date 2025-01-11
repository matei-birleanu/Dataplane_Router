# DataPlane Router

**Author:** Teodor Matei Bîrleanu  
**Group:** 324 CA  

---

## Overview
This project implements a DataPlane Router, addressing routing and packet forwarding processes using IPv4, ARP protocols, and ICMP messages. The implementation focuses on modular design and efficient routing using the Longest Prefix Match (LPM) algorithm with binary search.

---

## Implementation Details

### Protocol IPv4
- **Header Construction:**
  - A dedicated function constructs the IPv4 header to ensure modularity.
- **Packet Processing Logic:**
  - The program logic is split based on the Ethernet "type" field:
    1. **IPv4 Protocol:**
       - Handles cases where the packet cannot be forwarded (e.g., addressed to the router, TTL expired).
       - Generates ICMP messages for specific scenarios (e.g., Time Exceeded, Destination Unreachable).
       - Utilizes the **Longest Prefix Match (LPM)** algorithm to find the next hop in the routing table.
       - If `next_hop` is not found, sends an ICMP Destination Unreachable message.
       - If `next_hop` is found:
         - Searches for the MAC address in the ARP table.
         - If MAC is not found, generates an ARP Request packet.
         - If MAC is found, forwards the packet to the destination.

### Protocol ARP
- **Handling ARP Replies:**
  - Dynamically updates the ARP table with the new entry.
  - Extracts the first packet from the queue and sends it using the MAC address from the ARP Reply.
- **Handling ARP Requests:**
  - Sends a broadcast packet on the respective interface to discover the MAC address associated with the requested IP.

### Routing Table Optimization
- **Binary Search for Efficient Lookup:**
  - The routing table is sorted using `qsort` in ascending order by prefix and, in case of ties, by mask.
  - Modified the `get_best_route` function from Lab 4 to implement binary search.
  - Retains the same conditions for selecting the best route:
    - Matches by prefix.
    - Prefers entries with larger masks for the same prefix.

---

## Features Implemented
- ARP Protocol
- Routing Process
- ICMP Protocol
- Longest Prefix Match (Binary Search)

---

## Thank You!
For further questions or clarifications, feel free to contact the author.
