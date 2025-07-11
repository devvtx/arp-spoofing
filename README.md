

This project implements an **ARP spoofing tool** in Python using the `scapy` library. It performs a man-in-the-middle (MITM) attack by poisoning the ARP tables of a target and the network gateway.


 What It Does

  - Spoofs ARP responses to both the victim and the gateway.
  - Enables IP packet forwarding on the attacker's machine to relay traffic (MITM).
  - Repeatedly sends forged ARP replies to maintain the attack.
  - Restores the network ARP tables when the script is stopped.

