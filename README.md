# Targeted Gratuitous ARP Sender

**A simple Python tool using Scapy to send targeted unicast gratuitous ARP replies  
to a single selected host in your local network.**

**Important legal & ethical notice**  
This tool can be used to demonstrate ARP spoofing / cache poisoning concepts.  
**It must only be used on networks and devices you own or have explicit written permission to test.**  
Misuse may violate laws in many jurisdictions.

## Features

- Interactive network interface selection
- Automatic detection of local subnet and default gateway
- Reliable ARP-based host discovery (multiple rounds + retry logic)
- Optional ICMP fallback for hosts that don't respond to ARP
- Shows response times and possible hostnames
- Lets you choose **one target host** from discovered devices
- Sends **unicast** gratuitous ARP replies telling the target that the gateway now has a **spoofed/random MAC**
- Configurable number of packets to send
- Clear real-time sending progress

## How it works (high-level)

1. Selects network interface (or uses one provided via argument)
2. Detects your local subnet and gateway IP
3. Performs ARP scanning (multiple passes + retries) → finds live hosts
4. Displays discovered devices (IP, MAC, hostname, response time)
5. You choose **one target IP** (victim)
6. Generates a random locally-administered MAC (or you can specify one)
7. Sends several **unicast** ARP replies **only to the chosen target** saying:  
   “Gateway IP is now at [spoofed MAC]”
8. Shows progress for each packet sent

```text
               Your machine                 Target device
                  │                                │
   Send unicast   │   "192.168.1.1 is-at aa:bb:cc:dd:ee:ff"   │
   gratuitous ARP │ ───────────────────────────────────────► │
                  │                                │
                  │   (only target receives it)    │
                  ▼                                ▼
           Spoofs gateway MAC                  Updates ARP cache
