#!/usr/bin/python3
import argparse
from scapy.all import *

# conf.debug_dissector=2

# This is how the scapy route type is configured
# (Interface,Destination,gateway)
default_interface = conf.route.route("0.0.0.0")[0]
print("default_interface in entry point ---> {}".format(default_interface))

parser = argparse.ArgumentParser(
    description="Sniff on what port? because the default is 10000 and 6969")

parser.add_argument('--ports', nargs='+'  # accept 1 or more ports (args)
                    , type=int,
                    # default ports if none are provided (this is a toy)
                    default=[6969, 10000],
                    help='Defaults to sniffing port 6969 and 10000')
parser.add_argument('--interface', nargs='+'  # accpept 1 or more default_interfaces to sniff
                    , default=default_interface  # detected by scapy
                    , help='Defaults to lo (Loopback) interface to sniff: pass an interface eg, wlon enp0s3')

# parsing the given timeout fromm the given arguements in the cli


def parse_duration(value):
    # Handles unlimited sniffing time
    if value.lower() == 'unlimited':
        # sniff allows for None to be set as timeout
        print("TIMEOUT SET TO UNLIIMTED")
        return None
    try:
        print(f'TIMEOUT SET TO {value}')
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "TIMEOUT value given is bogus or not 'unlimited'")


parser.add_argument("--timeout", nargs='?'  # only accept 1 input for sniff time out
                    , type=parse_duration  # calling the parse_duration function to handle this argument type
                    , default='10', help="Defaults to a timeout of 10 seconds unless a timeout is given or 'unlimited")
args = parser.parse_args()

# In the case of no network interface case given
interface = ''
if args.interface is not None:
    interface = ''.join(args.interface)
    default_interface = interface
else:
    print("Using your system's preferred interface-->{}".format(default_interface))

filtered_ports = " or ".join([f"port {p}" for p in args.ports])
bpf_filter = f"(tcp or udp) and ({filtered_ports})"

# function to process packets for my use case. I don't need too much infomation


def process_packet(packet):
    # There are Layers to the packet structure
    if packet.haslayer(IP):
        ip = packet[IP]
        print("---[IP]---")
        print("\tSrc = {} ---> Dst = {}".format(ip.src, ip.dst))
        # TCP and UDP are more or less on the same level
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("---[TCP]---")
        print("\tPort = {} ---> Dst = {}".format(tcp.sport, tcp.dport))
        # Raw data that is sent (usually in unencrypted transmissions)
        if packet.getlayer(Raw) is None:
            print("\tTCP Empty Payload")
        else:
            payload = packet[Raw].load
            print("---[Raw]---")
            print("Payload  \n{}".format(payload))

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print("---[UDP]---")
        print("\t Port = {} ---> Dst = {}".format(udp.sport, udp.dport))
        # Raw data that is sent (usually in unencrypted transmissions)
        if packet.getlayer(Raw) is None:
            print("\tUDP Empty Payload")
        else:
            payload = packet[Raw]
            print("---[UDP]---")
            print("Payoad  \n{}".format(payload.load))

    # ICMP-> Internet Communication Message Protocol, in important part of packets
    # It contains infomation in the header that is needed for Error Reporting
    # and Operational Communication
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print("---[ICMP]--- \n{}".format(icmp.type))
        # Type 8) Echo Request
        # Type 0) Echo reply
        # Type 3) Destination Unreachable
        # Type 5) Redirect, src should use a different route
        icmp_response = ""
        match icmp.type:
            case 3:
                icmp_response = "Dst {}: Unreachable".format(packet[IP].dst)
                pass
            case 5:
                icmp_response = "Src {}: Should re-route".format(
                    packet[IP].src)
                pass
            case 0 | 8:
                icmp_response = "Echo Reply"
                pass
            case _:
                print("Some other code I probably don't care about")
                pass

        print("\tCode = {} \n{icmp_response}".format(icmp.type))

    else:
        print("Nothing for Bobby to sneuf")


# Finding the default route interface of where the script is running
print("Found network interface from command-line arguments as-->{}".format(default_interface))
print("...Sniffing for packets on the given interface: {}".format(default_interface))
print("...Using BPF_Filter -->{}".format(bpf_filter))
# This is the call back approach for scapy. We're calling back the "process_packet" method
pkt = sniff(iface=default_interface, filter=bpf_filter,
            prn=process_packet, timeout=args.timeout)
