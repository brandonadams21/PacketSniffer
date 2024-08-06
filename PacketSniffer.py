import sys
from scapy.all import sniff
import subprocess

def list_networks():
    try:
        # Ask the user for their operating system
        os_selected = int(input("Enter which OS you are using by pressing 1 or 2: 1. Unix-based (Linux/macOS) 2. Windows: "))
        if os_selected == 1:
            command = 'ifconfig'
        elif os_selected == 2:
            command = 'ipconfig'
        else:
            print("Error. Please enter 1 or 2.")
            sys.exit(1)

        # Run the appropriate command and capture the output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        networks = []
        
        # Parse the output based on the chosen command
        if command == 'ifconfig':
            lines = result.stdout.split('\n') # split into a new line
            for line in lines:
                if line and not line.startswith('\t'):
                    network_name = line.split(':')[0]
                    networks.append(network_name)
        elif command == 'ipconfig':
            lines = result.stdout.split('\n')
            for line in lines:
                if "adapter" in line:
                    # Extract the network name
                    network_name = line.split("adapter ")[1].strip(': ')
                    networks.append(network_name)
        
        # Display available networks
        for i, iface in enumerate(networks):
            print(f"{i + 1}. {iface}")
        
        return networks

    except Exception as e:
        print(f"Error listing networks: {e}")
        sys.exit(1)

def packet_handler(packet):
    if packet.haslayer('TCP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst

        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport

        print(f"TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

def main(network, verbose=False):
    try:
        if verbose:
            sniff(iface=network, prn=packet_handler, store=0, verbose=verbose)
        else:
            sniff(iface=network, prn=packet_handler, store=0)

    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    # List available networks
    networks = list_networks()

    # Prompt the user to select an network
    try:
        choice = int(input("Enter the number of the network you want to use: "))
        if choice < 1 or choice > len(networks):
            raise ValueError("Invalid choice")
    except ValueError as e:
        print(e)
        sys.exit(1)

    selected_network = networks[choice - 1]

    # Call the main function with the selected network
    main(selected_network)
