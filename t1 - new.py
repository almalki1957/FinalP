import numpy as np
import subprocess
import random
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import logging
from mininet.net import Mininet
from mininet.node import Host, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import xml.etree.ElementTree as ET

# Download NLTK data
nltk.download('punkt')
nltk.download('stopwords')

# Set up logging


def setup_logging():
    logger = logging.getLogger("TangleNet")
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler("TangleNet.log")
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s - %(message)s")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


logger = setup_logging()

# Define the attack phases as states
attack_phases = [
    'Reconnaissance',
    'Weaponization',
    'Delivery',
    'Exploitation',
    'Installation',
    'Command and Control',
     'Action']

# Actions that the system can take
actions = ['Allow Command', 'Substitute Command', 'Block Command']

# Rewards for each state-action pair
rewards = np.array([
    [10, 5, 0],   # Reconnaissance phase
    [20, 10, 0],  # Weaponization phase
    [30, 15, 0],  # Delivery phase
    [40, 20, 0],  # Exploitation phase
    [50, 25, 0],  # Installation phase
    [60, 30, 0],  # Command and Control phase
    [100, 50, 0]  # Action phase (final phase)
])

# Initialize Q-table with zeros
num_states = len(attack_phases)
num_actions = len(actions)
Q = np.zeros((num_states, num_actions))

# Set Q-learning hyperparameters
learning_rate = 0.8
discount_factor = 0.95
num_episodes = 1000

# Function to read commands from the XML file


def read_commands_from_file(file_path):
    phase_commands = {phase: [] for phase in attack_phases}
    tree = ET.parse('attack.xml')
    root = tree.getroot()
    for phase in root.findall('Phase'):
        phase_name = phase.get('name')
        commands = phase.findall('.//Code')

        if phase_name in phase_commands:
            phase_commands[phase_name].extend(
    cmd.text.strip() for cmd in commands if cmd.text)

    return phase_commands

# Function to execute a command in the shell


def execute_command(command):
    try:
        output = subprocess.check_output(
    command,
    shell=True,
    stderr=subprocess.STDOUT,
     universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"Command execution error: {e.output.strip()}"

# Calculate similarity score between two commands


def calculate_similarity(command1, command2):
    stop_words = set(stopwords.words('english'))
    tokens1 = [token.lower()
                           for token in word_tokenize(command1) if token.isalnum()]
    tokens2 = [token.lower()
                           for token in word_tokenize(command2) if token.isalnum()]
    filtered_tokens1 = [token for token in tokens1 if token not in stop_words]
    filtered_tokens2 = [token for token in tokens2 if token not in stop_words]
    intersection = len(set(filtered_tokens1).intersection(filtered_tokens2))
    union = len(set(filtered_tokens1).union(filtered_tokens2))
    similarity_score = intersection / union if union != 0 else 0.0
    return similarity_score

# Q-learning process with XML-based command matching


def q_learning_process(phase_commands):
    state = 0  # Start at the 'Reconnaissance' phase
    while state < num_states - 1:  # Continue until reaching the final phase 'Action'
        command = input("\nEnter the Command: ")
        response = execute_command(command)
        print(f"Command executed: {command}")
        print(f"Response: {response}")
        logger.info(f"Command: {command}, Response: {response}")

        # Find the closest matching phase for the command based on similarity
        best_similarity = 0
        best_phase = attack_phases[state]  # Default to the current phase
        for phase, cmds in phase_commands.items():
            for stored_command in cmds:
                similarity = calculate_similarity(command, stored_command)
                if similarity > best_similarity:
                  best_similarity = similarity
                  best_phase = phase

        # Determine the index of the best-matching phase
        phase_index = attack_phases.index(best_phase)
        action = random.choice(range(num_actions))  # Choose an action randomly

        # Display the selected phase and action
        print(f"Phase: {best_phase}, Action taken: {actions[action]}")
        logger.info(f"Phase: {best_phase}, Action taken: {actions[action]}")

        # Update Q-values based on the action taken
        Q[state, action] = (1 - learning_rate) * Q[state, action] + \
                           learning_rate * (rewards[state, action] + discount_factor * np.max(Q[phase_index]))

        print(f"Q-value updated: {Q[state, action]}")
        state = phase_index  # Move to the detected phase index

# Create network topology with VLAN configuration
def create_topology():
    net = Mininet()

    # Adding hosts with shortened names
    ftp = net.addHost('ftp')
    ssh = net.addHost('ssh')
    mysql = net.addHost('mysql')
    smtp = net.addHost('smtp')

    # Adding firewall as a switch with specific DPID
    firewall = net.addSwitch('firewall', dpid='0000000000000001')

    # Adding links between hosts and the firewall switch
    net.addLink(ftp, firewall)
    net.addLink(ssh, firewall)
    net.addLink(mysql, firewall)
    net.addLink(smtp, firewall)

    # Starting the network
    net.start()

    # Setting up VLANs by adding virtual interfaces on firewall switch
    firewall.cmd('vconfig add firewall-eth1 10')
    firewall.cmd('vconfig add firewall-eth2 20')
    firewall.cmd('vconfig add firewall-eth3 30')
    firewall.cmd('vconfig add firewall-eth4 40')

    # Bringing up VLAN interfaces on the firewall
    firewall.cmd('ifconfig firewall-eth1.10 up')
    firewall.cmd('ifconfig firewall-eth2.20 up')
    firewall.cmd('ifconfig firewall-eth3.30 up')
    firewall.cmd('ifconfig firewall-eth4.40 up')

    # Assigning IPs to hosts within their VLANs
    ftp.cmd('ifconfig ftp-eth0 192.168.10.2/24')
    ssh.cmd('ifconfig ssh-eth0 192.168.20.2/24')
    mysql.cmd('ifconfig mysql-eth0 192.168.30.2/24')
    smtp.cmd('ifconfig smtp-eth0 192.168.40.2/24')

    # Assigning IPs to firewall VLAN interfaces
    firewall.cmd('ifconfig firewall-eth1.10 192.168.10.1/24')
    firewall.cmd('ifconfig firewall-eth2.20 192.168.20.1/24')
    firewall.cmd('ifconfig firewall-eth3.30 192.168.30.1/24')
    firewall.cmd('ifconfig firewall-eth4.40 192.168.40.1/24')

    # Adding default gateway for each host to route through the firewall
    ftp.cmd('ip route add default via 192.168.10.1')
    ssh.cmd('ip route add default via 192.168.20.1')
    mysql.cmd('ip route add default via 192.168.30.1')
    smtp.cmd('ip route add default via 192.168.40.1')

    # Enabling IP forwarding on the firewall
    firewall.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Adding NAT rule on firewall for external traffic (assuming eth0 is external)
    firewall.cmd('iptables -t nat -A POSTROUTING -o firewall-eth0 -j MASQUERADE')

    # Start CLI for interactive testing
    CLI(net)

    # Stop the network after testing
    net.stop()

# Main function
if __name__ == '__main__':
    setLogLevel('info')
    print("Creating topology and starting Q-learning process...")
    phase_commands = read_commands_from_file('attack.xml')
    create_topology()
    q_learning_process(phase_commands)

    # Output learned Q-values
    print("Learned Q-values:")
    print(Q)
