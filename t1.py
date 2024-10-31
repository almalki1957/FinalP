import numpy as np
import random
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import logging
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
import xml.etree.ElementTree as ET
import subprocess

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
    'Action'
]

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

class AgentOne:
    def __init__(self, phase_commands):
        self.phase_commands = phase_commands

    def calculate_similarity(self, command1, command2):
        stop_words = set(stopwords.words('english'))
        tokens1 = [token.lower() for token in word_tokenize(command1) if token.isalnum()]
        tokens2 = [token.lower() for token in word_tokenize(command2) if token.isalnum()]
        filtered_tokens1 = [token for token in tokens1 if token not in stop_words]
        filtered_tokens2 = [token for token in tokens2 if token not in stop_words]
        intersection = len(set(filtered_tokens1).intersection(filtered_tokens2))
        union = len(set(filtered_tokens1).union(filtered_tokens2))
        similarity_score = intersection / union if union != 0 else 0.0
        return similarity_score

    def identify_phase(self, command):
        best_similarity = 0
        best_phase = attack_phases[0]  # Default to the first phase
        for phase, cmds in self.phase_commands.items():
            for stored_command in cmds:
                similarity = self.calculate_similarity(command, stored_command)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_phase = phase
        return best_phase

class AgentTwo:
    def __init__(self, attack_phases, actions, rewards, phase_commands):
        self.attack_phases = attack_phases
        self.actions = actions
        self.rewards = rewards
        self.num_states = len(attack_phases)
        self.num_actions = len(actions)
        self.Q = np.zeros((self.num_states, self.num_actions))
        self.current_phase_index = 0  # Track the current phase
        self.phase_commands = phase_commands  # Save commands for each phase
        
        # Define Q-learning hyperparameters here
        self.learning_rate = 0.8
        self.discount_factor = 0.95
        self.num_episodes = 1000

    def q_learning_process(self):
        # Execute commands in the current phase automatically
        while self.current_phase_index < self.num_states:  # Continue until reaching the final phase
            # Get commands for the current phase
            commands = self.phase_commands[self.attack_phases[self.current_phase_index]]
            for command in commands:
                response = execute_command(command)
                print(f"Command executed: {command}")
                print(f"Response: {response}")
                logger.info(f"Command: {command}, Response: {response}")

                # Static reward based on phase
                reward = self.rewards[self.current_phase_index, 0]  # Fetch reward from table

                # Select an action based on the current phase
                action =0  # Choose an action randomly

                # Display the selected phase and action
                print(f"Phase: {self.attack_phases[self.current_phase_index]}, Action: {self.actions[action]}")
                logger.info(f"Phase: {self.attack_phases[self.current_phase_index]}, Action: {self.actions[action]}")

                # Update Q-values based on the action taken
                old_q_value = self.Q[self.current_phase_index, action]
                self.Q[self.current_phase_index, action] = (
                    (1 - self.learning_rate) * old_q_value
                    + self.learning_rate * (reward + self.discount_factor * np.max(self.Q[self.current_phase_index]))
                )

                print(f"Old Q-value: {old_q_value}, Updated Q-value: {self.Q[self.current_phase_index, action]}")

            self.current_phase_index += 1  # Move to the next phase

        print("All phases executed. Final flag set!")
        print("Learned Q-values:")
        print(self.Q)

# Function to execute command on the server
def execute_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode().strip()  # Return decoded output
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode().strip()}"

# Function to read commands from the XML file
def read_commands_from_file(file_path):
    phase_commands = {phase: [] for phase in attack_phases}
    tree = ET.parse(file_path)
    root = tree.getroot()
    for phase in root.findall('Phase'):
        phase_name = phase.get('name')
        commands = phase.findall('.//Code')
        if phase_name in phase_commands:
            phase_commands[phase_name].extend(cmd.text.strip() for cmd in commands if cmd.text)
    return phase_commands

# Create network topology with VLAN configuration
def create_topology():
    net = Mininet()

    # Adding hosts with specific IP addresses
    ftp = net.addHost('ftp', ip='192.168.10.2')
    ssh = net.addHost('ssh', ip='192.168.20.2')
    mysql = net.addHost('mysql', ip='192.168.30.2')
    smtp = net.addHost('smtp', ip='192.168.40.2')

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
    for i in range(1, 5):
        firewall.cmd(f'vconfig add firewall-eth{i} {i * 10}')

    # Bringing up VLAN interfaces on the firewall
    for i in range(1, 5):
        firewall.cmd(f'ifconfig firewall-eth{i}.{i * 10} up')

    # Assigning IPs to firewall VLAN interfaces
    for i in range(1, 5):
        firewall.cmd(f'ifconfig firewall-eth{i}.{i * 10} 192.168.{i * 10}.1/24')

    # Adding default gateway for each host to route through the firewall
    for host in [ftp, ssh, mysql, smtp]:
        host.cmd(f'ip route add default via 192.168.{host.IP().split(".")[1] * 10}.1')

    # Enabling IP forwarding on the firewall
    firewall.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Adding NAT rule on firewall for external traffic (assuming eth0 is external)
    firewall.cmd('iptables -t nat -A POSTROUTING -o firewall-eth0 -j MASQUERADE')

    # Return the net object and hosts for further processing
    return net, [ftp, ssh, mysql, smtp]

# Main function
if __name__ == '__main__':
    setLogLevel('info')
    print("Creating topology and starting Q-learning process...")
    phase_commands = read_commands_from_file('attack.xml')
    net, hosts = create_topology()  # Get hosts from the topology
    agent_one = AgentOne(phase_commands)
    agent_two = AgentTwo(attack_phases, actions, rewards, phase_commands)   # Pass the correct parameters to AgentTwo
    agent_two.q_learning_process()

    # Output learned Q-values
    print("Learned Q-values:")
    print(agent_two.Q)

    # Stop the network after testing
    net.stop()
