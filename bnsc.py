import socket

def scan_ports(ip_address, port_range):
    open_ports = []
    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip_address, port)) == 0:
                open_ports.append(port)
    return open_ports

def identify_blockchain_node(port):
    blockchain_ports = {
        8333: 'Bitcoin',
        8545: 'Ethereum'
    }
    return blockchain_ports.get(port, 'Unknown')

def check_rpc_exposure(ip_address, port):
    if port == 8545:
        return True
    return False

def generate_report(ip_address, open_ports):
    report = f'Security Report for {ip_address}\n'
    report += '=' * 30 + '\n'
    for port in open_ports:
        node_type = identify_blockchain_node(port)
        report += f'Open port detected: {port} ({node_type})\n'
        if check_rpc_exposure(ip_address, port):
            report += f'WARNING: RPC interface for {node_type} is publicly exposed!\n'
            report += 'Recommendation: Restrict access to the RPC interface to trusted IPs only.\n'
    return report

if __name__ == '__main__':
    ip_address = '127.0.0.1'
    port_range = range(8300, 8600)
    open_ports = scan_ports(ip_address, port_range)
    report = generate_report(ip_address, open_ports)
    print(report)
