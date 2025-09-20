import socket
import sys
from datetime import datetime

def scan_port(ip, port):
    """Scan a single port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {ip}")
        return False
    except socket.error:
        print(f"Error: Could not connect to {ip}:{port}")
        return False

def get_vulnerability_info(port):
    """Return potential vulnerability and mitigation for open ports."""
    vulnerabilities = {
        22: {
            "service": "SSH",
            "risk": "Unauthorized access if weak credentials or outdated software.",
            "mitigation": "Use strong passwords, enable key-based auth, update SSH server."
        },
        80: {
            "service": "HTTP",
            "risk": "Web server vulnerabilities like XSS or outdated software.",
            "mitigation": "Use HTTPS, apply WAF, keep server software updated."
        },
        443: {
            "service": "HTTPS",
            "risk": "SSL/TLS misconfigurations or weak ciphers.",
            "mitigation": "Use strong ciphers, enable HSTS, regularly test SSL config."
        }
    }
    return vulnerabilities.get(port, {
        "service": "Unknown",
        "risk": "Potential unauthorized access or misconfiguration.",
        "mitigation": "Close unnecessary ports, use firewall rules to restrict access."
    })

def port_scanner(ip, ports):
    """Scan specified ports on the target IP and generate a report."""
    print(f"\nStarting port scan on {ip} at {datetime.now()}")
    print("-" * 50)
    
    results = []
    for port in ports:
        if scan_port(ip, port):
            vuln_info = get_vulnerability_info(port)
            result = (f"Port {port} is OPEN\n"
                     f"  Service: {vuln_info['service']}\n"
                     f"  Risk: {vuln_info['risk']}\n"
                     f"  Mitigation: {vuln_info['mitigation']}\n")
            print(result)
            results.append(result)
        else:
            print(f"Port {port} is CLOSED")
            results.append(f"Port {port} is CLOSED\n")
    
    try:
        with open("port_scan_report.txt", "w") as f:
            f.write(f"Port Scan Report for {ip} - {datetime.now()}\n")
            f.write("-" * 50 + "\n")
            f.writelines(results)
        print("\nReport saved to port_scan_report.txt")
    except IOError:
        print("Error: Could not write to report file")

def main():
    """Main function to handle user input and run the scanner."""
    if len(sys.argv) != 2:
        print("Usage: python port_scanner.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    ports = [22, 80, 443]
    
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print("Error: Invalid IP address")
        sys.exit(1)
    
    port_scanner(target_ip, ports)

if __name__ == "__main__":
    main()