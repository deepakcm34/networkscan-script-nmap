import os
import subprocess
from lxml import etree
from jinja2 import Template

# File containing domains and IPs with names to scan
target_file = "targets.txt"

# Output directory for scan results
output_dir = "nmap_results"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Read targets from file
def read_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            targets = []
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:  # Ensure valid "domain/IP name" format
                    targets.append({"target": parts[0], "name": parts[1]})
            return targets
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return []

# Run Nmap scan
def run_nmap_scan(target, vuln_scan=False, ports=None):
    scan_type = "vulnerability scan" if vuln_scan else "port scan"
    print(f"Starting {scan_type} for {target}...")
    xml_file = os.path.join(output_dir, f"{target.replace('.', '_')}_vuln.xml" if vuln_scan else f"{target.replace('.', '_')}.xml")
    try:
        # Construct Nmap command
        command = [
            "nmap",
            "-Pn",            # Skip host discovery
            "-sT",            
            "-T3",            # Moderate timing template
            "--min-rate", "500",
            "--max-retries", "3",  # Maximum retries per port
            "--reason",       # Include reasoning for port state
            "-oX", xml_file   # Save output as XML
        ]

        if vuln_scan:
            # Add vulnerability scripts and open ports
            command.extend(["--script", "vuln", "-p", ",".join(map(str, ports))])
        else:
            # Full port scan
            command.extend(["-p", "1-65535"])

        command.append(target)
        subprocess.run(command, check=True)
        print(f"{scan_type.capitalize()} results saved to {xml_file}")
        return xml_file
    except subprocess.CalledProcessError as e:
        print(f"Error during {scan_type} for {target}: {e}")
        return None

# Parse Nmap XML and extract open ports
def parse_open_ports(xml_file):
    try:
        dom = etree.parse(xml_file)
        root = dom.getroot()
        open_ports = []
        for port in root.findall(".//port"):
            state_element = port.find("state")
            state = state_element.get("state") if state_element is not None else "Unknown"
            if state == "open":
                port_id = port.get("portid")
                open_ports.append(port_id)
        return open_ports
    except Exception as e:
        print(f"Error parsing open ports from XML file {xml_file}: {e}")
        return []

# Parse Nmap XML and extract data with vulnerabilities
def parse_nmap_xml(xml_file):
    try:
        dom = etree.parse(xml_file)
        root = dom.getroot()

        # Extract scan data
        hosts = []
        for host in root.findall("host"):
            # Extract IPv4 address
            ip_element = host.find("address[@addrtype='ipv4']")
            ip = ip_element.get("addr") if ip_element is not None else "Unknown"

            # Extract hostname (if available)
            hostname_element = host.find(".//hostname")
            hostname = hostname_element.get("name") if hostname_element is not None else None

            ports = []
            for port in host.findall(".//port"):
                state_element = port.find("state")
                state = state_element.get("state") if state_element is not None else "Unknown"
                reason = state_element.get("reason") if state_element is not None else "Unknown"

                # Log split-handshake behavior
                if reason == "split-handshake-syn":
                    print(f"Port {port.get('portid')} on {ip} exhibits split-handshake behavior.")
                    continue  # Skip split-handshake-syn ports

                # Only include open ports
                if state != "open":
                    continue  # Skip non-open ports

                port_id = port.get("portid")
                service_element = port.find(".//service")
                service = service_element.get("name") if service_element is not None else "Unknown"

                # Extract vulnerabilities
                vulnerabilities = []
                for script in port.findall(".//script"):
                    script_id = script.get("id", "Unknown")
                    output = script.get("output", "No details")
                    if "ERROR" in output:
                        continue
                    vulnerabilities.append({"id": script_id, "output": output})

                ports.append({
                    "port": port_id,
                    "state": state,
                    "service": service,
                    "reason": reason,
                    "vulnerabilities": vulnerabilities
                })

            # Add host details
            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports if ports else None
            })
        return hosts
    except Exception as e:
        print(f"Error parsing XML file {xml_file}: {e}")
        return []

# Generate combined HTML report
def generate_combined_report(all_hosts):
    try:
        template = Template("""
        <html>
        <head>
            <title>Nmap Combined VAPT Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f4f4f9;
                }
                h1 {
                    text-align: center;
                    color: #333;
                }
                h2 {
                    color: #444;
                    background-color: #eef;
                    padding: 10px;
                    border-radius: 5px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }
                table th, table td {
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }
                table th {
                    background-color: #4CAF50;
                    color: white;
                    font-weight: bold;
                }
                table tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                table tr:hover {
                    background-color: #f1f1f1;
                }
                .no-ports {
                    color: #666;
                    font-style: italic;
                }
                .vulnerability-list li {
                    color: #d9534f;
                }
                .vulnerability-list li strong {
                    color: #5bc0de;
                }
            </style>
        </head>
        <body>
            <h1>Nmap Combined VAPT Report</h1>
            {% for host in all_hosts %}
            <h2>
                Host: 
                {% if host.hostname %}
                    {{ host.hostname }} ({{ host.ip }})
                {% else %}
                    {{ host.ip }}
                {% endif %}
                {% if host.name %}
                    <span style="color: blue;">({{ host.name }})</span>
                {% endif %}
            </h2>
            {% if host.ports %}
                <table>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Reason</th>
                        <th>Service</th>
                        <th>Vulnerabilities</th>
                    </tr>
                    {% for port in host.ports %}
                    <tr>
                        <td>{{ port.port }}</td>
                        <td>{{ port.state }}</td>
                        <td>{{ port.reason }}</td>
                        <td>{{ port.service }}</td>
                        <td>
                            {% if port.vulnerabilities %}
                                <ul class="vulnerability-list">
                                    {% for vuln in port.vulnerabilities %}
                                    <li><strong>{{ vuln.id }}</strong>: {{ vuln.output }}</li>
                                    {% endfor %}
                                </ul>
                            {% else %}
                                No vulnerabilities detected
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            {% else %}
                <p class="no-ports">No open ports detected.</p>
            {% endif %}
            {% endfor %}
        </body>
        </html>
        """)

        # Render HTML
        html_content = template.render(all_hosts=all_hosts)
        combined_file = os.path.join(output_dir, "combined_report.html")
        with open(combined_file, "w") as f:
            f.write(html_content)
        print(f"Combined HTML report generated: {combined_file}")
    except Exception as e:
        print(f"Error generating combined report: {e}")

# Main function
if __name__ == "__main__":
    targets = read_targets(target_file)
    if not targets:
        print("No targets to scan.")
        exit(1)

    all_hosts = []
    for target in targets:
        target_host = {"ip": target["target"], "name": target["name"], "hostname": None, "ports": None}
        port_scan_file = run_nmap_scan(target["target"])
        if port_scan_file:
            open_ports = parse_open_ports(port_scan_file)
            if open_ports:
                vuln_scan_file = run_nmap_scan(target["target"], vuln_scan=True, ports=open_ports)
                if vuln_scan_file:
                    vuln_results = parse_nmap_xml(vuln_scan_file)
                    for result in vuln_results:
                        result["name"] = target["name"]  # Add the name to the result
                        all_hosts.append(result)
            else:
                all_hosts.append(target_host)  # Add the host even if no ports are open

    if all_hosts:
        generate_combined_report(all_hosts)
    else:
        print("No results to generate combined report.")

