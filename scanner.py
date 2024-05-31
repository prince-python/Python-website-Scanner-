import subprocess
import nmap

def sqlmap_scan(target):
    result = subprocess.run(
        ['python', 'sqlmap-dev/sqlmap.py', '-u', target, '--batch'],
        capture_output=True, text=True)
    return result.stdout

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, '22-443')
    open_ports = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            open_ports.extend(nm[host]['tcp'].keys())
    return open_ports

def wapiti_scan(target):
    result = subprocess.run(
        ['wapiti', '-u', target, '-f', 'txt'],
        capture_output=True, text=True)
    return result.stdout

def extract_sqlmap_vulnerabilities(scan_results):
    vulnerabilities = []
    lines = scan_results.split('\n')
    for line in lines:
        if line.startswith('[!!]'):
            vulnerabilities.append(line)
    return vulnerabilities

def extract_wapiti_vulnerabilities(scan_results):
    vulnerabilities = []
    lines = scan_results.split('\n')
    for line in lines:
        if line.startswith('    -'):
            vulnerabilities.append(line)
    return vulnerabilities

def summarize_results(sqlmap_results, nmap_results, wapiti_results):
    sqlmap_vulnerabilities = extract_sqlmap_vulnerabilities(sqlmap_results)
    wapiti_vulnerabilities = extract_wapiti_vulnerabilities(wapiti_results)
    
    summary = {
        'sqlmap': 'No vulnerabilities found' if not sqlmap_vulnerabilities else 'Vulnerabilities found',
        'Nmap': f'Open ports found: {", ".join(map(str, nmap_results))}' if nmap_results else 'No open ports found',
        'Wapiti': 'No vulnerabilities found' if not wapiti_vulnerabilities else 'Vulnerabilities found'
    }
    
    vulnerabilities = {
        'sqlmap': sqlmap_vulnerabilities,
        'wapiti': wapiti_vulnerabilities
    }
    
    return summary, vulnerabilities

def main(target):
    print(f"Starting scan for {target}")
    
    print("Running sqlmap scan...")
    sqlmap_results = sqlmap_scan(target)
    print("SQLMap Scan Results:")
    print(sqlmap_results)
    
    print("\nRunning Nmap scan...")
    nmap_results = nmap_scan(target)
    print("Nmap Scan Results:")
    print(nmap_results)
    
    print("\nRunning Wapiti scan...")
    wapiti_results = wapiti_scan(target)
    print("Wapiti Scan Results:")
    print(wapiti_results)
    
    summary, vulnerabilities = summarize_results(sqlmap_results, nmap_results, wapiti_results)
    
    print("\nScan Summary:")
    for test, result in summary.items():
        print(f"{test}: {result}")
        
    print("\nVulnerabilities:")
    for tool, vulns in vulnerabilities.items():
        print(f"\nVulnerabilities found by {tool.capitalize()}:")
        if vulns:
            for vuln in vulns:
                print(vuln)
        else:
            print(f"No vulnerabilities found by {tool.capitalize()}.")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    main(target_url)

