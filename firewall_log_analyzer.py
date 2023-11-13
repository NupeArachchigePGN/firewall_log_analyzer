import re
from collections import defaultdict

def parse_log(log_file):
    logs = []
    with open(log_file, 'r') as file:
        for line in file:
            if line.startswith('#') or line.strip() == '':
                continue
            fields = re.split(r'\s+', line.strip())
            log_entry = {
                'Date': fields[0],
                'Time': fields[1],
                'Action': fields[2],
                'Protocol': fields[3],
                'Src_IP': fields[4],
                'Dst_IP': fields[5],
                'Src_Port': fields[6],
                'Dst_Port': fields[7],
                'Size': fields[8],
                'TCP_Flags': fields[9],
                'Info': ' '.join(fields[10:])
            }
            logs.append(log_entry)
    return logs

def analyze_logs(logs):
    summary = defaultdict(int)
    threats = []
    
    for log_entry in logs:
        summary['TotalEntries'] += 1
        summary[log_entry['Action']] += 1
        
        if log_entry['Action'] == 'BLOCK':
            threats.append(log_entry)
    
    return summary, threats

def generate_report(summary, threats):
    report = f"Summary Report\n{'='*15}\n"
    for key, value in summary.items():
        report += f"{key}: {value}\n"
    
    report += f"\nPotential Threats\n{'='*18}\n"
    for threat in threats:
        report += f"{threat['Date']} {threat['Time']} - {threat['Action']} - {threat['Src_IP']} to {threat['Dst_IP']}:{threat['Dst_Port']} - {threat['Info']}\n"
    
    return report

if __name__ == "__main__":
    log_file = r"C:\Users\PC\OneDrive\Desktop\sample_firewall_log.txt"  # Replace with the actual path to your log file
    logs = parse_log(log_file)
    summary, threats = analyze_logs(logs)
    report = generate_report(summary, threats)
    
    with open("security_report.txt", "w") as report_file:
        report_file.write(report)

    print("Analysis completed. Security report saved to security_report.txt.")
