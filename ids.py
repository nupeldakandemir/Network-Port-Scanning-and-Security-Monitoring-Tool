from datetime import datetime

def analyze_ports(ip, ports):
    alerts = []

    # Kural 1: Çok fazla açık port varsa
    if len(ports) > 15:
        alerts.append(f"{ip} adresinde çok fazla açık port tespit edildi (>{len(ports)}). Bu bir port tarama olabilir.")

    # Kural 2: SSH (22) portu açık
    if 22 in ports:
        alerts.append(f"{ip} adresinde SSH (22) portu açık. Brute force saldırısı riski olabilir.")

    # Kural 3: Telnet (23) portu açık
    if 23 in ports:
        alerts.append(f"{ip} adresinde Telnet (23) portu açık. Bu protokol güvenli değildir.")

    # Kural 4: RDP (3389) portu açık
    if 3389 in ports:
        alerts.append(f"{ip} adresinde RDP (3389) portu açık. Uzak erişim açığı olabilir.")

    # Kural 5: Web servisleri (80 ve 443) açık
    if 80 in ports or 443 in ports:
        alerts.append(f"{ip} adresinde Web servisleri tespit edildi (80/443).")

    # Kural 6: Şüpheli özel portlar
    suspicious_ports = [1337, 31337, 54321]
    for p in suspicious_ports:
        if p in ports:
            alerts.append(f"{ip} adresinde şüpheli port {p} açık. Bu portlar kötü amaçlı yazılımlar tarafından kullanılabilir.")

    # Log'a yaz
    if alerts:
        with open("alerts.log", "a") as log_file:
            log_file.write(f"[{datetime.now()}] {ip} için uyarılar:\n")
            for alert in alerts:
                log_file.write(f" - {alert}\n")
            log_file.write("\n")

    return alerts
