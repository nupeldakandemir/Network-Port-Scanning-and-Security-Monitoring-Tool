import json
import os
from scanner import scan_ports
from ids import analyze_ports

def get_result_filename(ip):
    return f"scan_{ip.replace('.', '_')}.json"

def save_scan_results(ip, ports):
    data = {
        "ip": ip,
        "ports": ports
    }
    filename = get_result_filename(ip)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def load_previous_results(ip):
    filename = get_result_filename(ip)
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return None

if __name__ == "__main__":
    ip = input("Hedef IP adresini girin: ")
    ports = scan_ports(ip, port_range=(20, 120))
    print(f"Açık portlar: {ports}")

    # IDS analizi
    alerts = analyze_ports(ip, ports)
    if alerts:
        print("Güvenlik Uyarıları:")
        for alert in alerts:
            print(f" - {alert}")

    # Önceki sonuçları yükle
    previous = load_previous_results(ip)
    if previous:
        print(f"\n Önceki tarama ({previous['ip']}): {previous['ports']}")
        newly_opened = list(set(ports) - set(previous["ports"]))
        newly_closed = list(set(previous["ports"]) - set(ports))

        print("\n Değişiklikler:")
        if newly_opened:
            print(f" + Yeni açılan portlar: {newly_opened}")
        if newly_closed:
            print(f" - Kapanan portlar: {newly_closed}")
        if not newly_opened and not newly_closed:
            print("   Hiçbir değişiklik yok.")
    else:
        print("\n Önceki tarama bulunamadı. Bu ilk kayıt.")

    # Yeni sonuçları kaydet
    save_scan_results(ip, ports)
