import csv
from collections import defaultdict
from pathlib import Path

DATA_FILE = Path(__file__).parent / "sample_traffic.csv"
PACKET_THRESHOLD = 1000


def analyze_traffic():
    packets_by_ip = defaultdict(int)
    total_packets = 0
    total_records = 0

    with DATA_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required = {"source_ip", "packet_count"}

        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                "CSV must contain source_ip and packet_count columns."
            )

        for row in reader:
            ip = row["source_ip"].strip()
            packets = int(row["packet_count"])

            if not ip or packets < 0:
                continue

            packets_by_ip[ip] += packets
            total_packets += packets
            total_records += 1

    print("NETWORK TRAFFIC ANALYSIS")
    print("-" * 30)
    print(f"Records analyzed: {total_records}")
    print(f"Total packets: {total_packets}")

    print("\nPackets by source IP:")

    for ip, count in sorted(
        packets_by_ip.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{ip}: {count} packets")

    print("\nHigh-volume sources (review required):")

    alerts = 0

    for ip, count in sorted(
        packets_by_ip.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        if count >= PACKET_THRESHOLD:
            print(f"REVIEW: {ip} generated {count} packets")
            alerts += 1

    if alerts == 0:
        print("No sources crossed the configured threshold.")

    print("\nNote: High traffic is not proof of an attack.")


if __name__ == "__main__":
    analyze_traffic()
