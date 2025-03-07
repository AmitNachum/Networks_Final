import pyshark
import matplotlib.pyplot as plt
import os

# Define the correct file paths
pcap_folder = os.path.join(os.getcwd(), "wireshark_files")  # Get absolute path to the folder

# Define the correct file paths for the new pcapng files
pcap_files = {
    "Chrome": os.path.join(pcap_folder, "chrom.pcapng"),
    "Firefox": os.path.join(pcap_folder, "firefox.pcapng"),
    "Spotify": os.path.join(pcap_folder, "spotify.pcapng"),
    "YouTube Video": os.path.join(pcap_folder, "videoYoutube.pcapng"),
    "Zoom": os.path.join(pcap_folder, "ZoomRecord.pcapng")
}

# Check if all files exist before running the analysis
missing_files = [name for name, path in pcap_files.items() if not os.path.exists(path)]
if missing_files:
    print("❌ Error: The following .pcapng files are missing:", missing_files)
    print("Make sure all files are inside the 'wireshark_files' folder and restart the script.")
    exit(1)

print("✅ All required .pcapng files found. Starting analysis...\n")

# Define a fixed color mapping for each application (light & distinguishable)
color_map = {
    "Chrome": "#1f77b4",  # Light Blue
    "Firefox": "#ffcc00",  # Light Yellow
    "Spotify": "#2ca02c",  # Light Green
    "YouTube Video": "#d62728",  # Light Red
    "Zoom": "#9467bd"  # Light Purple
}

# Function to analyze packets and extract required characteristics
def analyze_pcap(file_path):
    try:
        capture = pyshark.FileCapture(file_path, display_filter="ip or tcp or tls")

        # Characteristics
        packet_sizes = []
        ttl_values = []
        dscp_values = []
        tcp_flags = {"SYN": 0, "ACK": 0, "FIN": 0}
        tls_versions = []

        for packet in capture:
            try:
                # D. Packet Sizes
                packet_sizes.append(int(packet.length))

                # A. IP Header Fields - TTL & DSCP
                if hasattr(packet, 'ip'):
                    ttl_values.append(int(packet.ip.ttl))
                    if hasattr(packet.ip, 'dsfield'):
                        dscp_values.append(int(packet.ip.dsfield, 16))  # DSCP value

                # B. TCP Header Fields - Flags (SYN, ACK, FIN) using bitwise operations
                if hasattr(packet, 'tcp'):
                    flags = int(packet.tcp.flags, 16)  # Convert from hex to integer
                    if flags & 0x02:  # SYN flag
                        tcp_flags["SYN"] += 1
                    if flags & 0x10:  # ACK flag
                        tcp_flags["ACK"] += 1
                    if flags & 0x01:  # FIN flag
                        tcp_flags["FIN"] += 1

                # C. TLS Header Fields - TLS Version
                if hasattr(packet, 'tls'):
                    if hasattr(packet.tls, 'handshake_version'):
                        try:
                            tls_versions.append(int(packet.tls.handshake_version, 16))  # Convert from hex
                        except ValueError:
                            pass  # Ignore conversion errors

            except AttributeError:
                continue

        capture.close()
        return packet_sizes, ttl_values, dscp_values, tcp_flags, tls_versions

    except Exception as e:
        print(f"⚠️ Error processing {file_path}: {e}")
        return [], [], [], {"SYN": 0, "ACK": 0, "FIN": 0}, []

# Create subplots for each characteristic
fig, axs = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle("Network Traffic Characteristics Across Applications", fontsize=14)

# Process and plot results for each characteristic
for idx, (name, file) in enumerate(pcap_files.items()):
    packet_sizes, ttl_values, dscp_values, tcp_flags, tls_versions = analyze_pcap(file)

    # Use the correct color for the application
    app_color = color_map[name]

    # A. IP Header Fields - TTL Distribution
    if ttl_values:
        axs[0, 0].hist(ttl_values, bins=50, alpha=0.8, label=name, color=app_color, edgecolor="black")
    axs[0, 0].set_title("TTL Distribution")
    axs[0, 0].set_xlabel("TTL Value")
    axs[0, 0].set_ylabel("Frequency")

    # B. TCP Header Fields - Flags (SYN, ACK, FIN)
    if sum(tcp_flags.values()) > 0:
        x_position = [0, 1, 2]
        flags = [tcp_flags["SYN"], tcp_flags["ACK"], tcp_flags["FIN"]]
        axs[0, 1].bar(
            [x + idx * 0.15 for x in x_position], flags, width=0.15, color=app_color, label=name, alpha=0.8, edgecolor="black"
        )
    axs[0, 1].set_title("TCP Flag Distribution")
    axs[0, 1].set_xticks(x_position)
    axs[0, 1].set_xticklabels(["SYN", "ACK", "FIN"])
    axs[0, 1].set_ylabel("Count")

    # C. TLS Header Fields - TLS Version Distribution
    if tls_versions:
        axs[1, 0].set_title("TLS Version Distribution")
        axs[1, 0].hist(tls_versions, bins=10, alpha=0.8, label=name, color=app_color, edgecolor="black")
    else:
        axs[1, 0].set_title("TLS Version Distribution")
    axs[1, 0].set_xlabel("TLS Version")
    axs[1, 0].set_ylabel("Frequency")

    # D. Packet Size Distribution
    if packet_sizes:
        axs[1, 1].hist(packet_sizes, bins=50, alpha=0.8, label=name, color=app_color,edgecolor="black",linewidth=0.12222555)
    axs[1, 1].set_title("Packet Size Distribution")
    axs[1, 1].set_xlabel("Packet Size (Bytes)")
    axs[1, 1].set_ylabel("Frequency")

# Add legends to all subplots
for ax in axs.flat:
    ax.legend(fontsize=10, frameon=True)

# Save the figure without plt.show()
plt.tight_layout()
plt.savefig("traffic_characteristics.png", dpi=300)

print("\n✅ Analysis complete! The plots have been saved as 'traffic_characteristics.png'.")
