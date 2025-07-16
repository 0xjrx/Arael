# Arael (SYN Flooder)

Arael is a Python-based tool designed to perform SYN flood attacks. It can be used for network stress testing, security research, or demonstrating denial-of-service attack principles. This tool sends a large number of SYN packets to a target, aiming to exhaust its connection resources. 

**I started writing this during a college lecture because I was bored. I dont even known if it still works, just thought I'd add a readme so my profile looks nicer lol**

**Disclaimer:** This tool is intended for educational and ethical testing purposes only. Unauthorized use of this tool against any network or system is illegal and unethical. The author is not responsible for any misuse or damage caused by this software. Always ensure you have explicit permission before using this tool on any network you do not own or manage.

## Features

* **SYN Flood Attack:** Generates and sends SYN packets to a specified target.

* **Randomized Source IP/Port:** Can use randomized source IP addresses and ports to make tracing more difficult.

* **Packet Count Control:** Allows specifying the number of packets to send.

* **Flexible Packet Sending:** Supports two methods for sending packets:

    * **Scapy Integration:** Utilizes the `scapy` library for robust and high-level packet crafting and sending.

    * **Raw Socket Implementation:** Includes a lower-level method for manually building TCP packets and sending them via raw sockets.

## Installation

Arael requires Python 3 and the `scapy` library.

1.  **Clone the repository:**

    ```
    git clone [https://github.com/0xjrx/Arael.git](https://github.com/0xjrx/Arael.git)
    cd Arael

    ```

2.  **Install Scapy:**

    ```
    pip install scapy

    ```

    *Note: You might need to install `libpcap-dev` (on Linux) or `Npcap`/`WinPcap` (on Windows) for Scapy to function correctly, as it relies on low-level packet capture and injection libraries.*

## Usage

Arael requires root/administrator privileges to send raw packets.
```
sudo python3 arael.py -t

```
**Arguments:**

* `-t` or `--target`: Specify the target IP address (e.g., `192.168.1.1`).

* `-p` or `--port`: Specify the target port (e.g., `80`, `443`).

* `-c` or `--count`: Specify the amount of SYN packets to send.

**Example:**

To send 1000 SYN packets to `192.168.1.100` on port `80`:

```
sudo python3 arael.py -t 192.168.1.100 -p 80 -c 1000

```
## How it Works (Briefly)

Arael implements two primary methods for sending SYN packets:

1.  **`send_tcp()` (Default/Active):** This function leverages the `scapy` library. It constructs `IP` and `TCP` layers, sets the SYN flag (`"S"`), and randomizes the source IP, source port, sequence number, and window size for each packet. `scapy` handles the low-level details of sending these crafted packets. This is the function called when the script is executed.

2.  **`legacy_send()` (Alternative/Raw Sockets):** This function manually builds the TCP packet header using `struct.pack` and calculates the TCP checksum, including a pseudo-header. It then uses Python's `socket` module with `socket.SOCK_RAW` to send the raw TCP packet directly. This method offers more granular control but is generally more complex to implement and maintain than using `scapy`. While present in the code, `legacy_send()` is not actively called by default.

Both methods aim to send SYN packets to the target, attempting to initiate many half-open connections and consume server resources.

## Troubleshooting

* **Permission Denied:**

    * Ensure you are running the script with `sudo` (on Linux/macOS) or as an Administrator (on Windows). Raw socket operations require elevated privileges.

* **Scapy Errors:**

    * Verify that `scapy` is correctly installed (`pip install scapy`).

    * Check if `libpcap-dev` (Linux) or `Npcap`/`WinPcap` (Windows) is installed and configured. Scapy relies on these system libraries for packet injection.

* **No Packets Sent/Received:**

    * Confirm your target IP and port are correct and reachable.

    * Check your firewall rules on both the attacking and target machines. Firewalls might block raw outgoing or incoming SYN packets.

    * Ensure no other network monitoring tools are interfering.

