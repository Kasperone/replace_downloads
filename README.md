# Replace Downloads

This is a Python script that demonstrates intercepting HTTP traffic to identify and replace `.exe` download requests with a different file. It uses the `netfilterqueue` library to intercept packets and the `scapy` library to analyze and modify them. This script is intended for educational purposes to understand packet manipulation and its implications for network security.

## Features
- Intercepts HTTP requests and responses.
- Identifies `.exe` download requests in HTTP traffic.
- Replaces the requested `.exe` file with a specified file hosted online.

## Prerequisites
- Python 3.x
- Linux-based operating system
- `netfilterqueue` library (for packet interception)
- `scapy` library (for packet analysis and modification)

## Installation
Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/replace_downloads.git
cd replace_downloads
```

Install the required libraries:

```bash
pip install scapy netfilterqueue
```

## Usage
Run the script with superuser privileges to intercept and modify packets.

```bash
sudo python3 replace_downloads.py
```

### Notes:
- Ensure your system is configured to forward packets through the Netfilter queue.
- Replace `"HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n"` in the script with the desired URL to redirect `.exe` downloads.

### Configuring iptables
To redirect HTTP traffic to the Netfilter queue, use the following `iptables` commands:

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

For testing on the local machine:

```bash
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -j NFQUEUE --queue-num 0
```

To clear the rules after use:

```bash
sudo iptables --flush
```

## Example:
Run the script and observe its behavior:

Output:

```
[+] exe Request
[+] Replacing file
```

## Troubleshooting
- Ensure you have installed all required libraries.
- Verify that your `iptables` rules are correctly configured.
- Run the script with `sudo` or as root to ensure it has the necessary permissions.

## License
This project is licensed under the MIT License.

## About
This script is part of the course **Learn Python & Ethical Hacking from Scratch** on Udemy. The course covers Python scripting and its application in ethical hacking, network security, and more.

---

### Disclaimer:
This script is for educational purposes only. Use it responsibly and only in environments where you have permission to perform testing. Packet interception and modification without authorization is illegal and unethical.