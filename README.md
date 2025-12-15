### PurpleSnake ###



## Multi-Platform Mini Security Toolkit (Windows & Linux)



## Overview



--- PurpleSnake is a lightweight, educational security toolkit written in C, designed to demonstrate both offensive (Red Team) and defensive (Blue Team) fundamentals at a low level.



--- The project focuses on understanding how common security tools work under the hood, rather than relying on high-level libraries or frameworks.



--- This project is developed strictly for educational and ethical purposes.



## Features

1. TCP Port Scanner

* Detects open, closed, and filtered ports.
* Service name mapping for common ports.
* Cross-platform. (Windows \& Linux).

2. XOR Encrypt / Decrypt Tool.

* File-based XOR encryption.
* Demonstrates basic symmetric cryptography concepts.

3. Packet Sniffer / Network Monitor.

* Windows: Active TCP connection monitor. (PID-based).
* Linux: Raw packet sniffer. (Ethernet → IP → TCP/UDP/ICMP).
* DNS detection and TCP flag inspection.



## Build & Run



🔵 Windows (MinGW / GCC)



* Compile with ->
	
	gcc PurpleSnake.c -o purplesnake -lws2\_32 -liphlpapi



* Run with ->

	./purplesnake.exe



	// Works without administrator privileges. (packet sniffer uses Windows APIs).

	// Raw packet sniffing on Windows is handled via system APIs (not raw sockets).



🟢 Linux



* Compile with ->

	gcc PurpleSnake.c -o purplesnake



* Run with;

	sudo ./purplesnake



	// Run as root. (required for raw packet capture).





## Testing



* Windows tested on standard user environment.
* Linux tested with live traffic. (ICMP, TCP, UDP, DNS).
* Packet sniffer exits automatically after capturing 20 packets.



## Why C?



This project is intentionally written in C to:



* Work close to the operating system \& network stack.
* Understand raw sockets, memory handling, and system calls.
* Avoid abstraction and expose real-world security mechanics.
* Demonstrate performance-oriented, low-level programming.



## Disclaimer



This tool is not intended for illegal use.



* Do NOT scan networks you do not own or have permission for.
* Do NOT use packet sniffing on unauthorized networks.
* The author takes no responsibility for misuse



This project exists solely for learning, research, and demonstration purposes.



## Future Improvements



* Interface selection for packet sniffing.
* Threaded port scanning.
* Output logging.
* Protocol-specific packet analysis.
* Modular architecture.
* BPF-style packet filtering.



## AUTHOR 



Berke Bolsoy

GitHub: https://github.com/Rexlynn


Computer Science Engineering – 1st Year
University of Pécs (PTE)



Cybersecurity & Blue Team Enthusiast
