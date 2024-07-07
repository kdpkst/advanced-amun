# Advanced Amun Honeypot
**Advanced Amun Honeypot** is an extended and enhanced version of the original Amun Honeypot. You can find Amun honeypot here https://github.com/zeroq/amun  
Limitations of original Amun:
- ...
- ...

## Requirements
- 2.6 <= Python < 3
- Docker
- scapy 2.3.3

## Features Extended
- **Proxy Mode**: enable Amun to be a proxy to forward attacking data to a backend machine, and forward the real response from the backend decoy to the attacker.
- **Reverse Shell Spoofing**: dynamically create docker container to emulate reverse shell if the incoming shellcode aims to establish a reverse shell. Usage is as below:
  - change directory to reverseshell_spoofing and execute below commands in order.
  - ```
    sudo chmod +x build_image.sh
    ```
  - ```
    ./build_image.sh
    ```
  - then start the honeypot

 
## Acknowledgments
Truly thanks for the following open-source projects, which have been instrumental in the development of this project:

- [Amun](https://github.com/zeroq/amun)
- [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo)
- [Docker Cuckoo Sandox](https://github.com/blacktop/docker-cuckoo)
- [PE Converter](https://github.com/0xballistics/inject2pe)
- ...







