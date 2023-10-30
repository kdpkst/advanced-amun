# Advanced Amun Honeypot
**Advanced Amun Honeypot** is an extended and enhanced version of the original Amun Honeypot. You can find Amun honeypot here https://github.com/zeroq/amun

## Requirements
- 2.6 <= Python < 3
- Docker

## Advanced Features
- **Proxy Mode**: enable Amun to be a proxy to forward attacking data to a backend machine, and forward the real response from the backend decoy to the attacker.
- **Reverse Shell Spoofing**: dynamically create docker container to emulate reverse shell if the incoming shellcode aims to establish a reverse shell.
  - **how to use**: cd into reverseshell_spoofing.
  -                 sudo chmod +x build_image.sh
  -                 ./build._image.sh
  -                 then start the honeypot





