# Advanced Amun Honeypot
**Advanced Amun Honeypot** is an extended and enhanced version of the original Amun Honeypot. You can find Amun honeypot here https://github.com/zeroq/amun

## Features added
- **Windows Shell for Emulated Telnet Service**: The default shell in the emulated Telnet service is replaced with a Windows shell.
- **Proxy Mode**: Advanced Amun Honeypot introduces a proxy mode that takes deception to the next level. Here's how it works:

   - When an attacker uses the Telnet service, they are prompted to enter commands.
   - If the proxy mode is activated, all commands entered by the attacker are redirected to a real machine, known as the "Backend Decoy."
   - The Backend Decoy processes the commands and generates genuine responses.
   - The responses from the Backend Decoy are sent back to the honeypot, making it appear as if the attacker is interacting with a real system.
   - The honeypot then forwards the genuine responses to the attacker, creating a highly convincing deception environment.





