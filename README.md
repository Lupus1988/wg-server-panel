WG Server Panel
Lightweight WireGuard management panel for Raspberry Pi and Linux servers.
No Docker.  
Minimal dependencies.  
Simple installation.
Built with Python + Flask/Gunicorn.
---
Features
Single-server WireGuard management panel
automatic client IP allocation
QR code client configuration
client configuration download
client import
client delete
online/offline tunnel detection
traffic statistics
backup export
backup import
Dynu DDNS integration
automatic endpoint detection
manual endpoint override
dynamic DNS endpoint support
client access levels:
Level 1 = VPN client ↔ server
Level 2 = VPN client ↔ server ↔ VPN clients
Level 3 = Level 2 + selected LAN targets
selected LAN targets as positive list
automatic LAN network suggestion during server generation
editable LAN network confirmation during server generation
router forwarding hint for UDP 51820
---
Scope
This project is a single-server WireGuard panel.
It is intentionally focused on:
one WireGuard server
its VPN clients
selected LAN target access
clear and predictable access control
It does not provide multi-server mesh management.
---
Requirements
Debian / Ubuntu / Raspberry Pi OS
WireGuard
Python 3
---
Installation
Clone the repository:
```bash
git clone https://github.com/Lupus1988/wg-server-panel.git
cd wg-server-panel
sudo ./install.sh
```
After installation the panel is available at:
`http://SERVER-IP:5000`
---
Default paths
`/opt/wg-panel/app.py`
`/opt/wg-panel/server.json`
`/opt/wg-panel/clients/clients.json`
`/opt/wg-panel/lan-targets/lan-targets.json`
`/etc/wireguard/wg0.conf`
---
Access levels
Level 1
Client can access:
the WireGuard server
Client cannot access:
other VPN clients
LAN targets
Level 2
Client can access:
the WireGuard server
other local VPN clients
Client cannot access:
LAN targets
Level 3
Client can access:
the WireGuard server
other local VPN clients
selected LAN targets from the panel
Client cannot access:
the whole LAN automatically
---
LAN targets
LAN access is handled through an explicit positive list.
Only clients with Level 3 may access configured LAN targets.
If the local LAN subnet changes later, affected Level-3 clients may need an updated client configuration.
---
Server generation
When generating a new server, the panel:
creates new WireGuard server keys
resets the server configuration
removes existing clients
automatically suggests the detected local LAN subnet
lets the user confirm or adjust that subnet before saving
Important:
UDP port 51820 must be forwarded on the router
all old client configurations become invalid after server regeneration
---
Notes
This panel manages WireGuard on the server side.
Existing client configurations may need to be reimported when relevant routed subnets change.
Example configuration files in `example-config/` are placeholders only and must be adapted for productive use.
---
License
See `LICENSE`.
