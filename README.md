# TorRoute

Portable Windows user-mode proxy router.

Commands: start, stop, status, add DOMAIN, remove DOMAIN, list.

Tor must already be running on 127.0.0.1:9050.

Selected domains are sent through Tor SOCKS5. Other requests are sent directly.

Limitation: this is a user-level HTTP proxy. Applications that ignore Windows/WinINET proxy settings or use raw sockets/UDP are not transparently intercepted. A true all-application transparent router normally needs WFP/WinDivert/TUN or process hooks and may require Administrator/driver access.

No Administrator privilege is required by TorRoute itself.
