# Network Information

{{#include ../../banners/hacktricks-training.md}}

Local listeners, Unix sockets, and network-facing software may expose paths that are invisible from an external scan. Start with the host's listening services and the process that owns each endpoint.

- [Traffic capture, firewall, and egress triage](traffic-capture-and-firewall-egress.md) covers packet capture, filtering, proxies, and connectivity tests.
- [Local network and socket triage](local-network-and-socket-triage.md) covers loopback services, Unix sockets, and container networks.
- [Socket command injection](socket-command-injection.md) covers commands accepted through exposed local sockets.
- [Cisco vManage](cisco-vmanage.md) documents a product-specific target and related checks.
