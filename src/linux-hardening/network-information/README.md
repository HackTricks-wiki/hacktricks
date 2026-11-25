# Network Information

{{#include ../../banners/hacktricks-training.md}}

Local listeners, Unix sockets, and network-facing software may expose paths that are invisible from an external scan. Start with the host's listening services and the process that owns each endpoint.

- [Traffic capture, firewall, and egress triage](traffic-capture-and-firewall-egress.md) covers packet capture, filtering, proxies, and connectivity tests.
- [Local network and socket triage](local-network-and-socket-triage.md) covers loopback services, Unix sockets, and container networks.
- [Socket command injection](socket-command-injection.md) covers commands accepted through exposed local sockets.
- For Cisco SD-WAN Manager appliance footholds, see [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); its ConfD CLI, REST API, and root-owned import paths are distinct from general socket triage.
{{#include ../../banners/hacktricks-training.md}}
