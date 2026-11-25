# Netzwerkinformationen

{{#include ../../banners/hacktricks-training.md}}

Lokale Listener, Unix-Sockets und netzwerkseitig erreichbare Software können Angriffswege eröffnen, die bei einem externen Scan nicht sichtbar sind. Beginne mit den Listening Services des Hosts und dem Prozess, dem jeder Endpunkt gehört.

- [Traffic-Erfassung, Firewall- und Egress-Triage](traffic-capture-and-firewall-egress.md) behandelt die Paketerfassung, Filterung, Proxys und Verbindungstests.
- [Triage lokaler Netzwerke und Sockets](local-network-and-socket-triage.md) behandelt Loopback-Dienste, Unix-Sockets und Containernetzwerke.
- [Socket command injection](socket-command-injection.md) behandelt Befehle, die über offengelegte lokale Sockets angenommen werden.
- Für Footholds auf Cisco-SD-WAN-Manager-Appliances siehe [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); dessen ConfD-CLI, REST-API und Importpfade mit Root-Besitz unterscheiden sich von der allgemeinen Socket-Triage.
{{#include ../../banners/hacktricks-training.md}}
