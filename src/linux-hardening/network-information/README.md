# Informations réseau

{{#include ../../banners/hacktricks-training.md}}

Les services en écoute locaux, les sockets Unix et les logiciels exposés au réseau peuvent révéler des chemins invisibles lors d’un scan externe. Commencez par examiner les services en écoute de l’hôte et le processus qui possède chaque point de terminaison.

- [Capture du trafic, pare-feu et triage des connexions sortantes](traffic-capture-and-firewall-egress.md) traite de la capture de paquets, du filtrage, des proxys et des tests de connectivité.
- [Triage du réseau local et des sockets](local-network-and-socket-triage.md) traite des services loopback, des sockets Unix et des réseaux de conteneurs.
- [Socket command injection](socket-command-injection.md) traite des commandes acceptées via des sockets locaux exposés.
- Pour les footholds sur des appliances Cisco SD-WAN Manager, consultez [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md) ; sa CLI ConfD, son API REST et ses chemins d’import appartenant à root sont distincts du triage général des sockets.

{{#include ../../banners/hacktricks-training.md}}
