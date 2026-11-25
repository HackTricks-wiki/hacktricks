# Informazioni di rete

{{#include ../../banners/hacktricks-training.md}}

I servizi in ascolto locali, i socket Unix e i software esposti alla rete possono rivelare percorsi invisibili da una scansione esterna. Inizia dai servizi in ascolto sull'host e dal processo proprietario di ciascun endpoint.

- [Analisi del traffico, firewall e traffico in uscita](traffic-capture-and-firewall-egress.md) tratta l'acquisizione dei pacchetti, il filtraggio, i proxy e i test di connettività.
- [Analisi della rete locale e dei socket](local-network-and-socket-triage.md) tratta i servizi loopback, i socket Unix e le reti dei container.
- [Command injection tramite socket](socket-command-injection.md) tratta i comandi accettati tramite socket locali esposti.
- Per gli accessi iniziali agli appliance Cisco SD-WAN Manager, consulta [escalation dei privilegi locali in vManage](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); la sua CLI ConfD, la REST API e i percorsi di importazione con proprietario root sono distinti dall'analisi generale dei socket.
{{#include ../../banners/hacktricks-training.md}}
