# Mrežne informacije

{{#include ../../banners/hacktricks-training.md}}

Lokalni servisi koji osluškuju, Unix sockets i mrežno dostupni softver mogu izložiti putanje koje nisu vidljive pri spoljašnjem skeniranju. Počnite od servisa koji osluškuju na hostu i procesa koji je vlasnik svake krajnje tačke.

- [Analiza saobraćaja, firewall-a i izlaznog saobraćaja](traffic-capture-and-firewall-egress.md) obrađuje hvatanje paketa, filtriranje, proxy-je i testove povezivosti.
- [Analiza lokalne mreže i socket-a](local-network-and-socket-triage.md) obrađuje loopback servise, Unix sockets i mreže kontejnera.
- [Injekcija komandi preko socket-a](socket-command-injection.md) obrađuje komande koje se prihvataju preko izloženih lokalnih socket-a.
- Za početni pristup Cisco SD-WAN Manager uređajima, pogledajte [lokalnu eskalaciju privilegija u vManage-u](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); njegov ConfD CLI, REST API i putanje za uvoz u vlasništvu root korisnika razlikuju se od opšte analize socket-a.
{{#include ../../banners/hacktricks-training.md}}
