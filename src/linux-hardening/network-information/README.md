# Informacje o sieci

{{#include ../../banners/hacktricks-training.md}}

Lokalne usługi nasłuchujące, gniazda Unix i oprogramowanie dostępne przez sieć mogą udostępniać ścieżki niewidoczne podczas skanowania z zewnątrz. Zacznij od usług nasłuchujących na hoście i procesu, który obsługuje każdy punkt końcowy.

- [Analiza ruchu, zapory i ruchu wychodzącego](traffic-capture-and-firewall-egress.md) obejmuje przechwytywanie pakietów, filtrowanie, serwery proxy i testy łączności.
- [Analiza sieci lokalnej i gniazd](local-network-and-socket-triage.md) obejmuje usługi loopback, gniazda Unix i sieci kontenerów.
- [Wstrzykiwanie poleceń przez gniazdo](socket-command-injection.md) dotyczy poleceń przyjmowanych przez udostępnione gniazda lokalne.
- W przypadku uzyskania dostępu do urządzenia Cisco SD-WAN Manager zobacz [eskalację uprawnień lokalnych w vManage](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md); jego CLI ConfD, REST API i ścieżki importu z prawami roota różnią się od ogólnej analizy gniazd.
{{#include ../../banners/hacktricks-training.md}}
