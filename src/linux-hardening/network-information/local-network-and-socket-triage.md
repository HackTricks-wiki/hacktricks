# Lokales Netzwerk und Socket-Triage

{{#include ../../banners/hacktricks-training.md}}

Nach dem Zugriff auf eine Shell auf einem Linux-Host sind die nützlichsten Netzwerkziele oft nicht extern erreichbar. Nur an Loopback gebundene Dienste, veth-Netzwerke, Unix-Sockets, temporäre Listener, Paketmitschnitte und lokale Firewall-Regeln können Zugangsdaten oder nur lokal erreichbare Angriffsflächen offenlegen.

Diese Seite konzentriert sich auf praktische lokale Post-Exploitation-Techniken, nicht auf allgemeines Remote-Network-Pentesting.

## Loopback- und lokale Diensterkennung

Ermitteln Sie zunächst lauschende Dienste, ihre Bind-Adressen und, sofern die Berechtigungen es zulassen, den zugehörigen Prozess.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Wichtige Muster:

- `127.0.0.1:<port>` oder `[::1]:<port>`: standardmäßig nur vom Host aus erreichbar.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: auf allen IPv4-Schnittstellen erreichbar, sofern nicht gefiltert.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` oder `192.168.0.0/16` auf `veth*`, `docker*`, `br-*`, `cni*`: wahrscheinlich Container- oder lokale Labornetzwerke.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-Sockets unter `/run`, `/var/run`, `/tmp` oder in Anwendungsverzeichnissen: lokale IPC-Angriffsflächen.<sup>[[5]](#references)</sup>

Beim historischen [snapd-Socket-Parsing-Problem, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) solltest du den laufenden Daemon, seinen lokalen API-Socket und die installierte Paket- oder Snap-Revision mit dem Fix für die jeweilige Distribution abgleichen. Der Fehler lag in der Validierung der Socket-Adresse eines Peers durch snapd, nicht in `snap-confine`; eine Datei `snap-confine` mit Set-User-ID-Bit oder eine Upstream-Versionszeichenfolge allein belegt keine Gefährdung. Ubuntu lieferte Fixes mit release-spezifischen Paketversionen aus, und snapd kann unabhängig vom Distributionspaket über einen Snap aktualisiert worden sein. Prüfe den tatsächlich laufenden Build und die Erreichbarkeit des lokalen Sockets, bevor du die privilegierte API-Grenze bewertest. Bei passiver Aufzählung solltest du weder eine speziell präparierte Socket-Anfrage senden noch einen Snap installieren.

Ein Loopback-Listener, der über [`socat` mit `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) gestartet wird, kann lokale Client-Eingaben an ein separates Programm weitergeben. Gleiche den Befehl des Listeners, den Pfad zur ausführbaren Datei, die effektive Identität des Kindprozesses, die lokale Erreichbarkeit und die Authentifizierung ab, bevor du einen benutzerdefinierten Dienst im Besitz von root als Ansatzpunkt für eine Privilegieneskalation wertest. Ein Memory-Safety-Fehler oder ein unsicherer Pfad von Eingabe zu Befehl erfordert Belege aus der konkreten Binärdatei und dem Build; die Portnummer, der `socat`-Prozess oder der Besitz durch root allein belegen dies nicht. Bei passiver Aufzählung solltest du dich auf Prozess-, Socket- und Dateimetadaten beschränken und keine Eingaben an den Dienst senden.

Ein lokaler Salt-Master kann auf den TCP-Ports 4505 und 4506 lauschen, auch auf Loopback oder einem von einem Container veröffentlichten Host-Port. In den [Versionshinweisen zu Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) wird ein Fehler beim unauthentifizierten Zugriff auf Methoden beschrieben, CVE-2020-11651, der in den Upstream-Versionen 2019.2.4 und 3000.2 behoben wurde. Gleiche den Listener mit dem tatsächlichen `salt-master`-Prozess, der erreichbaren Schnittstelle, dem installierten Paket und den Hersteller-Patches sowie der effektiven Container- oder Host-Identität ab, bevor du ihn als Ansatzpunkt für eine Privilegieneskalation wertest; ein Port oder eine Upstream-Version allein ist kein Beweis. Wenn ein Master in einem Container läuft, ist die Auswirkung auf root des Hosts eine separate Grenze: Prüfe, ob ein nutzbarer Host-Runtime-API-Socket in diesen Container eingebunden und von dort aus erreichbar ist. Bei passiver Aufzählung solltest du weder den Salt-Request-Server abfragen noch einen Container erstellen, um die Gefährdung festzustellen. Siehe die [Port-Dokumentation von Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) und die [Triage der Runtime-API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Ordne lokale Ports mit leichtgewichtigen Probes zu.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Verwenden Sie `nmap` lokal, sofern verfügbar.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Verborgene veth- und Container-Subnetze

Containerisierte oder Lab-Umgebungen machen Dienste oft nur über ein Bridge- oder veth-Subnetz erreichbar. Enumeriere Schnittstellen und Routen, bevor du annimmst, dass ein Dienst nicht erreichbar ist.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Finde wahrscheinliche lokale Subnetze.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Untersuche ein entdecktes Subnetz sorgfältig.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Die Technik ist nützlich, wenn ein Webpanel, ein Debug-Endpunkt oder ein Hilfsdienst vor externen Scans verborgen, aber vom kompromittierten Host oder Containernetzwerk aus erreichbar ist.

## Notebook-Service-Tokens über Benutzergrenzen hinweg

Ein Notebook-Dienst auf Loopback kann sich mit einem Start-Token authentifizieren, das in der Prozessausgabe angezeigt wird. Wird diese Ausgabe in ein Protokoll umgeleitet, das für ein anderes lokales Konto lesbar ist, kann das Token eine Benutzergrenze überschreiten und die Codeausführung unter dem Konto des Notebook-Servers ermöglichen. Prüfe den Eigentümer des lauschenden Prozesses, das Protokollziel und dessen Berechtigungen, die aktuelle Token-Konfiguration und die Notebook-Zugriffskontrollen im Zusammenhang, bevor du einen Protokollpfad als Ansatzpunkt für eine Rechteausweitung behandelst. Erfasse bei der passiven Enumeration die Metadaten des Protokolls; gib keine Tokens aus und verbinde dich nicht mit dem Dienst, nur um den Host einzuordnen.

Ein Jupyter-Lab-Dienst kann sein Token auch in einem lesbaren systemd-`ExecStart` oder in der laufenden Befehlszeile (`ps auxww`) offenlegen, statt nur in Startprotokollen. Im beschriebenen Beispiel identifizierten `User=analyst` und `--ServerApp.token` sowohl die Zugangsdaten als auch das Konto hinter einem Listener auf `127.0.0.1:8888`. Mit Host-Zugriff ermöglichten das Token und `ssh -L 8888:127.0.0.1:8888 user@host` den Zugriff auf das Terminal von Jupyter Lab als dieser Dienstbenutzer. Prüfe gemeinsam den effektiven Benutzer der Unit, die Prozessargumente, den Listener und die Gültigkeit des Tokens; eine Bindung an Loopback allein ist keine Autorisierungsgrenze.<sup>[[28]](#references)</sup>

## Lokales Pivoting mit socat oder SSH

Wenn ein Dienst an Loopback gebunden ist, mache ihn über einen zulässigen Kanal verfügbar, statt den Dienst selbst zu ändern.

Leite einen nur lokal verfügbaren HTTP-Dienst mit SSH weiter.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Einen lokalen Port mit `socat` überbrücken, wenn bereits Shell-Zugriff besteht.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Einen Unix-Socket für lokale Tests an TCP weiterleiten.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Dies exploitet für sich genommen nichts. Es macht eine nur lokal erreichbare Oberfläche von deinen Tools aus erreichbar, sodass du wie mit einem normalen Dienst mit ihr interagieren kannst.

## Banner Grabbing und einfache Protokolle

Nicht jeder Dienst verwendet HTTP. Viele lokale Dienste leaken über einen Banner oder ein einzeiliges Protokoll genug Informationen.

Einfache Probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP-Test ohne Browser.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Für TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Ziel ist es, das Protokoll, das Authentifizierungsschema, die Version und das Vertrauen des Dienstes in lokale Clients zu ermitteln.

Bei einem aiohttp-Listener solltest du sowohl die Konfiguration statischer Routen als auch die Version überprüfen. CVE-2024-23334 betrifft aiohttp-Versionen vor 3.9.2, wenn eine statische Route `follow_symlinks=True` aktiviert: Anfragen an diese Route können Dateien außerhalb des statischen Stammverzeichnisses lesen. Läuft der Dienst als root, kann er Dateien offenlegen, auf die root zugreifen kann, sofern die Route erreichbar ist. Ein Versionsbanner oder eine Loopback-Bindung allein belegt weder die anfällige Konfiguration noch den Dateizugriff.<sup>[[27]](#references)</sup>

## Capturing Loopback Traffic

Lokaler Traffic kann Header, Bearer-Tokens, Basic-Auth-Zugangsdaten oder anwendungsspezifische Geheimnisse offenlegen.<sup>[[17]](#references)[[25]](#references)</sup> Führe Mitschnitte nur in autorisierten Umgebungen durch.

Zeichne Loopback-HTTP-Traffic auf.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Einen bestimmten lokalen Dienst erfassen.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Dekodiere Basic Auth aus einem abgefangenen oder protokollierten Header.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Nützliche Zeichenfolgen, nach denen in Textmitschnitten gesucht werden sollte:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS-Key-Logging

Wenn du in einer Lab-Umgebung die Umgebung des Client-Prozesses kontrollieren kannst, lassen sich TLS-Sitzungen mit `SSLKEYLOGFILE` in Wireshark oder kompatiblen Tools entschlüsseln.<sup>[[19]](#references)[[20]](#references)</sup> Das ist hilfreich, um lokalen HTTPS-Traffic zu verstehen, ohne TLS selbst anzugreifen.

Starte einen Client mit aktiviertem Key-Logging.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Zeichne den Datenverkehr gleichzeitig auf.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Lade anschließend `/tmp/tls.pcap` und `/tmp/sslkeys.log` in Wireshark. Das funktioniert nur, wenn die Clientbibliothek NSS-artiges Key Logging unterstützt und du die Umgebung vor dem Verbindungsaufbau festlegen kannst.<sup>[[20]](#references)[[21]](#references)</sup>

## Unix-Socket-Interaktion und Command Injection

Unix-Sockets sind lokale IPC-Endpunkte.<sup>[[5]](#references)</sup> Sie können HTTP-APIs, benutzerdefinierte Protokolle oder unsichere Befehls-Handler bereitstellen.<sup>[[12]](#references)[[14]](#references)</sup>

Ein Socket, der root gehört und für die Gruppe Schreibrechte hat, ist eine Autorisierungsgrenze, aber für sich genommen keine Schwachstelle. Vergleiche seine Gruppe und seinen Berechtigungsmodus mit dem aktuellen Konto, ermittle den lauschenden Prozess und prüfe, welche Eingaben dieser Prozess von Clients akzeptiert, bevor du das Risiko bewertest. Insbesondere kann ein privilegierter Dienst, der übermitteltes PHP ausführt, eine zweite Grenze überschreiten, wenn er außerdem einem vom Aufrufer ausgewählten `php.ini`-Pfad vertraut oder es dem Aufrufer erlaubt, `disable_functions` oder `open_basedir` zu ändern. Prüfe die effektive Konfiguration und den Validierungspfad des Dienstes. Der [PHP-Konfigurationsleitfaden](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) erläutert diese Direktiven. Socket-Metadaten allein belegen keine Codeausführung.

Sockets finden.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Über einen Unix-Socket mit HTTP kommunizieren.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Mit einem Raw Socket interagieren.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Wenn socket-Eingaben, die von Benutzern kontrolliert werden, an eine shell oder einen privilegierten Helfer übergeben werden, kann daraus command injection entstehen.<sup>[[26]](#references)</sup> Ein gezieltes Beispiel findest du unter [Socket Command Injection](socket-command-injection.md).

## nftables-Überprüfung und autorisierte Regeländerungen

Lokale Firewall-Regeln können erklären, warum ein Dienst lokal sichtbar ist, aber remote blockiert wird, oder warum ein hoher Port über eine Schnittstelle nicht erreichbar ist.<sup>[[22]](#references)</sup>

Überprüfe die Regeln.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Suche nach Drops, die einen Zielport betreffen.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Entfernen Sie in einem autorisierten Labor eine bestimmte blockierende Regel anhand ihres Handles.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Ziehe es vor, den exakten Handle zu löschen, statt vollständige Tabellen zu leeren. Dabei wird der genaue Filter identifiziert, der das Verhalten verursacht, und nur diese Regel geändert.<sup>[[22]](#references)</sup>

## Schneller Workflow

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Priorisieren Sie Dienste, die nur lokal verfügbar sind, mit einem privilegierteren Benutzer ausgeführt werden, Admin-/Debug-Funktionen bereitstellen oder Loopback-/Container-Netzwerk-Clients vertrauen.

## References

- [1] [ss(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IPv6-Adressierungsarchitektur](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Umleitungen (Bash-Referenzhandbuch)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout-Aufruf (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port-Scan-Techniken (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host-Erkennung (Nmap-Referenzhandbuch)](https://nmap.org/book/man-host-discovery.html)
- [10] [Portangabe und Scan-Reihenfolge (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD-Handbuchseite](https://man.openbsd.org/nc.1)
- [14] [Handbuch für das curl-Befehlszeilentool](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL-Dokumentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Das HTTP-Authentifizierungsschema „Basic“](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64-Aufruf (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL-Dokumentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark-Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark-Benutzerhandbuch](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables-Handbuch](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Adresszuweisung für private Internets (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Das OAuth-2.0-Autorisierungsframework: Verwendung von Bearer-Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Unzureichende Neutralisierung spezieller Elemente in einem Betriebssystembefehl](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Sicherheitshinweis der aiohttp-Maintainer: Traversierung statischer Routen mit follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — Jupyter-Token über systemd und Prozessargumente offengelegt](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
