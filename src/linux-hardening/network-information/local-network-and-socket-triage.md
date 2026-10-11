# Lokales Netzwerk- und Socket-Triage

{{#include ../../banners/hacktricks-training.md}}

Nachdem du eine Shell auf einem Linux-Host erhalten hast, sind die interessantesten Netzwerkziele oft nicht extern erreichbar. Nur an Loopback gebundene Dienste, veth-Netzwerke, Unix-Sockets, temporäre Listener, Packet Captures und lokale Firewall-Regeln können Zugangsdaten oder nur lokal erreichbare Angriffsflächen offenlegen.

Diese Seite konzentriert sich auf praktische lokale Post-Exploitation-Techniken und nicht auf allgemeines Remote Network Pentesting.

## Loopback- und lokale Diensterkennung

Ermittle zunächst die lauschenden Dienste, ihre Bind-Adressen und, sofern die Berechtigungen es erlauben, den zugehörigen Prozess.<sup>[[1]](#references)[[2]](#references)</sup>

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

Untersuchen Sie beim historischen [snapd-Problem mit der Socket-Analyse, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) den laufenden Daemon, seinen lokalen API-Socket sowie die installierte Paket- oder Snap-Revision und prüfen Sie, ob der Fix für diese Distribution enthalten ist. Der Fehler betraf die Validierung der Socket-Adresse eines Peers durch snapd, nicht `snap-confine`; eine Datei `snap-confine` mit set-user-ID oder eine Upstream-Versionszeichenfolge allein belegt keine Anfälligkeit. Ubuntu veröffentlichte Fixes unter release-spezifischen Paketversionen, und snapd kann unabhängig vom Distributionspaket über einen Snap aktualisiert worden sein. Prüfen Sie den tatsächlich laufenden Build und die Erreichbarkeit des lokalen Sockets, bevor Sie die privilegierte API-Grenze bewerten. Passive enumeration sollte weder eine speziell erstellte Socket-Anfrage senden noch einen Snap installieren.

Ein über [`socat` mit `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) gestarteter Loopback-Listener kann lokale Client-Eingaben an ein separates Programm weitergeben. Prüfen Sie den Befehl des Listeners, den Pfad der ausführbaren Datei, die effektive Identität des Child-Prozesses, die lokale Erreichbarkeit und die Authentifizierung, bevor Sie einen benutzerdefinierten Dienst im Besitz von root als möglichen Privilege-Escalation-Ansatz einstufen. Ein Memory-Safety-Fehler oder ein unsicherer Eingabe-zu-Befehl-Pfad erfordert Belege aus der konkreten Binärdatei und dem Build; die Portnummer, der `socat`-Prozess oder der Besitz durch root allein belegen einen solchen Fehler nicht. Passive enumeration sollte bei Prozess-, Socket- und Datei-Metadaten enden, anstatt Eingaben an den Dienst zu senden.

Ein lokaler Salt-Master kann auf TCP 4505 und 4506 lauschen, auch auf Loopback oder einem über einen Container veröffentlichten Host-Port. [Die Versionshinweise für Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) beschreiben eine nicht authentifizierte Schwachstelle beim Methodenzugriff, CVE-2020-11651, die in den Upstream-Versionen 2019.2.4 und 3000.2 behoben wurde. Prüfen Sie den Listener anhand des tatsächlichen `salt-master`-Prozesses, der erreichbaren Schnittstelle, des installierten Pakets und der Hersteller-Patches sowie seiner effektiven Container- oder Host-Identität, bevor Sie ihn als möglichen Privilege-Escalation-Ansatz einstufen; ein Port oder eine Upstream-Version allein ist kein Beweis. Läuft ein Master in einem Container, ist eine Auswirkung auf root-Rechte des Hosts eine separate Grenze: Prüfen Sie, ob ein nutzbarer Host-Runtime-API-Socket in diesen Container eingebunden und von dort aus zugänglich ist. Passive enumeration sollte weder den Salt-Request-Server abfragen noch einen Container erstellen, um die Anfälligkeit festzustellen. Siehe [Salts Dokumentation zu Ports](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) und [Triage der Runtime-API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Erfassen Sie lokale Ports mit leichtgewichtigen Probes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Verwende `nmap` lokal, sofern verfügbar.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Versteckte veth- und Container-Subnetze

Container- oder Laborumgebungen stellen Dienste oft nur über ein Bridge- oder veth-Subnetz bereit. Zähle Schnittstellen und Routen auf, bevor du annimmst, dass ein Dienst nicht erreichbar ist.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Wahrscheinliche lokale Subnetze ermitteln.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Ein entdecktes Subnetz sorgfältig untersuchen.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Die Technik ist nützlich, wenn ein Web-Panel, ein Debug-Endpoint oder ein Hilfsdienst vor externen Scans verborgen, aber vom kompromittierten Host oder Container-Netzwerk aus erreichbar ist.

Ein Loopback-Notebook-Dienst kann sich mit einem Startup-Token authentifizieren, das in der Prozessausgabe ausgegeben wird. Wird diese Ausgabe in ein Log umgeleitet, das für ein anderes lokales Konto lesbar ist, kann der Token eine Benutzergrenze überschreiten und Codeausführung unter dem Konto des Notebook-Servers ermöglichen. Gleichen Sie den Eigentümer des lauschenden Prozesses, das Log-Ziel und dessen Berechtigungen, die aktuelle Token-Konfiguration und die Notebook-Zugriffskontrollen ab, bevor Sie einen Log-Pfad als Ansatzpunkt für eine Rechteausweitung betrachten. Erfassen Sie bei der passiven Aufklärung Log-Metadaten; geben Sie keine Tokens aus und verbinden Sie sich nicht mit dem Dienst, nur um den Host einzuordnen.

## Lokaler Pivot mit socat oder SSH

Wenn ein Dienst an Loopback gebunden ist, leiten Sie ihn über einen zulässigen Kanal weiter, anstatt den Dienst selbst zu ändern.

Leiten Sie einen nur lokal verfügbaren HTTP-Dienst mit SSH weiter.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Leiten Sie einen lokalen Port mit `socat` weiter, wenn Sie bereits Shell-Zugriff haben.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Einen Unix-Socket für lokale Tests an TCP weiterleiten.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Dies nutzt für sich genommen nichts aus. Es macht eine nur lokal erreichbare Angriffsfläche von deinen Tools aus erreichbar, sodass du wie mit einem normalen Dienst damit interagieren kannst.

## Banner Grabbing und einfache Protokolle

Nicht jeder Dienst verwendet HTTP. Viele lokale Dienste geben über einen Banner oder ein Ein-Zeilen-Protokoll genügend Informationen preis.

Einfache Probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP-Prüfung ohne Browser.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Für TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Ziel ist es, Protokoll, Authentifizierungsschema und Version zu ermitteln und festzustellen, ob der Dienst lokalen Clients vertraut.

Prüfen Sie bei einem aiohttp-Listener neben der Version auch die Konfiguration statischer Routen. CVE-2024-23334 betrifft aiohttp-Versionen vor 3.9.2, wenn eine statische Route `follow_symlinks=True` aktiviert: Anfragen an diese Route können Dateien außerhalb des statischen Stammverzeichnisses lesen. Läuft der Dienst als root, kann er dadurch Dateien zugänglich machen, die für root lesbar sind, sofern die Route erreichbar ist. Ein Versionsbanner oder eine Loopback-Bindung allein belegt weder eine anfällige Konfiguration noch den Zugriff auf Dateien.<sup>[[27]](#references)</sup>

## Loopback-Datenverkehr erfassen

Lokaler Datenverkehr kann Header, Bearer-Tokens, Basic-Auth-Zugangsdaten oder anwendungsspezifische Geheimnisse offenlegen.<sup>[[17]](#references)[[25]](#references)</sup> Erfassen Sie Datenverkehr nur in autorisierten Umgebungen.

Erfassen Sie Loopback-HTTP-Datenverkehr.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Einen bestimmten lokalen Dienst mitschneiden.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Basic Auth aus einem abgefangenen oder protokollierten Header decodieren.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Nützliche Strings, nach denen in Textmitschnitten gesucht werden sollte:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS-Schlüsselprotokollierung

Wenn du in einer Lab-Umgebung den Prozess des Clients kontrollieren kannst, kann `SSLKEYLOGFILE` dafür sorgen, dass TLS-Sitzungen in Wireshark oder kompatiblen Tools entschlüsselt werden können.<sup>[[19]](#references)[[20]](#references)</sup> Das ist nützlich, um lokalen HTTPS-Traffic zu verstehen, ohne TLS selbst anzugreifen.

Starte einen Client mit aktivierter Schlüsselprotokollierung.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Zeichne den Datenverkehr gleichzeitig auf.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Laden Sie anschließend `/tmp/tls.pcap` und `/tmp/sslkeys.log` in Wireshark. Das funktioniert nur, wenn die Clientbibliothek NSS-artiges Key Logging unterstützt und Sie die Umgebung festlegen können, bevor die Verbindung hergestellt wird.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaktion mit Unix-Sockets und Command Injection

Unix-Sockets sind lokale IPC-Endpunkte.<sup>[[5]](#references)</sup> Sie können HTTP-APIs, benutzerdefinierte Protokolle oder unsichere Command-Handler bereitstellen.<sup>[[12]](#references)[[14]](#references)</sup>

Ein root-eigener Socket mit Schreibberechtigung für die Gruppe bildet eine Autorisierungsgrenze, ist aber für sich genommen keine Schwachstelle. Vergleichen Sie Gruppe und Modus mit dem aktuellen Konto, ermitteln Sie den lauschenden Prozess und prüfen Sie, welche Eingaben dieser Prozess von Clients akzeptiert, bevor Sie das Risiko bewerten. Insbesondere kann ein privilegierter Dienst, der übermittelten PHP-Code ausführt, eine weitere Grenze überschreiten, wenn er außerdem einem vom Aufrufer gewählten `php.ini`-Pfad vertraut oder dem Aufrufer erlaubt, `disable_functions` oder `open_basedir` zu ändern. Prüfen Sie die effektive Konfiguration und den Validierungspfad des Dienstes. Der [PHP-Konfigurationsleitfaden](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) erläutert diese Direktiven. Socket-Metadaten allein belegen keine Codeausführung.

Suchen Sie nach Sockets.<sup>[[1]](#references)[[5]](#references)</sup>

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

Wenn benutzergesteuerte Socket-Eingaben an eine Shell oder einen privilegierten Helfer weitergegeben werden, kann daraus eine Command Injection werden.<sup>[[26]](#references)</sup> Ein gezieltes Beispiel finden Sie unter [Socket Command Injection](socket-command-injection.md).

## nftables Review and Authorized Rule Changes

Lokale Firewall-Regeln können erklären, warum ein Dienst lokal sichtbar, aber remote blockiert ist, oder warum ein hoher Port über eine Schnittstelle nicht erreichbar erscheint.<sup>[[22]](#references)</sup>

Regeln überprüfen.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Suchen Sie nach verworfenen Paketen, die einen Zielport betreffen.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Entfernen Sie in einem autorisierten Labor eine bestimmte blockierende Regel anhand ihres Handles.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Lösche vorzugsweise den genauen Handle, statt ganze Tabellen zu leeren. Dabei wird der präzise Filter identifiziert, der das Verhalten verursacht, und nur diese Regel geändert.<sup>[[22]](#references)</sup>

## Schnellablauf

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Priorisieren Sie Dienste, die nur lokal erreichbar sind, unter einem stärker privilegierten Benutzer laufen, Admin-/Debug-Funktionen bereitstellen oder Clients aus dem Loopback-/Container-Netzwerk vertrauen.

## References

- [1] [ss(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Adressierungsarchitektur für IP-Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Umleitungen (Bash-Referenzhandbuch)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Aufruf von timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port-Scan-Techniken (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host-Erkennung (Nmap-Referenzhandbuch)](https://nmap.org/book/man-host-discovery.html)
- [10] [Portangabe und Scan-Reihenfolge (Nmap-Referenzhandbuch)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux-Handbuchseite](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD-Handbuchseite](https://man.openbsd.org/nc.1)
- [14] [Handbuch zum curl-Befehlszeilentool](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL-Dokumentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Das HTTP-Authentifizierungsschema „Basic“](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Aufruf von base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL-Dokumentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark-Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark-Benutzerhandbuch](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables-Handbuch](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Adresszuweisung für private Netzwerke (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Das OAuth-2.0-Autorisierungsframework: Verwendung von Bearer-Tokens (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Unzureichende Neutralisierung spezieller Elemente in einem Betriebssystembefehl](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Sicherheitshinweis der aiohttp-Maintainer: Traversal statischer Routen mit follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
