# Traffic-Aufzeichnung, Firewall und Egress-Triage

{{#include ../../banners/hacktricks-training.md}}

Nachdem du [lokale Listener und Unix-Sockets](local-network-and-socket-triage.md) gefunden hast, prüfe, über welche Schnittstellen deren Traffic läuft und welche Firewall- oder Proxy-Regeln die Erreichbarkeit beeinflussen. Ein ausschließlich an Loopback gebundener Dienst kann sensible HTTP-Header übertragen, selbst wenn er von keinem anderen Host aus erreichbar ist.

## Capture-Berechtigungen prüfen und eine Schnittstelle auswählen

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` kann Paketaufzeichnungsfunktionen besitzen, selbst wenn der aktuelle Benutzer keinen sudo-Zugriff hat. Prüfe die tatsächlichen Capabilities der ausführbaren Datei und die Gruppenberechtigungen. Beschränke die Aufzeichnung auf die kleinste sinnvolle Schnittstelle, Dauer und Filter; eine Aufzeichnung kann Zugangsdaten oder personenbezogene Daten enthalten.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiert Klartext-TCP-Datenströme; `tshark` kann einen Mitschnitt filtern und Felder extrahieren. Bei TLS-Datenverkehr erfordert die Entschlüsselung Endpunktschlüssel oder einen unterstützten Client, der vor dem Verbindungsaufbau für `SSLKEYLOGFILE` konfiguriert wurde. Die [Seite zur Triage lokaler Netzwerke](local-network-and-socket-triage.md#tls-key-logging) zeigt diesen Ablauf. Behandle einen verschlüsselten Mitschnitt nicht als lesbaren Klartext.

Gespeicherte Incident-Artefakte können diese Einschätzung ändern. Ein [Linux-Core-Dump ist ein Abbild des Prozessspeichers](https://man7.org/linux/man-pages/man5/core.5.html), das möglicherweise einen Sitzungsschlüssel enthält. Wenn ein lesbarer Dump und ein Paketmitschnitt vom selben Prozess und derselben Sitzung stammen, kann ein Analyst diesen Datenverkehr möglicherweise entschlüsseln. Ermittle zuerst die Artefaktpfade und Berechtigungen und überprüfe dann separat die Prozessidentität, den Zeitpunkt des Mitschnitts, das Protokoll und das Schlüssel-Format. Entschlüsselter Datenverkehr oder ein wiederhergestelltes Archiv ist ein Hinweis auf eine Offenlegung, aber kein Beweis für den Zugriff auf ein anderes Konto: Partielle SSH-Schlüsseldaten müssen zunächst rekonstruiert und dem entsprechenden öffentlichen Schlüssel zugeordnet werden; außerdem müssen sie von der SSH-Richtlinie dieses Kontos akzeptiert werden. Gib Core-Dump-Inhalte oder Paketmitschnitt-Nutzdaten nicht in allgemeinen Enumeration-Ausgaben aus.

## Firewall-Ebenen identifizieren

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` und `iptables` können über Distributions-Wrapper wie UFW oder firewalld bereitgestellt werden. Lies die aktiven Regeln und die gespeicherte Konfiguration des Wrappers aus; eine Regel, die in einer Darstellung sichtbar ist, kann von einem anderen Tool erstellt worden sein. Prüfe Schnittstelle, Richtung, Quelle, Ziel, Protokoll, Port und Verbindungsstatus, bevor du einen blockierten Dienst einer bestimmten Regel zuordnest. Ein gezieltes Beispiel findest du unter [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes).

## Teste Egress- und Proxy-Verhalten

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS-Fehler von TCP-, TLS- oder Proxy-Fehlern unterscheiden. Teste das konkrete Ziel und Protokoll, das für die Prüfung relevant ist; die Erreichbarkeit über ICMP bedeutet nicht, dass TCP oder UDP erlaubt ist. Wenn ein Proxy konfiguriert ist, vergleiche die vorgesehene Proxy-Anfrage mit derselben Anfrage an dasselbe Ziel unter den geltenden `no_proxy`-Regeln. Durch eine lokale Portweiterleitung kann ein Loopback-Dienst auch anderswo verfügbar werden. Überprüfe daher aktive Listener und SSH-Tunnel, wenn die Firewall-Sicht und die beobachtete Erreichbarkeit voneinander abweichen.
{{#include ../../banners/hacktricks-training.md}}
