# Traffic Capture, Firewall- und Egress-Triage

{{#include ../../banners/hacktricks-training.md}}

Nachdem du [lokale Listener und Unix-Sockets](local-network-and-socket-triage.md) gefunden hast, prüfe, welche Schnittstellen ihren Traffic übertragen und welche Firewall- oder Proxy-Regeln die Erreichbarkeit beeinflussen. Ein Dienst, der nur an Loopback gebunden ist, kann sensible HTTP-Header übertragen, auch wenn er von keinem anderen Host aus erreichbar ist.

## Capture-Berechtigungen prüfen und eine Schnittstelle auswählen

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` kann über Paketaufzeichnungsfunktionen verfügen, auch wenn der aktuelle Benutzer keinen sudo-Zugriff hat. Prüfen Sie die tatsächlichen Capabilities der ausführbaren Datei und die Gruppenberechtigungen. Verwenden Sie die kleinstmögliche sinnvolle Schnittstelle, Dauer und Filter für die Aufzeichnung; sie kann Zugangsdaten oder personenbezogene Daten enthalten.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiert Klartext-TCP-Streams; `tshark` kann einen Mitschnitt filtern und Felder daraus extrahieren. Für TLS-Traffic sind zur Entschlüsselung Endpunkt-Schlüssel oder ein unterstützter Client erforderlich, der vor dem Verbindungsaufbau für `SSLKEYLOGFILE` konfiguriert wurde. Die [Seite zur lokalen Netzwerk-Triage](local-network-and-socket-triage.md#tls-key-logging) zeigt diesen Ablauf. Behandle einen verschlüsselten Mitschnitt nicht als lesbaren Klartext.

Gespeicherte Incident-Artefakte können diese Einschätzung ändern. Ein [Linux-Core-Dump ist ein Abbild des Prozessspeichers](https://man7.org/linux/man-pages/man5/core.5.html), das möglicherweise einen Sitzungsschlüssel enthält. Wenn ein lesbarer Dump und ein Paketmitschnitt vom selben Prozess und derselben Sitzung stammen, kann ein Analyst diesen Traffic möglicherweise entschlüsseln. Ermittle zuerst die Artefaktpfade und Berechtigungen, und überprüfe anschließend Prozessidentität, Mitschnittzeitpunkt, Protokoll und Schlüsselformat separat. Entschlüsselter Traffic oder ein wiederhergestelltes Archiv ist ein Hinweis auf eine mögliche Offenlegung, aber kein Beweis für den Zugriff auf das Konto einer anderen Person: Teilweise vorhandenes SSH-Schlüsselmaterial muss weiterhin rekonstruiert, dem entsprechenden öffentlichen Schlüssel zugeordnet und von der SSH-Richtlinie des Kontos akzeptiert werden. Gib Core-Dump-Inhalte oder Mitschnitt-Payloads nicht in einer breit angelegten Enumeration aus.

## Firewall-Ebenen identifizieren

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` und `iptables` können über Distributions-Wrapper wie UFW oder firewalld bereitgestellt werden. Lies die aktiven Regeln und die gespeicherte Konfiguration des Wrappers aus; eine in einer Darstellung sichtbare Regel kann von einem anderen Tool erzeugt worden sein. Prüfe Schnittstelle, Richtung, Quelle, Ziel, Protokoll, Port und Verbindungsstatus, bevor du einen blockierten Dienst einer bestimmten Regel zuordnest. Ein gezieltes Beispiel findest du unter [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes).

## Egress- und Proxy-Verhalten testen

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Unterscheide DNS-Fehler von TCP-, TLS- oder Proxy-Fehlern. Teste das für die Prüfung relevante Ziel und Protokoll. Die Erreichbarkeit per ICMP bedeutet nicht, dass TCP oder UDP erlaubt ist. Wenn ein Proxy konfiguriert ist, vergleiche die vorgesehene Proxy-Anfrage mit derselben Anfrage an dasselbe Ziel unter den geltenden `no_proxy`-Regeln. Eine lokale Portweiterleitung kann einen Loopback-Dienst auch an anderer Stelle verfügbar machen. Prüfe daher aktive Listener und SSH-Tunnel, wenn die Firewall-Ansicht und die beobachtete Offenlegung voneinander abweichen.
{{#include ../../banners/hacktricks-training.md}}
