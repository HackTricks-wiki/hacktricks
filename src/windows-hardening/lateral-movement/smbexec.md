# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Erhalten Sie die Perspektive eines Hackers auf Ihre Webanwendungen, Ihr Netzwerk und Ihre Cloud**

**Finden und melden Sie kritische, ausnutzbare Schwachstellen mit echtem Geschäftsauswirkungen.** Verwenden Sie unsere 20+ benutzerdefinierten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die Ihnen ermöglichen, Berechtigungen zu eskalieren, und nutzen Sie automatisierte Exploits, um wesentliche Beweise zu sammeln und Ihre harte Arbeit in überzeugende Berichte umzuwandeln.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Wie es funktioniert

**Smbexec** ist ein Tool, das für die Ausführung von Remote-Befehlen auf Windows-Systemen verwendet wird, ähnlich wie **Psexec**, aber es vermeidet es, schädliche Dateien auf dem Zielsystem abzulegen.

### Wichtige Punkte zu **SMBExec**

- Es funktioniert, indem es einen temporären Dienst (zum Beispiel "BTOBTO") auf der Zielmaschine erstellt, um Befehle über cmd.exe (%COMSPEC%) auszuführen, ohne Binärdateien abzulegen.
- Trotz seines stealthy Ansatzes generiert es Ereignisprotokolle für jeden ausgeführten Befehl und bietet eine Form von nicht-interaktivem "Shell".
- Der Befehl zur Verbindung mit **Smbexec** sieht folgendermaßen aus:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Ausführen von Befehlen ohne Binaries

- **Smbexec** ermöglicht die direkte Ausführung von Befehlen über DienstbinPaths, wodurch die Notwendigkeit physischer Binaries auf dem Ziel entfällt.
- Diese Methode ist nützlich, um einmalige Befehle auf einem Windows-Ziel auszuführen. Zum Beispiel ermöglicht die Kombination mit Metasploit's `web_delivery`-Modul die Ausführung eines PowerShell-zielgerichteten Reverse-Meterpreter-Payloads.
- Durch das Erstellen eines Remote-Dienstes auf dem Rechner des Angreifers mit binPath, der so eingestellt ist, dass der bereitgestellte Befehl über cmd.exe ausgeführt wird, ist es möglich, den Payload erfolgreich auszuführen, Callback und Payload-Ausführung mit dem Metasploit-Listener zu erreichen, selbst wenn Dienstantwortfehler auftreten.

### Beispielbefehle

Das Erstellen und Starten des Dienstes kann mit den folgenden Befehlen durchgeführt werden:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Für weitere Details siehe [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referenzen

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Erhalten Sie die Perspektive eines Hackers auf Ihre Webanwendungen, Ihr Netzwerk und Ihre Cloud**

**Finden und melden Sie kritische, ausnutzbare Schwachstellen mit echtem Geschäftsauswirkungen.** Verwenden Sie unsere 20+ benutzerdefinierten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die Ihnen ermöglichen, Berechtigungen zu eskalieren, und nutzen Sie automatisierte Exploits, um wesentliche Beweise zu sammeln, die Ihre harte Arbeit in überzeugende Berichte verwandeln.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
