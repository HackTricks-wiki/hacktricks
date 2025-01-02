# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Wie es funktioniert

**Smbexec** ist ein Tool zur Remote-Befehlsausführung auf Windows-Systemen, ähnlich wie **Psexec**, aber es vermeidet das Platzieren von schädlichen Dateien auf dem Zielsystem.

### Wichtige Punkte zu **SMBExec**

- Es funktioniert, indem es einen temporären Dienst (zum Beispiel "BTOBTO") auf der Zielmaschine erstellt, um Befehle über cmd.exe (%COMSPEC%) auszuführen, ohne Binärdateien abzulegen.
- Trotz seines stealthy Ansatzes generiert es Ereignisprotokolle für jeden ausgeführten Befehl und bietet eine Form von nicht-interaktivem "Shell".
- Der Befehl zur Verbindung mit **Smbexec** sieht folgendermaßen aus:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Ausführen von Befehlen ohne Binaries

- **Smbexec** ermöglicht die direkte Ausführung von Befehlen über Service-binPaths, wodurch die Notwendigkeit physischer Binaries auf dem Ziel entfällt.
- Diese Methode ist nützlich, um einmalige Befehle auf einem Windows-Ziel auszuführen. Zum Beispiel ermöglicht die Kombination mit Metasploit's `web_delivery`-Modul die Ausführung eines PowerShell-zielgerichteten Reverse-Meterpreter-Payloads.
- Durch das Erstellen eines Remote-Services auf dem Rechner des Angreifers mit binPath, der so eingestellt ist, dass der bereitgestellte Befehl über cmd.exe ausgeführt wird, ist es möglich, den Payload erfolgreich auszuführen, Callback und Payload-Ausführung mit dem Metasploit-Listener zu erreichen, selbst wenn Fehler bei der Service-Antwort auftreten.

### Beispielbefehle

Das Erstellen und Starten des Services kann mit den folgenden Befehlen durchgeführt werden:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Für weitere Details siehe [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referenzen

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
