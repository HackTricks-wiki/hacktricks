# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Wie funktionieren sie

Der Prozess ist in den folgenden Schritten skizziert, die veranschaulichen, wie Dienst-Binärdateien manipuliert werden, um eine Remote-Ausführung auf einem Zielrechner über SMB zu erreichen:

1. **Kopieren einer Dienst-Binärdatei in den ADMIN$-Freigabe über SMB** wird durchgeführt.
2. **Erstellung eines Dienstes auf dem Remote-Rechner** erfolgt durch Verweisen auf die Binärdatei.
3. Der Dienst wird **remote gestartet**.
4. Nach dem Beenden wird der Dienst **gestoppt und die Binärdatei gelöscht**.

### **Prozess der manuellen Ausführung von PsExec**

Angenommen, es gibt eine ausführbare Payload (erstellt mit msfvenom und obfuskiert mit Veil, um die Erkennung durch Antivirenprogramme zu umgehen), benannt 'met8888.exe', die eine meterpreter reverse_http Payload darstellt, werden die folgenden Schritte unternommen:

- **Kopieren der Binärdatei**: Die ausführbare Datei wird von einer Eingabeaufforderung in die ADMIN$-Freigabe kopiert, obwohl sie überall im Dateisystem platziert werden kann, um verborgen zu bleiben.
- Anstelle des Kopierens der Binärdatei ist es auch möglich, eine LOLBAS-Binärdatei wie `powershell.exe` oder `cmd.exe` zu verwenden, um Befehle direkt aus den Argumenten auszuführen. Z.B. `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Erstellen eines Dienstes**: Mit dem Windows-Befehl `sc`, der das Abfragen, Erstellen und Löschen von Windows-Diensten aus der Ferne ermöglicht, wird ein Dienst namens "meterpreter" erstellt, der auf die hochgeladene Binärdatei verweist.
- **Starten des Dienstes**: Der letzte Schritt besteht darin, den Dienst zu starten, was wahrscheinlich zu einem "Zeitüberschreitung"-Fehler führen wird, da die Binärdatei keine echte Dienst-Binärdatei ist und nicht den erwarteten Antwortcode zurückgibt. Dieser Fehler ist unerheblich, da das Hauptziel die Ausführung der Binärdatei ist.

Die Beobachtung des Metasploit-Listeners wird zeigen, dass die Sitzung erfolgreich initiiert wurde.

[Erfahren Sie mehr über den `sc`-Befehl](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Finden Sie detailliertere Schritte in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Sie könnten auch die **Windows Sysinternals-Binärdatei PsExec.exe** verwenden:

![](<../../images/image (928).png>)

Oder über webddav darauf zugreifen:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Sie könnten auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Sie könnten auch [**SharpMove**](https://github.com/0xthirteen/SharpMove) verwenden:
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- Sie könnten auch **Impacket's `psexec` und `smbexec.py`** verwenden.


{{#include ../../banners/hacktricks-training.md}}
