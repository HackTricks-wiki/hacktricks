# Mythic

{{#include ../banners/hacktricks-training.md}}

## Šta je Mythic?

Mythic je open-source, modularni i kolaborativni command and control (C2) framework dizajniran za red teaming. Omogućava operatorima da upravljaju i deploy-uju agente (payloads) na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža browser UI za tasking više operatora, rukovanje fajlovima, upravljanje SOCKS/rpfwd funkcijama i generisanje payloads.

Za razliku od monolitnih framework-a, sam Mythic repository ne sadrži payload types niti C2 profiles. Agenti, wrappers i C2 profiles se obično instaliraju kao spoljne komponente i mogu se ažurirati nezavisno od Mythic core-a.

### Instalacija

Da biste instalirali Mythic, pratite uputstva u zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Uobičajeni bootstrap iz Mythic direktorijuma je:
```bash
sudo make
sudo ./mythic-cli start
```
Ako je Mythic već pokrenut, obično možete dodati novi agent ili profile pomoću `./mythic-cli install github ...`, a zatim ponovo pokrenuti Mythic ili samo direktno pokrenuti novu komponentu.

### Agenti

Mythic podržava više agenata, odnosno **payload-ove koji izvršavaju zadatke na kompromitovanim sistemima**. Svaki agent može biti prilagođen specifičnim potrebama i može raditi na različitim operativnim sistemima.

Mythic podrazumevano nema instalirane agente. Agenti open-source zajednice nalaze se na [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**matrica funkcionalnosti zajednice**](https://mythicmeta.github.io/overview/agent_matrix.html) korisna je za brzu proveru podržanih operativnih sistema, formata payload-ova, wrapper-a i C2 profila.<sup>[[1]](#references)</sup>

Da biste instalirali agenta iz te organizacije, možete pokrenuti:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` je korisna kada instalirate iz okruženja koje nije root. Možete dodati nove agente prethodnom komandom čak i ako je Mythic već pokrenut.

### C2 Profiles

C2 profiles u Mythic-u definišu **kako agenti komuniciraju sa Mythic serverom**. Oni određuju komunikacioni protokol, metode šifrovanja i druga podešavanja. C2 profiles možete kreirati i upravljati njima kroz Mythic web interfejs.

Mythic se podrazumevano instalira bez profila, ali je moguće preuzeti neke profile iz repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) pokretanjem:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Trenutni profili relevantni za operatore koje treba imati na umu:

- [`http`](https://github.com/MythicC2Profiles/http): osnovni asinhroni GET/POST saobraćaj.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): fleksibilniji HTTP saobraćaj sa više callback domena, fail-over/round-robin rotacijom, prilagođenim headerima/query parametrima i transformacijama poruka (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) smeštenim u cookies, headere, query parametre ili body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): oblikovanje HTTP poruka zasnovano na JSON/TOML-u kada je statički `http` profil previše prepoznatljiv.

### Trenutne napomene o platformi

- Mnogi javno dostupni agenti i profili sada se instaliraju pomoću unapred izgrađenih remote container image-a.
Ako fork-ujete komponentu ili je lokalno izmenite, a Mythic i dalje koristi staro
ponašanje, proverite generisane `.env` unose za `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; omogućavanje
`*_USE_BUILD_CONTEXT="true"` obično navodi Mythic da ponovo izgradi komponentu iz vašeg
lokalnog Docker context-a, umesto da neprimetno ponovo koristi remote image.
- Browser scripts su jedna od najvrednijih funkcija za poboljšanje rada operatora u Mythic-u:
mogu pretvoriti sirov izlaz komandi u tabele, preglednike snimaka ekrana, linkove za preuzimanje, linkove za pretragu i dugmad koja direktno iz UI-ja izdaju naknadno tasking. Trenutne Mythic verzije omogućavaju svakom operatoru da koristi sopstvene skripte, da ih globalno ili po task-u uključuje i isključuje, a najbolji rezultati se dobijaju kada agenti vraćaju strukturirani JSON umesto plaintext-a. Ovo je naročito korisno za repetitivne `ls`, `ps`, triage i file-browser workflow-e.<sup>[[4]](#references)[[6]](#references)</sup>
- Novije Mythic verzije takođe podržavaju interactive tasking i Push C2 obrasce,
koji smanjuju potrebu za polling-om pomoću `sleep 0` tokom operacija sa mnogo PTY/SOCKS/rpfwd aktivnosti. Kada ih agent/profil podržava, ovo obično stvara manje opterećenje nego neprekidno slanje zahteva serveru samo da bi interaktivni kanal ostao upotrebljiv.<sup>[[3]](#references)</sup>
- Aktuelni Mythic builder-i iz 3.4 ere svesniji su konteksta nego što stariji tekstovi sugerišu:
build parametri se sada mogu grupisati ili sakriti na osnovu izabranog OS-a
ili drugih build opcija, payload tipovi mogu deklarisati da li podržavaju
više C2 profila ili više instanci istog C2 u jednom build-u, a
C2 parameter deviations omogućavaju agentu da sakrije polja koja zapravo
ne implementira. Ovo je važno kada prelazite između `http`, `httpx`, `smb`,
`tcp` i `websocket`, jer bezbedan/ispravan build surface više nije
ravna statička forma.<sup>[[5]](#references)</sup>
- Ako pravite prilagođeni par agent/profil i ne želite Mythic-ov JSON format poruka ili podrazumevanu kriptografiju na wire-u, koristite
`translation_container`: Mythic uklanja UUID, prosleđuje enkriptovani blob i materijal ključa translator-u putem gRPC-a i očekuje agent-native bajtove nazad. Ovo je čist način za podršku binarnim protokolima, prilagođenom framing-u ili enkripciji na strani agenta bez prepisivanja celog servera.
- Imajte na umu da linked/P2P callback-ovi ne prosleđuju samo tasking. Mythic-ov
`get_tasking` flow može takođe prenositi response-e, kao i `delegates`,
`socks`, `rpfwd` i `interactive` podatke. U praksi, jedan egress callback može
opsluživati inner callback-ove i pivot kanale u istoj polling petlji; ako child agenti
sami obavljaju periodične check-in aktivnosti, `get_delegate_tasks=false` sprečava
parent da slučajno preuzme queued jobs unutrašnjeg callback-a.

### Wrapper payloads

Wrapper payloads omogućavaju da zadržite istu logiku agenta, a da promenite reprezentaciju na disku koja se isporučuje ili čuva.

- `service_wrapper`: pretvara drugi payload u Windows service executable, što je korisno kada putanja izvršavanja zahteva ispravan service binary.
- `scarecrow_wrapper`: obmotava kompatibilni shellcode ScareCrow loader-om kako bi generisao loader-backed output-e kao što su EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C#-u, koji koristi 4.0 .NET Framework i namenjen je korišćenju u SpecterOps training ponudama.<sup>[[2]](#references)</sup>

Instalirajte ga pomoću:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Beleške o trenutnoj izgradnji/profilu

- Apollo trenutno može da generiše `WinExe`, `Shellcode`, `Service` i `Source` payloads.
- Često korišćeni Apollo profili su `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` je obično fleksibilnija opcija kada su vam potrebni rotacija domena, podrška za proxy, prilagođeno smeštanje poruka i transformacije poruka, umesto starijeg statičkog `http` profila.
- Apollo je jedan od funkcionalno najpotpunijih community agenata i trenutno omogućava Mythic-side integracije kao što su browser scripts, prikazi file/process browsera, screenshots, keylogging, SOCKS, rpfwd, Push C2 i P2P routing.
- Apollo podržava wrapper payloads kao što su `service_wrapper` i `scarecrow_wrapper`.
- Apollo podržava dinamičko učitavanje komandi, tako da početni payload možete zadržati malim i kasnije učitati dodatne komande ili Forge module, umesto da svaku post-exploitation mogućnost kompajlirate u prvu izgradnju.
- Prilikom generisanja shellcode izlaza, trenutni Apollo builder takođe omogućava izbor Donut formata (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) i Donut bypass ponašanja (`None`, `Abort on fail`, `Continue on fail`). Ovo je korisno ako je krajnji cilj ponovno pakovanje shellcode-a pomoću `service_wrapper`, `scarecrow_wrapper` ili prilagođenog loadera.
- `register_file` i `register_assembly` predstavljaju staging primitive za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. U trenutnim Apollo builds, ti staged artifacts se keširaju na strani klijenta kao DPAPI-zaštićeni AES256 blobovi.
- Rezultati komandi `ls` i `ps` posebno dobro se integrišu sa Mythic browser scripts i file/process browserom, što primetno ubrzava operator triage u kolaborativnim operacijama.
- Apollo fork-and-run jobs nasleđuju podešavanja sacrificial procesa iz
`spawnto_x86` / `spawnto_x64`, izbor parent procesa nasleđuju iz
`ppid`, a zatim koriste trenutno izabrani injection primitive. U praksi, to znači da
vaše OPSEC podešavanje za jednu komandu često utiče na `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i `spawn` istovremeno.
- Trenutno dokumentovani Apollo injection backends obuhvataju `CreateRemoteThread`,
`QueueUserAPC` (early-bird stil) i `NtCreateThreadEx` preko syscalls. Koristite
`get_injection_techniques` pre noisy post-exploitation aktivnosti i
`set_injection_technique` ako je potrebno da zamenite primitive koji nije
kompatibilan sa targetom ili komandom koju želite da pokrenete.
- `blockdlls` utiče samo na sacrificial procese kreirane za post-exploitation
jobs. U kombinaciji sa manje sumnjivim `spawnto_x64` targetom u odnosu na podrazumevani
goli `rundll32.exe`, ovo je jedna od najlakših Apollo-side izmena koju možete napraviti
pre pokretanja assembly/PowerShell-heavy taskinga.

Ovaj agent ima veliki broj komandi zbog kojih je veoma sličan Cobalt Strike Beacon-u, uz nekoliko dodataka. Između ostalog, podržava:

### Uobičajene radnje

- `cat`: Ispisuje sadržaj fajla
- `cd`: Menja trenutni working directory
- `cp`: Kopira fajl sa jedne lokacije na drugu
- `ls`: Prikazuje fajlove i direktorijume u trenutnom direktorijumu ili na navedenoj putanji
- `ifconfig`: Pribavlja informacije o network adapterima i interfejsima
- `netstat`: Pribavlja informacije o TCP i UDP konekcijama
- `pwd`: Ispisuje trenutni working directory
- `ps`: Prikazuje running procese na target sistemu (uz dodatne informacije)
- `jobs`: Prikazuje sve running jobs povezane sa dugotrajnim taskingom
- `download`: Preuzima fajl sa target sistema na lokalnu mašinu
- `upload`: Otpremanje fajla sa lokalne mašine na target sistem
- `reg_query`: Ispituje registry ključeve i vrednosti na target sistemu
- `reg_write_value`: Upisuje novu vrednost u navedeni registry ključ
- `sleep`: Menja sleep interval agenta, koji određuje koliko često agent proverava Mythic server
- I mnoge druge; koristite `help` da biste videli kompletnu listu dostupnih komandi.

### Eskalacija privilegija

- `getprivs`: Omogućava što veći broj privilegija na tokenu trenutne niti
- `getsystem`: Otvara handle ka winlogon procesu i duplira token, čime efektivno eskalira privilegije na SYSTEM nivo
- `make_token`: Kreira novu logon sesiju i primenjuje je na agenta, omogućavajući impersonation drugog korisnika
- `steal_token`: Krade primary token iz drugog procesa, omogućavajući agentu da impersonate korisnika tog procesa
- `pth`: Pass-the-Hash napad, koji agentu omogućava autentifikaciju kao korisnik pomoću njegovog NTLM hash-a, bez potrebe za plaintext lozinkom
- `mimikatz`: Pokreće Mimikatz komande za izvlačenje credentiala, hash-ova i drugih osetljivih informacija iz memorije ili SAM baze podataka
- `rev2self`: Vraća token agenta na njegov primary token, čime efektivno uklanja privilegije i vraća ih na prvobitni nivo
- `ppid`: Menja parent proces za post-exploitation jobs navođenjem novog parent process ID-ja, što omogućava bolju kontrolu nad execution contextom job-a
- `printspoofer`: Izvršava PrintSpoofer komande za zaobilaženje security mera print spoolera, omogućavajući eskalaciju privilegija ili code execution
- `dcsync`: Sinhronizuje Kerberos ključeve korisnika na lokalnu mašinu, omogućavajući offline password cracking ili dalje napade
- `ticket_cache_add`: Dodaje Kerberos ticket u trenutnu logon sesiju ili u navedenu sesiju, omogućavajući ponovnu upotrebu ticketa ili impersonation

### Izvršavanje procesa

- `assembly_inject`: Omogućava injection .NET assembly loadera u udaljeni proces
- `blockdlls`: Blokira učitavanje DLL-ova koje nije potpisao Microsoft u post-exploitation jobs
- `execute_assembly`: Izvršava .NET assembly u kontekstu agenta
- `execute_coff`: Izvršava COFF fajl u memoriji, omogućavajući in-memory execution kompajliranog koda
- `execute_pe`: Izvršava unmanaged executable (PE)
- `keylog_inject`: Injectuje keylogger u drugi proces i prosleđuje pritisnute tastere u Mythic keylog view
- `screenshot` / `screenshot_inject`: Snima trenutnu radnu površinu direktno ili
injectovanjem screenshot assembly-ja u target proces/sesiju
- `get_injection_techniques`: Prikazuje dostupne injection techniques i trenutno izabranu tehniku
- `inline_assembly`: Izvršava .NET assembly u disposable AppDomain-u, omogućavajući privremeno izvršavanje koda bez uticaja na glavni proces agenta
- `register_assembly`: Registruje .NET assembly za kasnije izvršavanje
- `register_file`: Registruje fajl u agent cache za kasniji `execute_*` ili PowerShell tasking
- `run`: Izvršava binary na target sistemu, koristeći system PATH za pronalaženje executable-a
- `set_injection_technique`: Menja injection primitive koji koriste post-exploitation jobs
- `shinject`: Injectuje shellcode u udaljeni proces, omogućavajući in-memory execution proizvoljnog koda
- `inject`: Injectuje agent shellcode u udaljeni proces, omogućavajući in-memory execution koda agenta
- `spawn`: Pokreće novu agent sesiju u navedenom executable-u, omogućavajući izvršavanje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Menjaju podrazumevani binary koji se koristi u post-exploitation jobs na navedenu putanju, umesto korišćenja `rundll32.exe` bez parametara, što je veoma noisy.

### Mythic Forge

Ovo omogućava **učitavanje COFF/BOF** fajlova iz Mythic Forge-a, koji predstavlja repozitorijum pre-compiled payloads i tools koji se mogu izvršavati na target sistemu. Sa svim komandama koje mogu da se učitaju, biće moguće obavljati uobičajene radnje njihovim izvršavanjem u trenutnom procesu agenta kao BOF-ova (obično uz bolji OPSEC nego pri pokretanju zasebnog procesa).

Počnite njihovu instalaciju pomoću:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Zatim upotrebite `forge_collections` da prikažete COFF/BOF modules iz Mythic Forge-a, kako biste mogli da ih izaberete i učitate u memoriju agenta radi izvršavanja. Podrazumevano su u Apollo dodate sledeće 2 kolekcije:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nakon učitavanja jednog module-a, on će se pojaviti na listi kao druga komanda, na primer `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

Za BOF-ove imajte na umu da Forge **ne prosleđuje** Apollo-u samo jedan neformatirani string argumenata. On mapira BOF parametre u Mythic-ov typed-array format, a zatim ih prosleđuje u Apollo-ov `execute_coff` flow. Ako se BOF učitan preko Forge-a ponaša neobično, proverite očekivane tipove BOF argumenata / entrypoint, a ne samo command line koji ste uneli. Takođe imajte na umu da je noviji Apollo BOF loader promenio način obrade argumenata u odnosu na mnogo starije build-ove iz ere 2.3.1, pa stale BOF-ovi ili stare kolekcije mogu da zakažu isključivo zato što su se očekivanja za marshaling promenila.

### PowerShell & izvršavanje skripti

- `powershell_import`: Uvozi novu PowerShell skriptu (.ps1) u cache agenta radi kasnijeg izvršavanja
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, omogućavajući napredno scripting i automation
- `powerpick`: Ubrizgava PowerShell loader assembly u žrtveni proces i izvršava PowerShell komandu (bez PowerShell logging-a).
- `psinject`: Izvršava PowerShell u navedenom procesu, omogućavajući ciljano izvršavanje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično pokretanju komande u cmd.exe

### Lateral Movement

- `jump_psexec`: Koristi PsExec tehniku za lateralno kretanje na novi host tako što najpre kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `jump_wmi`: Koristi WMI tehniku za lateralno kretanje na novi host tako što najpre kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `link` i `unlink`: Kreiraju i prekidaju P2P links (na primer preko SMB/TCP) između callback-ova.
- `wmiexecute`: Izvršava komandu na lokalnom ili navedenom remote sistemu koristeći WMI, uz opcione credentials za impersonation.
- `net_dclist`: Preuzima listu domain controller-a za navedeni domain, što je korisno za identifikovanje potencijalnih target-a za lateralno kretanje.
- `net_localgroup`: Izlistava local groups na navedenom računaru, podrazumevano na localhost ako računar nije naveden.
- `net_localgroup_member`: Preuzima članstvo u local group za navedenu grupu na lokalnom ili remote računaru, omogućavajući enumeraciju korisnika u određenim grupama.
- `net_shares`: Izlistava remote shares i njihovu dostupnost na navedenom računaru, što je korisno za identifikovanje potencijalnih target-a za lateralno kretanje.
- `socks`: Omogućava SOCKS 5 compliant proxy na target network-u, dopuštajući tunneling saobraćaja kroz kompromitovani host. Kompatibilno je sa alatima kao što je proxychains.
- `rpfwd`: Počinje da osluškuje navedeni port na target host-u i prosleđuje saobraćaj kroz Mythic ka remote IP adresi i portu, omogućavajući remote access servisima na target network-u.
- `listpipes`: Izlistava sve named pipes na lokalnom sistemu, što može biti korisno za lateralno kretanje ili privilege escalation interakcijom sa IPC mehanizmima.

Za WMI execution primitive nižeg nivoa koje se koriste unutar `jump_wmi` ili `wmiexecute`, pogledajte [WmiExec](lateral-movement/wmiexec.md). Za šire pivoting obrasce pogledajte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Prikazuje detaljne informacije o određenim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Obeležava task-ove kao 'cleared', tako da ih agenti ne mogu preuzeti. Možete navesti `all` za brisanje svih task-ova ili `task Num` za brisanje određenog task-a.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon je Golang agent koji se kompajlira u izvršne datoteke za **Linux i macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Beleške o trenutnom build/profile stanju

- Trenutni Poseidon buildovi ciljaju Linux i macOS na platformama `x86_64` i `arm64`.
- Podržani izlazni formati uključuju native izvršne fajlove, kao i izlaze u stilu shared library-ja, poput `dylib` i `so`.
- Poseidon podržava `http`, `websocket`, `tcp` i `dynamichttp`, a trenutni builderi nude multi-egress podešavanja kao što su `egress_order` i pragovi za failover.
- Trenutni capability metadata za Poseidon takođe oglašava browser scripts, integraciju file/process browser-a, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd i P2P, tako da može da funkcioniše kao pravi Linux/macOS pivot node, a ne samo kao jednostavan remote shell.
- Build-time opcije poput `proxy_bypass` i `garble` vredi proveriti kada su vam potrebni čistije mrežno ponašanje ili dodatna Go binary obfuskacija.
- `pty` je jedna od najkorisnijih novijih QoL komandi za Linux/macOS
operacije, jer otvara interaktivni PTY i može da izloži Mythic-side
port za potpuniju terminal interakciju bez pribegavanja starijem `sleep 0`
+ SOCKS workaround-u.
- Trenutna Poseidon dokumentacija je naročito zanimljiva za macOS-heavy
tradecraft: `jxa` izvršava JavaScript for Automation u memoriji,
`screencapture` snima desktop prijavljenog korisnika, `clipboard_monitor`
prosleđuje promene pasteboard-a, `execute_library` učitava lokalni dylib i poziva
funkciju iz njega, a `libinject` primorava udaljeni proces da učita dylib
sa diska.
- Za dugotrajne poslove imajte na umu da Poseidon izvršava post-exploitation rad
u gorutinama/thread-ovima koji su kooperativni, a ne mogu se nasilno prekinuti. Dokumentacija
takođe izričito navodi da trenutno ne postoji ugrađena agent
obfuskacija, pa su build/profile-level tradecraft tehnike važnije nego kod
komercijalnih implantata sa intenzivnom obfuskacijom.

Za macOS-specifični tradecraft u vezi sa Mythic-backed operacijama, JAMF abuse-om ili MDM-as-C2 idejama, pogledajte [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Kada se koristi na Linuxu ili macOS-u, ima neke zanimljive komande:

### Uobičajene radnje

- `cat`: Ispisuje sadržaj fajla
- `cd`: Menja trenutni working directory
- `chmod`: Menja dozvole fajla
- `config`: Prikazuje trenutnu konfiguraciju i informacije o hostu
- `cp`: Kopira fajl sa jedne lokacije na drugu
- `curl`: Izvršava jedan web request sa opcionim headerima i metodom
- `upload`: Otpremanje fajla na cilj
- `download`: Preuzima fajl sa ciljnog sistema na lokalnu mašinu
- I još mnogo toga

### Pretraga osetljivih informacija

- `triagedirectory`: Pronalaženje zanimljivih fajlova unutar direktorijuma na hostu, kao što su osetljivi fajlovi ili credentiali.
- `getenv`: Dobavljanje svih trenutnih environment varijabli.

### macOS-specifični tradecraft

- `jxa`: Izvršava JavaScript for Automation u memoriji preko `OSAScript`, što je
korisno za native macOS post-exploitation bez ostavljanja zasebnih script
fajlova.
- `clipboard_monitor`: Proverava pasteboard i prijavljuje promene nazad Mythic-u,
što je korisno za workflow-e krađe credentiala/tokena koji se oslanjaju na copy/paste.
- `screencapture`: Snima desktop korisnika na macOS-u.
- `execute_library`: Učitava dylib sa diska i poziva određenu eksportovanu funkciju.
- `libinject`: Injektuje shellcode stub koji primorava drugi macOS proces da učita dylib sa diska.
- `persist_launchd`: Direktno iz agenta kreira LaunchAgent / LaunchDaemon persistence.

### Lateralno kretanje

- `ssh`: Povezuje se na host preko SSH-a koristeći određene credentiale i otvara PTY bez pokretanja ssh-a.
- `sshauth`: Povezuje se na navedene hostove koristeći određene credentiale. Ovo se može koristiti i za izvršavanje određene komande na udaljenim hostovima preko SSH-a ili za SCP fajlova.
- `link_tcp`: Povezuje se sa drugim agentom preko TCP-a, omogućavajući direktnu komunikaciju između agenata.
- `link_webshell`: Povezuje se sa agentom koristeći webshell P2P profil, omogućavajući remote access web interfejsu agenta.
- `rpfwd`: Pokreće ili zaustavlja Reverse Port Forward, omogućavajući remote access servisima na ciljnoj mreži.
- `socks`: Pokreće ili zaustavlja SOCKS5 proxy na ciljnoj mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno je sa alatima poput proxychains.
- `portscan`: Skenira hostove radi pronalaženja otvorenih portova, što je korisno za identifikovanje potencijalnih ciljeva za lateralno kretanje ili dalje napade.

### Izvršavanje procesa

- `shell`: Izvršava jednu shell komandu preko /bin/sh, omogućavajući direktno izvršavanje komandi na ciljnom sistemu.
- `run`: Izvršava komandu sa diska sa argumentima, omogućavajući izvršavanje binarnih fajlova ili scriptova na ciljnom sistemu.
- `pty`: Otvara interaktivni PTY, omogućavajući direktnu interakciju sa shell-om na ciljnom sistemu.

## Reference

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
