# Mythic

{{#include ../banners/hacktricks-training.md}}

## Šta je Mythic?

Mythic je open-source, modularni, kolaborativni command and control (C2) framework dizajniran za red teaming. Omogućava operatorima da upravljaju agentima (payloads) i da ih deployuju na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža browser UI za tasking više operatora, rukovanje fajlovima, upravljanje SOCKS/rpfwd i generisanje payloads.

Za razliku od monolitnih frameworka, sam Mythic repository **ne isporučuje tipove payloads niti C2 profile**. Agenti, wrappers i C2 profili se obično instaliraju kao spoljne komponente i mogu se nezavisno ažurirati od Mythic core-a.

### Instalacija

Da biste instalirali Mythic, pratite uputstva u zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Uobičajeni bootstrap iz Mythic direktorijuma je:
```bash
sudo make
sudo ./mythic-cli start
```
Ako Mythic već radi, obično možete dodati novi agent ili profile pomoću `./mythic-cli install github ...`, a zatim ponovo pokrenuti Mythic ili samo direktno pokrenuti novu komponentu.

### Agenti

Mythic podržava više agenata, odnosno **payloads koji izvršavaju zadatke na kompromitovanim sistemima**. Svaki agent može biti prilagođen specifičnim potrebama i može raditi na različitim operativnim sistemima.

Mythic podrazumevano nema instalirane agente. Agenti open-source zajednice nalaze se na adresi [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**matrica funkcija zajednice**](https://mythicmeta.github.io/overview/agent_matrix.html) korisna je za brzu proveru podržanih operativnih sistema, formata payloads, wrappera i C2 profila.

Da biste instalirali agenta iz te organizacije, možete pokrenuti:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` je korisna kada instalirate iz okruženja koje nije root. Možete dodati nove agente prethodnom komandom čak i ako je Mythic već pokrenut.

### C2 Profiles

C2 profiles u Mythic-u definišu **kako agenti komuniciraju sa Mythic serverom**. Oni određuju komunikacioni protokol, metode enkripcije i druga podešavanja. C2 profiles možete kreirati i njima upravljati putem Mythic web interfejsa.

Mythic se podrazumevano instalira bez profila, ali je moguće preuzeti neke profile iz repo-a [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) pokretanjem:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Trenutni profili relevantni za operatore koje treba imati na umu:

- [`http`](https://github.com/MythicC2Profiles/http): osnovni asinhroni GET/POST saobraćaj.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): fleksibilniji HTTP saobraćaj sa više callback domena, fail-over/round-robin rotacijom, prilagođenim headerima/query parametrima i transformacijama poruka (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) smeštenim u cookies, headere, query parametre ili telo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): oblikovanje HTTP poruka zasnovano na JSON/TOML-u kada je statički `http` profile prepoznatljiv.

### Napomene o trenutnoj platformi

- Mnogi javno dostupni agenti i profili sada se instaliraju pomoću unapred izgrađenih remote container image-a.
Ako fork-ujete komponentu ili je lokalno izmenite, a Mythic i dalje koristi staro
ponašanje, proverite generisane `.env` unose za `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; uključivanje
`*_USE_BUILD_CONTEXT="true"` obično omogućava Mythic-u da ponovo izgradi komponentu iz vašeg
lokalnog Docker context-a umesto da neprimetno ponovo koristi remote image.
- Browser scripts su jedne od najkorisnijih Mythic funkcija za operatore:
mogu pretvoriti sirov izlaz komandi u tabele, prikazivače screenshot-a, linkove za preuzimanje, linkove za pretragu i dugmad koja direktno iz UI-ja
pokreću naredno tasking. Trenutne Mythic verzije omogućavaju svakom operatoru da zadrži
sopstvene scripts, uključi ih globalno ili po task-u, a najbolji rezultati se dobijaju
kada agenti vraćaju strukturirani JSON umesto plaintext-a. Ovo je naročito korisno za ponavljajuće `ls`, `ps`, triage i file-browser workflow-e.
- Novije Mythic verzije takođe podržavaju interactive tasking i Push C2 obrasce,
koji smanjuju potrebu za polling-om pomoću `sleep 0` tokom operacija intenzivnih u PTY/SOCKS/rpfwd
kontekstima. Kada ih agent/profile podržava, ovo obično zahteva manje resursa
nego neprekidno zatrpavanje servera check-in zahtevima samo da bi interaktivni
kanal ostao upotrebljiv.
- Aktuelni Mythic builder-i iz 3.4 ere svesniji su konteksta nego što stariji tekstovi
navode: build parametri se sada mogu grupisati ili sakriti na osnovu izabranog OS-a
ili drugih build opcija, payload types mogu deklarisati da li podržavaju
više C2 profila ili više instanci istog C2 u jednom build-u, a
C2 parameter deviations omogućavaju agentu da sakrije polja koja zapravo
ne implementira. Ovo je važno kada prelazite između `http`, `httpx`, `smb`,
`tcp` i `websocket`, jer bezbedna/validna površina za build više nije ravna
statička forma.
- Ako pravite prilagođeni agent/profile par i ne želite Mythic-ov JSON format poruka
ili podrazumevanu kriptografiju preko wire-a, koristite
`translation_container`: Mythic uklanja UUID, prosleđuje enkriptovani blob i materijal ključa
translator-u preko gRPC-a i očekuje bytes u izvornom formatu agenta.
Ovo je pravi način za podršku binarnim protokolima, prilagođenom framing-u
ili enkripciji na strani agenta bez ponovnog pisanja celog servera.
- Imajte na umu da linked/P2P callback-ovi ne prosleđuju samo tasking. Mythic-ov
`get_tasking` flow može takođe prenositi responses, kao i `delegates`,
`socks`, `rpfwd` i `interactive` podatke. U praksi, jedan egress callback može opsluživati
unutrašnje callback-ove i pivot kanale u istom polling loop-u; ako child
agenti obavljaju sopstvene periodične check-in-e, `get_delegate_tasks=false` sprečava
parent da slučajno preuzme queued jobs unutrašnjeg callback-a.

### Wrapper payloads

Wrapper payloads omogućavaju da zadržite istu logiku agenta, a da promenite reprezentaciju na disku koja se isporučuje ili čuva.

- `service_wrapper`: pretvara drugi payload u Windows service executable, što je korisno kada execution path zahteva validan service binary.
- `scarecrow_wrapper`: obmotava kompatibilni shellcode ScareCrow loader-om radi generisanja loader-backed izlaza kao što su EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C#-u pomoću 4.0 .NET Framework-a, namenjen za korišćenje u SpecterOps training ponudama.

Instalirajte ga pomoću:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Beleške o trenutnoj build/profil konfiguraciji

- Apollo trenutno može da emituje `WinExe`, `Shellcode`, `Service` i `Source` payloads.
- Najčešće korišćeni Apollo profili su `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` je obično fleksibilnija opcija kada su potrebni rotacija domena, proxy podrška, prilagođeno smeštanje poruka i transformacije poruka, umesto starijeg statičkog `http` profila.
- Apollo je jedan od funkcionalno potpunijih community agenata i trenutno izlaže Mythic-side integracije kao što su browser scripts, prikazi file/process browsera, screenshots, keylogging, SOCKS, rpfwd, Push C2 i P2P routing.
- Apollo podržava wrapper payloads kao što su `service_wrapper` i `scarecrow_wrapper`.
- Apollo podržava dynamic command loading, tako da početni payload može ostati mali, a dodatne komande ili Forge module možete učitati kasnije, umesto da svaku post-exploitation mogućnost kompajlirate u prvom buildu.
- Prilikom generisanja shellcode izlaza, Apollo-ov trenutni builder takođe izlaže izbore Donut formata (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) i Donut bypass ponašanje (`None`, `Abort on fail`, `Continue on fail`). Ovo je korisno ako je krajnji cilj ponovno pakovanje shellcode-a pomoću `service_wrapper`, `scarecrow_wrapper` ili custom loader-a.
- `register_file` i `register_assembly` su staging primitive za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. U trenutnim Apollo buildovima, ti staged artefakti se keširaju na client-side-u kao DPAPI-zaštićeni AES256 blobovi.
- Rezultati komandi `ls` i `ps` posebno se dobro integrišu sa Mythic-ovim browser scripts i file/process browserom, što primetno ubrzava operator triage u collaborative operations.
- Apollo-ovi fork-and-run poslovi nasleđuju podešavanja sacrificial procesa iz
`spawnto_x86` / `spawnto_x64`, izbor parent procesa nasleđuju iz `ppid`, a zatim koriste trenutno izabranu injection primitive. U praksi, to znači da vaše OPSEC podešavanje za jednu komandu često utiče na `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i `spawn`
istovremeno.
- Trenutno dokumentovani Apollo injection backends obuhvataju `CreateRemoteThread`,
`QueueUserAPC` (early-bird stil) i `NtCreateThreadEx` putem syscall-ova. Koristite
`get_injection_techniques` pre noisy post-exploitation aktivnosti i
`set_injection_technique` ako je potrebno da zamenite primitive koja nije kompatibilna sa targetom ili komandom koju želite da pokrenete.
- `blockdlls` utiče samo na sacrificial procese kreirane za post-exploitation
poslove. U kombinaciji sa manje sumnjivim `spawnto_x64` targetom od podrazumevanog
golog `rundll32.exe`, ovo je jedna od najlakših Apollo-side izmena koju možete napraviti
pre pokretanja assembly/PowerShell-heavy taskinga.

Ovaj agent ima veliki broj komandi zbog kojih je veoma sličan Cobalt Strike-ovom Beacon-u, uz nekoliko dodataka. Između ostalog, podržava:

### Uobičajene radnje

- `cat`: Ispisuje sadržaj fajla
- `cd`: Menja trenutni working directory
- `cp`: Kopira fajl sa jedne lokacije na drugu
- `ls`: Prikazuje fajlove i direktorijume u trenutnom direktorijumu ili navedenoj putanji
- `ifconfig`: Dohvata network adaptere i interfejse
- `netstat`: Dohvata informacije o TCP i UDP konekcijama
- `pwd`: Ispisuje trenutni working directory
- `ps`: Prikazuje pokrenute procese na target sistemu (uz dodatne informacije)
- `jobs`: Prikazuje sve pokrenute poslove povezane sa long-running taskingom
- `download`: Preuzima fajl sa target sistema na lokalnu mašinu
- `upload`: Otpremа fajl sa lokalne mašine na target sistem
- `reg_query`: Ispituje registry keys i vrednosti na target sistemu
- `reg_write_value`: Upisuje novu vrednost u navedeni registry key
- `sleep`: Menja sleep interval agenta, koji određuje koliko često agent proverava stanje na Mythic serveru
- I mnoge druge; koristite `help` da biste videli kompletnu listu dostupnih komandi.

### Privilege escalation

- `getprivs`: Omogućava što je moguće više privilegija na tokenu trenutnog threada
- `getsystem`: Otvara handle prema winlogon-u i duplira token, čime efektivno podiže privilegije na SYSTEM nivo
- `make_token`: Kreira novu logon sesiju i primenjuje je na agenta, omogućavajući impersonation drugog korisnika
- `steal_token`: Krade primary token iz drugog procesa, omogućavajući agentu da impersonate-uje korisnika tog procesa
- `pth`: Pass-the-Hash napad, koji agentu omogućava autentikaciju kao korisnik pomoću njegovog NTLM hash-a bez potrebe za plaintext password-om
- `mimikatz`: Pokreće Mimikatz komande za izvlačenje credentials, hash-ova i drugih osetljivih informacija iz memorije ili SAM baze
- `rev2self`: Vraća token agenta na njegov primary token, čime efektivno uklanja privilegije i vraća ih na prvobitni nivo
- `ppid`: Menja parent proces za post-exploitation poslove navođenjem novog parent process ID-ja, što omogućava bolju kontrolu nad execution context-om posla
- `printspoofer`: Izvršava PrintSpoofer komande za zaobilaženje security mera print spooler-a, omogućavajući privilege escalation ili code execution
- `dcsync`: Sinhronizuje Kerberos keys korisnika na lokalnu mašinu, omogućavajući offline password cracking ili dalje napade
- `ticket_cache_add`: Dodaje Kerberos ticket u trenutnu ili navedenu logon sesiju, omogućavajući ponovno korišćenje ticket-a ili impersonation

### Izvršavanje procesa

- `assembly_inject`: Omogućava injection .NET assembly loader-a u remote proces
- `blockdlls`: Blokira učitavanje DLL-ova koji nisu potpisani od strane Microsoft-a u post-exploitation poslove
- `execute_assembly`: Izvršava .NET assembly u kontekstu agenta
- `execute_coff`: Izvršava COFF fajl u memoriji, omogućavajući in-memory execution kompajliranog koda
- `execute_pe`: Izvršava unmanaged executable (PE)
- `keylog_inject`: Inject-uje keylogger u drugi proces i prosleđuje pritisnute tastere nazad u Mythic-ov keylog prikaz
- `screenshot` / `screenshot_inject`: Snima trenutni desktop direktno ili
inject-ovanjem screenshot assembly-ja u target proces/sesiju
- `get_injection_techniques`: Prikazuje dostupne injection techniques i trenutno izabranu
- `inline_assembly`: Izvršava .NET assembly u disposable AppDomain-u, omogućavajući privremeno izvršavanje koda bez uticaja na glavni proces agenta
- `register_assembly`: Registruje .NET assembly za kasnije izvršavanje
- `register_file`: Registruje fajl u cache agenta za kasniji `execute_*` ili PowerShell tasking
- `run`: Izvršava binary na target sistemu, koristeći sistemski `PATH` za pronalaženje executable-a
- `set_injection_technique`: Menja injection primitive koju koriste post-exploitation poslovi
- `shinject`: Inject-uje shellcode u remote proces, omogućavajući in-memory execution proizvoljnog koda
- `inject`: Inject-uje agent shellcode u remote proces, omogućavajući in-memory execution koda agenta
- `spawn`: Pokreće novu agent sesiju u navedenom executable-u, omogućavajući izvršavanje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Menjaju podrazumevani binary koji se koristi u post-exploitation poslovima na navedenu putanju, umesto korišćenja `rundll32.exe` bez parametara, što je veoma noisy.

### Mythic Forge

Ovo omogućava **load COFF/BOF** fajlova iz Mythic Forge-a, koji predstavlja repository pre-kompajliranih payloads i tools koji se mogu izvršavati na target sistemu. Sa svim komandama koje se mogu učitati, biće moguće obavljati uobičajene radnje izvršavanjem u trenutnom procesu agenta kao BOF-ova (obično uz bolji OPSEC nego pri pokretanju zasebnog procesa).

Započnite njihovu instalaciju pomoću:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Zatim koristite `forge_collections` da prikažete COFF/BOF module iz Mythic Forge-a, kako biste mogli da ih izaberete i učitate u memoriju agenta radi izvršavanja. Podrazumevano se u Apollo dodaju sledeće 2 kolekcije:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nakon učitavanja modula, on će se pojaviti na listi kao druga komanda, na primer `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

Za BOF-ove imajte na umu da Forge ne prosleđuje Apollo-u samo jedan ravan string argumenata. On mapira BOF parametre u Mythic-ov typed-array format, a zatim ih prosleđuje u Apollo-ov `execute_coff` tok. Ako se BOF učitan preko Forge-a ponaša neobično, proverite očekivane tipove BOF argumenata / entrypoint, a ne samo komandnu liniju koju ste uneli. Takođe imajte na umu da je noviji Apollo BOF loader promenio način obrade argumenata u odnosu na mnogo starije buildove iz perioda 2.3.1, pa zastareli BOF-ovi ili stare kolekcije mogu da otkažu isključivo zato što su se očekivanja za marshaling promenila.

### Izvršavanje PowerShell-a i skripti

- `powershell_import`: Uvozi novu PowerShell skriptu (.ps1) u keš agenta radi kasnijeg izvršavanja
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, omogućavajući napredno skriptovanje i automatizaciju
- `powerpick`: Injektuje PowerShell loader assembly u žrtveni proces i izvršava PowerShell komandu (bez PowerShell logging-a).
- `psinject`: Izvršava PowerShell u navedenom procesu, omogućavajući ciljano izvršavanje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično pokretanju komande u cmd.exe

### Lateralno kretanje

- `jump_psexec`: Koristi PsExec tehniku za lateralno kretanje na novi host tako što prvo kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `jump_wmi`: Koristi WMI tehniku za lateralno kretanje na novi host tako što prvo kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `link` i `unlink`: Kreiraju i prekidaju P2P veze (na primer preko SMB/TCP-a) između callback-ova.
- `wmiexecute`: Izvršava komandu na lokalnom ili navedenom udaljenom sistemu koristeći WMI, uz opcione kredencijale za impersonaciju.
- `net_dclist`: Preuzima listu domain controller-a za navedeni domen, što je korisno za identifikovanje potencijalnih ciljeva za lateralno kretanje.
- `net_localgroup`: Prikazuje lokalne grupe na navedenom računaru; ako računar nije naveden, podrazumevano koristi localhost.
- `net_localgroup_member`: Preuzima članstvo u lokalnoj grupi za navedenu grupu na lokalnom ili udaljenom računaru, omogućavajući enumeraciju korisnika u određenim grupama.
- `net_shares`: Prikazuje udaljene share-ove i njihovu dostupnost na navedenom računaru, što je korisno za identifikovanje potencijalnih ciljeva za lateralno kretanje.
- `socks`: Omogućava SOCKS 5 compliant proxy na ciljnoj mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno je sa alatima kao što je proxychains.
- `rpfwd`: Počinje osluškivanje na navedenom portu na ciljnom hostu i prosleđuje saobraćaj kroz Mythic ka udaljenoj IP adresi i portu, omogućavajući udaljeni pristup servisima na ciljnoj mreži.
- `listpipes`: Prikazuje sve named pipe-ove na lokalnom sistemu, što može biti korisno za lateralno kretanje ili eskalaciju privilegija interakcijom sa IPC mehanizmima.

Za WMI execution primitive nižeg nivoa koje se koriste ispod `jump_wmi` ili `wmiexecute`, pogledajte [WmiExec](lateral-movement/wmiexec.md). Za šire obrasce pivotiranja pogledajte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Razne komande
- `help`: Prikazuje detaljne informacije o određenim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Označava task-ove kao „cleared“, tako da ih agenti više ne mogu preuzeti. Možete navesti `all` da očistite sve task-ove ili `task Num` da očistite određeni task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon je Golang agent koji se kompajlira u **Linux i macOS** izvršne datoteke.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Trenutne napomene o build/profilu

- Trenutni Poseidon buildovi ciljaju Linux i macOS na `x86_64` i `arm64` arhitekturama.
- Podržani izlazni formati uključuju native izvršne fajlove, kao i izlaze u stilu shared library-ja, poput `dylib` i `so`.
- Poseidon podržava `http`, `websocket`, `tcp` i `dynamichttp`, a trenutni builderi izlažu multi-egress podešavanja kao što su `egress_order` i pragovi za failover.
- Poseidonovi trenutni capability metapodaci takođe oglašavaju browser scripts, integraciju file/process browser-a, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd i P2P, tako da može da funkcioniše kao pravi Linux/macOS pivot node, a ne samo kao jednostavan remote shell.
- Opcije tokom build-a, kao što su `proxy_bypass` i `garble`, vredi proveriti kada su vam potrebni ili čistije mrežno ponašanje ili dodatna Go binary obfuscation.
- `pty` je jedna od najkorisnijih novijih QoL komandi za Linux/macOS
operacije, jer otvara interaktivni PTY i može da izloži Mythic-side
port za potpuniju terminal interakciju bez pribegavanja starijem
`sleep 0` + SOCKS workaround-u.
- Poseidonova trenutna dokumentacija je naročito zanimljiva za macOS-heavy
tradecraft: `jxa` izvršava JavaScript for Automation u memoriji,
`screencapture` snima desktop prijavljenog korisnika, `clipboard_monitor`
prosleđuje promene pasteboard-a, `execute_library` učitava lokalni dylib i
poziva funkciju iz njega, a `libinject` primorava udaljeni proces da učita
dylib sa diska.
- Za dugotrajne poslove imajte na umu da Poseidon izvršava post-exploitation rad
u goroutine/thread procesima koji su kooperativni, a ne mogu biti nasilno
prekinuti. Dokumentacija takođe izričito navodi da trenutno ne postoji
ugrađena agent obfuscation, pa tradecraft na nivou build/profila ima veći
značaj nego kod komercijalnih implant-a sa intenzivnom obfuscation.

Za macOS-specific tradecraft u vezi sa Mythic-backed operacijama, zloupotrebom JAMF-a ili idejama poput MDM-as-C2, pogledajte [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Kada se koristi na Linux-u ili macOS-u, ima neke zanimljive komande:

### Uobičajene radnje

- `cat`: Prikazuje sadržaj fajla
- `cd`: Menja trenutni working directory
- `chmod`: Menja dozvole fajla
- `config`: Prikazuje trenutnu konfiguraciju i informacije o hostu
- `cp`: Kopira fajl sa jedne lokacije na drugu
- `curl`: Izvršava jedan web zahtev sa opcionim headerima i metodom
- `upload`: Otpremanje fajla na target
- `download`: Preuzima fajl sa target sistema na lokalnu mašinu
- I mnoge druge

### Pretraga osetljivih informacija

- `triagedirectory`: Pronalaženje zanimljivih fajlova unutar direktorijuma na hostu, kao što su osetljivi fajlovi ili credentials.
- `getenv`: Dobavljanje svih trenutnih environment variables.

### macOS-specific tradecraft

- `jxa`: Izvršava JavaScript for Automation u memoriji putem `OSAScript`, što je
korisno za native macOS post-exploitation bez ostavljanja zasebnih script
fajlova.
- `clipboard_monitor`: Ispituje pasteboard i prijavljuje promene nazad Mythic-u,
što je korisno za credential/token theft workflow-e koji se oslanjaju na copy/paste.
- `screencapture`: Snima korisnikov desktop na macOS-u.
- `execute_library`: Učitava dylib sa diska i poziva određenu exportovanu funkciju.
- `libinject`: Inject-uje shellcode stub koji primorava drugi macOS proces da učita dylib sa diska.
- `persist_launchd`: Direktno iz agenta kreira LaunchAgent / LaunchDaemon persistence.

### Lateralno kretanje

- `ssh`: Povezuje se na host putem SSH-a koristeći određene credentials i otvara PTY bez pokretanja ssh-a.
- `sshauth`: Povezuje se na navedene hostove koristeći određene credentials. Ovo se takođe može koristiti za izvršavanje određene komande na udaljenim hostovima putem SSH-a ili za SCP fajlova.
- `link_tcp`: Povezuje se sa drugim agentom preko TCP-a, omogućavajući direktnu komunikaciju između agenata.
- `link_webshell`: Povezuje se sa agentom koristeći webshell P2P profil, omogućavajući remote access web interfejsu agenta.
- `rpfwd`: Pokreće ili zaustavlja Reverse Port Forward, omogućavajući remote access servisima na target mreži.
- `socks`: Pokreće ili zaustavlja SOCKS5 proxy na target mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno je sa alatima poput proxychains.
- `portscan`: Skenira hostove radi pronalaženja otvorenih portova, što je korisno za identifikovanje potencijalnih targeta za lateralno kretanje ili dalje napade.

### Izvršavanje procesa

- `shell`: Izvršava jednu shell komandu putem /bin/sh, omogućavajući direktno izvršavanje komandi na target sistemu.
- `run`: Izvršava komandu sa diska sa argumentima, omogućavajući izvršavanje binarnih fajlova ili scriptova na target sistemu.
- `pty`: Otvara interaktivni PTY, omogućavajući direktnu interakciju sa shell-om na target sistemu.








## Reference

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
