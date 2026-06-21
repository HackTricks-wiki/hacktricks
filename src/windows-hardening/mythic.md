# Mythic

{{#include ../banners/hacktricks-training.md}}

## Šta je Mythic?

Mythic je open-source, modularni, kolaborativni command and control (C2) framework dizajniran za red teaming. Omogućava operatorima da upravljaju i raspoređuju agente (payloads) na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža browser UI za tasking sa više operatora, rukovanje fajlovima, SOCKS/rpfwd upravljanje i generisanje payload-a.

Za razliku od monolitnih framework-a, sam Mythic repository **ne** dolazi sa payload tipovima ili C2 profilima. Agenti, wrapperi i C2 profili se obično instaliraju kao eksterni komponenti i mogu se ažurirati nezavisno od Mythic core-a.

### Instalacija

Da biste instalirali Mythic, pratite uputstva na zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Uobičajeni bootstrap iz Mythic direktorijuma je:
```bash
sudo make
sudo ./mythic-cli start
```
Ako Mythic već radi, obično možete dodati novi agent ili profile sa `./mythic-cli install github ...`, a zatim ili restartovati Mythic ili samo direktno pokrenuti novu komponentu.

### Agents

Mythic podržava više agenata, koji su **payloads koji izvršavaju zadatke na kompromitovanim sistemima**. Svaki agent može biti prilagođen specifičnim potrebama i može da radi na različitim operativnim sistemima.

Podrazumevano, Mythic nema instalirane agente. Open-source community agents se nalaze na [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) je korisna za brzo proveravanje podržanih operativnih sistema, payload formata, wrappers i C2 profila.

Da biste instalirali agenta iz te organizacije, možete pokrenuti:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Oblik `sudo -E` je koristan kada instalirate iz okruženja bez root privilegija. Možete dodati nove agente pomoću prethodne komande čak i ako Mythic već radi.

### C2 Profiles

C2 profiles u Mythic definišu **kako agenti komuniciraju sa Mythic serverom**. Oni određuju komunikacioni protokol, metode enkripcije i druga podešavanja. Možete kreirati i upravljati C2 profiles kroz Mythic web interfejs.

Podrazumevano, Mythic se instalira bez profila, međutim, moguće je preuzeti neke profiles iz repozitorijuma [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) pokretanjem:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Trenutni operator-relevant profili koje treba imati na umu:

- [`http`](https://github.com/MythicC2Profiles/http): osnovni asinhroni GET/POST saobraćaj.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): fleksibilniji HTTP saobraćaj sa više callback domena, fail-over/round-robin rotacijom, custom headers/query parametrima i transformacijama poruka (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) smeštenim u cookies, headers, query parametrima ili body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven oblikovanje HTTP poruka kada je statički `http` profile previše prepoznatljiv.

### Current platform notes

- Mnogi javni agents i profiles sada se instaliraju sa unapred izgrađenim remote container images.
Ako fork-uješ komponentu ili je lokalno patch-uješ, a Mythic i dalje koristi staro ponašanje, proveri generisane `.env` unose za `*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; omogućavanje
`*_USE_BUILD_CONTEXT="true"` je obično ono što tera Mythic da ponovo izgradi iz tvog
lokalnog Docker contexta umesto da tiho ponovo koristi remote image.
- Browser scripts su jedna od Mythic-ovih najvrednijih quality-of-life funkcija
za operatore: mogu da pretvore raw command output u tabele, screenshot
viewere, download linkove i dugmad koja direktno iz UI-ja pokreću follow-on tasking.
Ovo je posebno korisno za ponavljajuće `ls`, `ps`, triage
i file-browser workflows.
- Noviji Mythic buildovi takođe podržavaju interactive tasking i Push C2 obrasce
koji smanjuju potrebu za `sleep 0` pollingom tokom PTY/SOCKS/rpfwd-heavy
operacija. Kada agent/profile to podržava, ovo je obično niži overhead
nego stalno bombardovanje servera check-inovima samo da bi interaktivni
kanal ostao upotrebljiv.

### Wrapper payloads

Wrapper payloads ti omogućavaju da zadržiš istu agent logiku dok menjaš on-disk reprezentaciju koja se isporučuje ili perzistira.

- `service_wrapper`: pretvara drugi payload u Windows service executable, što je korisno kada execution path zahteva validan service binary.
- `scarecrow_wrapper`: obavija kompatibilan shellcode sa ScareCrow loaderom da bi generisao loader-backed outputs kao što su EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C# koristeći 4.0 .NET Framework, dizajniran za upotrebu u SpecterOps training ponudama.

Instaliraj ga sa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Trenutne beleške o build/profile

- Apollo trenutno može da emituje `WinExe`, `Shellcode`, `Service`, i `Source` payloads.
- Najčešće korišćeni Apollo profiles su `http`, `httpx`, `smb`, `tcp`, i `websocket`.
- `httpx` je obično fleksibilnija opcija kada vam trebaju rotacija domena, podrška za proxy, prilagođeno postavljanje poruka i transformacije poruka umesto starijeg statičkog `http` profile.
- Apollo podržava wrapper payloads kao što su `service_wrapper` i `scarecrow_wrapper`.
- `register_file` i `register_assembly` su staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, i `powerpick`. U trenutnim Apollo buildovima, ti staged artifacts se keširaju na klijentskoj strani kao DPAPI-protected AES256 blobs.
- `ls` i `ps` rezultati se naročito dobro integrišu sa Mythic browser scripts i file/process browser, što značajno ubrzava operator triage u collaborative operations.
- Apollo fork-and-run jobs nasleđuju podešavanja svog sacrificial process-a iz
`spawnto_x86` / `spawnto_x64`, nasleđuju parent selection iz `ppid`, i
zatim koriste trenutno izabranu injection primitive. U praksi, to znači
da vaše OPSEC podešavanje za jednu komandu često utiče na
`execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, i `spawn` istovremeno.
- Trenutno dokumentovani Apollo injection backends uključuju `CreateRemoteThread`,
`QueueUserAPC` (early-bird style), i `NtCreateThreadEx` preko syscalls. Koristite
`get_injection_techniques` pre noisy post-exploitation i
`set_injection_technique` ako treba da pređete sa primitive koja
se sudara sa targetom ili komandom koju želite da pokrenete.
- `blockdlls` utiče samo na sacrificial processes kreirane za post-exploitation
jobs. U kombinaciji sa manje sumnjivim `spawnto_x64` targetom od podrazumevanog
golog `rundll32.exe`, ovo je jedna od najlakših Apollo-side izmena koje možete
da napravite pre pokretanja assembly/PowerShell-heavy tasking.

Ovaj agent ima mnogo komandi, što ga čini veoma sličnim Cobalt Strike's Beacon, uz neke dodatke. Među njima podržava:

### Uobičajene akcije

- `cat`: Prikaži sadržaj fajla
- `cd`: Promeni trenutni working directory
- `cp`: Kopiraj fajl sa jedne lokacije na drugu
- `ls`: Prikaži fajlove i direktorijume u trenutnom direktorijumu ili zadatoj putanji
- `ifconfig`: Prikaži network adapters i interfaces
- `netstat`: Prikaži TCP i UDP informacije o konekcijama
- `pwd`: Prikaži trenutni working directory
- `ps`: Prikaži running processes na target sistemu (sa dodatnim info)
- `jobs`: Prikaži sve running jobs povezane sa long-running tasking
- `download`: Preuzmi fajl sa target sistema na lokalnu mašinu
- `upload`: Pošalji fajl sa lokalne mašine na target sistem
- `reg_query`: Upitaj registry keys i values na target sistemu
- `reg_write_value`: Upiši novu vrednost u navedeni registry key
- `sleep`: Promeni sleep interval agenta, koji određuje koliko često proverava Mythic server
- I mnoge druge, koristite `help` da vidite punu listu dostupnih komandi.

### Eskalacija privilegija

- `getprivs`: Omogući što više privilegija na trenutnom thread token-u
- `getsystem`: Otvori handle do winlogon i dupliraj token, efektivno podižući privilegije na SYSTEM nivo
- `make_token`: Kreiraj novu logon sesiju i primeni je na agenta, omogućavajući impersonation drugog korisnika
- `steal_token`: Ukradi primary token iz drugog procesa, omogućavajući agentu da impersonira korisnika tog procesa
- `pth`: Pass-the-Hash napad, omogućavajući agentu da se autentifikuje kao korisnik koristeći njegov NTLM hash bez potrebe za plaintext lozinkom
- `mimikatz`: Pokreni Mimikatz komande za ekstrakciju credentials, hash-eva i drugih osetljivih informacija iz memorije ili SAM baze
- `rev2self`: Vrati token agenta na njegov primary token, efektivno spuštajući privilegije nazad na originalni nivo
- `ppid`: Promeni parent process za post-exploitation jobs navođenjem novog parent process ID-a, omogućavajući bolju kontrolu nad execution context-om job-a
- `printspoofer`: Izvrši PrintSpoofer komande za zaobilaženje print spooler security measures, omogućavajući eskalaciju privilegija ili code execution
- `dcsync`: Sinhronizuj Kerberos ključeve korisnika na lokalnu mašinu, omogućavajući offline password cracking ili dalje napade
- `ticket_cache_add`: Dodaj Kerberos ticket u trenutnu logon sesiju ili navedenu, omogućavajući ponovnu upotrebu tiketa ili impersonation

### Izvršavanje procesa

- `assembly_inject`: Omogućava da se .NET assembly loader injektuje u remote process
- `blockdlls`: Blokira učitavanje DLL-ova koji nisu Microsoft signed u post-exploitation jobs
- `execute_assembly`: Izvršava .NET assembly u kontekstu agenta
- `execute_coff`: Izvršava COFF fajl u memoriji, omogućavajući in-memory execution kompajliranog koda
- `execute_pe`: Izvršava unmanaged executable (PE)
- `keylog_inject`: Injketuje keylogger u drugi process i šalje otkucaje nazad u Mythic keylog prikaz
- `screenshot` / `screenshot_inject`: Snimi trenutni desktop direktno ili
ubacivanjem screenshot assembly-ja u target process/session
- `get_injection_techniques`: Prikaži dostupne injection techniques i trenutno izabranu
- `inline_assembly`: Izvršava .NET assembly u disposable AppDomain-u, omogućavajući privremeno izvršavanje koda bez uticaja na glavni process agenta
- `register_assembly`: Registruj .NET assembly za kasnije izvršavanje
- `register_file`: Registruj fajl u kešu agenta za kasnije `execute_*` ili PowerShell tasking
- `run`: Izvršava binary na target sistemu, koristeći sistemski PATH da pronađe executable
- `set_injection_technique`: Promeni injection primitive koju koriste post-exploitation jobs
- `shinject`: Injektuje shellcode u remote process, omogućavajući in-memory execution proizvoljnog koda
- `inject`: Injektuje agent shellcode u remote process, omogućavajući in-memory execution koda agenta
- `spawn`: Pokreće novu agent sesiju u navedenom executable-u, omogućavajući izvršavanje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Promeni podrazumevani binary koji koriste post-exploitation jobs na navedenu putanju umesto korišćenja `rundll32.exe` bez parametara, što je veoma noisy.

### Mythic Forge

Ovo omogućava da se **učitaju COFF/BOF** fajlovi iz Mythic Forge-a, koji je repozitorijum unapred kompajliranih payloads i alata koji mogu da se izvrše na target sistemu. Sa svim komandama koje mogu da se učitaju biće moguće obaviti uobičajene akcije njihovim izvršavanjem u trenutnom procesu agenta kao BOFs (obično uz bolji OPSEC nego pokretanje odvojenog procesa).

Počnite da ih instalirate sa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Zatim, koristite `forge_collections` da prikažete COFF/BOF module iz Mythic Forge kako biste mogli da ih izaberete i učitate u memoriju agenta za izvršavanje. Podrazumevano, sledeće 2 kolekcije su dodate u Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nakon što se jedan modul učita, pojaviće se u listi kao druga komanda, poput `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

Za BOF-ove, imajte na umu da Forge **ne** prosleđuje samo jedan ravni string argumenata
Apollo-u. On mapira BOF parametre u Mythic-ov typed-array format i zatim
ih prosleđuje u Apollo `execute_coff` tok. Ako se Forge-učitani BOF ponaša
čudno, proverite očekivane tipove BOF argumenata / entrypoint, a ne samo
command line koji ste uneli.

### PowerShell & scripting execution

- `powershell_import`: Uvozi novi PowerShell skript (.ps1) u keš agenta za kasnije izvršavanje
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, omogućavajući napredno skriptovanje i automatizaciju
- `powerpick`: Ubrizgava PowerShell loader assembly u žrtveni proces i izvršava PowerShell komandu (bez powershell logginga).
- `psinject`: Izvršava PowerShell u specificiranom procesu, omogućavajući ciljano izvršavanje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično kao pokretanje komande u cmd.exe

### Lateral Movement

- `jump_psexec`: Koristi PsExec tehniku za lateralno premeštanje na novi host tako što prvo kopira Apollo agent izvršni fajl (apollo.exe) i pokreće ga.
- `jump_wmi`: Koristi WMI tehniku za lateralno premeštanje na novi host tako što prvo kopira Apollo agent izvršni fajl (apollo.exe) i pokreće ga.
- `link` and `unlink`: Kreira i uklanja P2P linkove (na primer preko SMB/TCP) između callbacks.
- `wmiexecute`: Izvršava komandu na lokalnom ili navedenom udaljenom sistemu koristeći WMI, sa opcionalnim kredencijalima za impersonation.
- `net_dclist`: Preuzima listu domain controller-a za navedeni domain, korisno za identifikovanje potencijalnih meta za lateral movement.
- `net_localgroup`: Izlistava lokalne grupe na navedenom računaru, podrazumevano localhost ako nije naveden računar.
- `net_localgroup_member`: Preuzima članstvo lokalne grupe za navedenu grupu na lokalnom ili udaljenom računaru, omogućavajući enumeraciju korisnika u određenim grupama.
- `net_shares`: Izlistava udaljene deljene resurse i njihovu dostupnost na navedenom računaru, korisno za identifikovanje potencijalnih meta za lateral movement.
- `socks`: Omogućava SOCKS 5 kompatibilan proxy na ciljnoj mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno sa alatima kao što su proxychains.
- `rpfwd`: Pokreće slušanje na navedenom portu na ciljnom hostu i prosleđuje saobraćaj kroz Mythic do udaljenog IP-a i porta, omogućavajući udaljeni pristup servisima na ciljnoj mreži.
- `listpipes`: Izlistava sve named pipes na lokalnom sistemu, što može biti korisno za lateral movement ili privilege escalation interakcijom sa IPC mehanizmima.

Za niželevelske WMI execution primitive koje se koriste ispod `jump_wmi` ili `wmiexecute`, pogledajte [WmiExec](lateral-movement/wmiexec.md). Za šire pivoting obrasce, pogledajte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Prikazuje detaljne informacije o određenim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Označava zadatke kao 'cleared' tako da ih agenti ne mogu preuzeti. Možete navesti `all` da obrišete sve zadatke ili `task Num` da obrišete određeni zadatak.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon je Golang agent koji se kompajlira u **Linux i macOS** izvršne fajlove.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.
- `pty` is one of the most useful newer-quality-of-life commands for Linux/macOS
operations because it opens an interactive PTY and can expose a Mythic-side
port for fuller terminal interaction without resorting to the older `sleep 0`
+ SOCKS workaround.
- Poseidon's current docs are especially interesting for macOS-heavy
tradecraft: `jxa` executes JavaScript for Automation in-memory,
`screencapture` grabs the logged-in desktop, `clipboard_monitor` streams
pasteboard changes, `execute_library` loads a local dylib and calls a
function from it, and `libinject` forces a remote process to load an on-disk
dylib.
- For long-running jobs, remember that Poseidon executes post-exploitation work
in goroutines/threads that are cooperative rather than hard-killable. The
docs also explicitly note that there is currently no built-in agent
obfuscation, so build/profile-level tradecraft matters more than with heavily
obfuscated commercial implants.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Ispiši sadržaj fajla
- `cd`: Promeni trenutni radni direktorijum
- `chmod`: Promeni dozvole fajla
- `config`: Prikaži trenutnu konfiguraciju i informacije o hostu
- `cp`: Kopiraj fajl sa jedne lokacije na drugu
- `curl`: Izvrši jedan web zahtev sa opcionalnim header-ima i metodom
- `upload`: Upload-uj fajl na target
- `download`: Download-uj fajl sa target sistema na lokalnu mašinu
- And many more

### Search Sensitive Information

- `triagedirectory`: Pronađi zanimljive fajlove unutar direktorijuma na hostu, kao što su sensitive fajlovi ili credentials.
- `getenv`: Prikaži sve trenutne environment variables.

### macOS-specific tradecraft

- `jxa`: Izvrši JavaScript for Automation u memoriji preko `OSAScript`, što je
korisno za native macOS post-exploitation bez ostavljanja odvojenih script
fajlova.
- `clipboard_monitor`: Poll-uj pasteboard i prijavi promene nazad u Mythic,
što je zgodno za credential/token theft workflows koji se oslanjaju na copy/paste.
- `screencapture`: Snimi desktop korisnika na macOS.
- `execute_library`: Učitaj dylib sa diska i pozovi određenu exported funkciju.
- `libinject`: Inject-uj shellcode stub koji primorava drugi macOS process da učita dylib sa diska.
- `persist_launchd`: Kreiraj LaunchAgent / LaunchDaemon persistence direktno iz agenta.

### Move laterally

- `ssh`: SSH na host koristeći navedene credentials i otvori PTY bez pokretanja ssh.
- `sshauth`: SSH na navedeni host(ove) koristeći navedene credentials. Ovo takođe možeš koristiti za izvršavanje određene komande na remote host-ovima preko SSH ili za SCP fajlova.
- `link_tcp`: Poveži se sa drugim agentom preko TCP, omogućavajući direktnu komunikaciju između agenata.
- `link_webshell`: Poveži se sa agentom koristeći webshell P2P profil, omogućavajući remote access web interfejsu agenta.
- `rpfwd`: Pokreni ili zaustavi Reverse Port Forward, omogućavajući remote access servisima na target mreži.
- `socks`: Pokreni ili zaustavi SOCKS5 proxy na target mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno sa alatima poput proxychains.
- `portscan`: Skeniraj host(ove) na otvorene portove, korisno za identifikaciju potencijalnih targeta za lateral movement ili daljnje attacks.

### Process execution

- `shell`: Izvrši jednu shell komandu preko /bin/sh, omogućavajući direktno izvršavanje komandi na target sistemu.
- `run`: Izvrši komandu sa diska sa argumentima, omogućavajući izvršavanje binary-ja ili scripti na target sistemu.
- `pty`: Otvori interaktivni PTY, omogućavajući direktnu interakciju sa shell-om na target sistemu.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
