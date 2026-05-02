# Mythic

{{#include ../banners/hacktricks-training.md}}

## Šta je Mythic?

Mythic je open-source, modularni, saradnički command and control (C2) framework namenjen za red teaming. Omogućava operaterima da upravljaju i raspoređuju agente (payloads) na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža browser UI za tasking više operatera, rukovanje fajlovima, upravljanje SOCKS/rpfwd i generisanje payloads.

Za razliku od monolitnih framework-a, sam Mythic repository **ne** dolazi sa tipovima payloads ili C2 profiles. Agenti, wrappers i C2 profiles se obično instaliraju kao eksterni komponente i mogu se ažurirati nezavisno od Mythic core.

### Instalacija

Da biste instalirali Mythic, pratite uputstva na zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Uobičajeni bootstrap iz Mythic direktorijuma je:
```bash
sudo make
sudo ./mythic-cli start
```
Ako Mythic već radi, obično možete dodati novog agenta ili profil pomoću `./mythic-cli install github ...`, a zatim ili restartovati Mythic ili jednostavno direktno pokrenuti novu komponentu.

### Agents

Mythic podržava više agenata, koji su **payloads koji izvršavaju zadatke na kompromitovanim sistemima**. Svaki agent može biti prilagođen specifičnim potrebama i može da radi na različitim operativnim sistemima.

Podrazumevano, Mythic nema instalirane agente. Agenti open-source zajednice nalaze se na [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) je koristan za brzo proveravanje podržanih operativnih sistema, payload formata, wrapper-a i C2 profila.

Da biste instalirali agenta iz te organizacije, možete pokrenuti:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` je korisna kada instalirate iz okruženja koje nije root. Možete dodati nove agente prethodnom komandom čak i ako Mythic već radi.

### C2 Profiles

C2 profiles u Mythic definišu **kako agenti komuniciraju sa Mythic serverom**. Oni određuju communication protocol, encryption methods i druga podešavanja. C2 profiles možete kreirati i upravljati njima kroz Mythic web interface.

Podrazumevano, Mythic se instalira bez profila, međutim, moguće je preuzeti neke profile iz repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) pokretanjem:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): osnovni asinhroni GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): fleksibilniji HTTP traffic sa više callback domain-a, fail-over/round-robin rotacijom, custom headers/query parameters, i message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) smeštenim u cookies, headers, query parameters, ili body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP oblikovanje poruka kada je statički `http` profile previše prepoznatljiv.

### Wrapper payloads

Wrapper payloads vam omogućavaju da zadržite istu agent logiku dok menjate on-disk reprezentaciju koja se isporučuje ili perzistira.

- `service_wrapper`: pretvara drugi payload u Windows service executable, što je korisno kada execution path zahteva validan service binary.
- `scarecrow_wrapper`: oblaže kompatibilan shellcode pomoću ScareCrow loader-a da bi generisao loader-backed izlaze kao što su EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C# koristeći 4.0 .NET Framework, dizajniran za upotrebu u SpecterOps training ponudama.

Instalirajte ga sa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Trenutne napomene o build/profile

- Apollo trenutno može da emituje `WinExe`, `Shellcode`, `Service` i `Source` payloads.
- Najčešće korišćeni Apollo profili su `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` je obično fleksibilnija opcija kada su ti potrebni domain rotation, proxy support, custom message placement i message transforms umesto starijeg statičkog `http` profila.
- Apollo podržava wrapper payloads kao što su `service_wrapper` i `scarecrow_wrapper`.
- `register_file` i `register_assembly` su staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. U trenutnim Apollo buildovima, ti staged artifacts se keširaju na klijentskoj strani kao DPAPI-protected AES256 blobs.
- `ls` i `ps` rezultati se posebno dobro integrišu sa Mythic browser scripts i file/process browser, što operator triage čini primetno bržim u kolaborativnim operacijama.

Ovaj agent ima mnogo komandi, što ga čini veoma sličnim Cobalt Strike's Beacon sa nekim dodacima. Među njima, podržava:

### Uobičajene akcije

- `cat`: Ispis sadržaja fajla
- `cd`: Promeni trenutni working directory
- `cp`: Kopiraj fajl sa jedne lokacije na drugu
- `ls`: Prikaži fajlove i direktorijume u trenutnom direktorijumu ili navedenoj putanji
- `ifconfig`: Prikaži network adapters i interface-e
- `netstat`: Prikaži informacije o TCP i UDP konekcijama
- `pwd`: Ispis trenutnog working directory
- `ps`: Prikaži pokrenute procese na ciljnom sistemu (sa dodatnim informacijama)
- `jobs`: Prikaži sve aktivne jobs povezane sa long-running tasking
- `download`: Preuzmi fajl sa ciljnog sistema na lokalnu mašinu
- `upload`: Pošalji fajl sa lokalne mašine na ciljni sistem
- `reg_query`: Upit za registry keys i values na ciljnom sistemu
- `reg_write_value`: Upiši novu vrednost u određeni registry key
- `sleep`: Promeni agentov sleep interval, koji određuje koliko često se javlja Mythic serveru
- I mnoge druge, koristi `help` da vidiš punu listu dostupnih komandi.

### Privilege escalation

- `getprivs`: Omogući što više privileges na trenutnom thread tokenu
- `getsystem`: Otvori handle na winlogon i dupliraj token, efektivno podižući privileges na SYSTEM nivo
- `make_token`: Kreiraj novu logon session i primeni je na agenta, omogućavajući impersonation drugog korisnika
- `steal_token`: Ukradi primary token iz drugog procesa, omogućavajući agentu da impersonira tog korisnika procesa
- `pth`: Pass-the-Hash attack, omogućavajući agentu da se autentifikuje kao korisnik koristeći njihov NTLM hash bez potrebe za plaintext password
- `mimikatz`: Pokreni Mimikatz komande za ekstrakciju credentials, hashes i drugih osetljivih informacija iz memory ili SAM database
- `rev2self`: Vrati agentov token na njegov primary token, efektivno spuštajući privileges nazad na originalni nivo
- `ppid`: Promeni parent process za post-exploitation jobs navođenjem novog parent process ID, omogućavajući bolju kontrolu nad job execution context
- `printspoofer`: Izvrši PrintSpoofer komande za zaobilaženje print spooler security measures, omogućavajući privilege escalation ili code execution
- `dcsync`: Sinhronizuj Kerberos keys korisnika na lokalnu mašinu, omogućavajući offline cracking lozinki ili dalje napade
- `ticket_cache_add`: Dodaj Kerberos ticket u trenutnu logon session ili navedenu, omogućavajući reuse ticketa ili impersonation

### Izvršavanje procesa

- `assembly_inject`: Omogućava ubacivanje .NET assembly loader-a u udaljeni proces
- `blockdlls`: Blokira učitavanje DLL-ova koji nisu potpisani od strane Microsofta u post-exploitation jobs
- `execute_assembly`: Izvršava .NET assembly u kontekstu agenta
- `execute_coff`: Izvršava COFF fajl u memoriji, omogućavajući in-memory execution kompajliranog koda
- `execute_pe`: Izvršava unmanaged executable (PE)
- `get_injection_techniques`: Prikaži dostupne injection techniques i trenutno izabranu
- `inline_assembly`: Izvršava .NET assembly u disposable AppDomain, omogućavajući privremeno izvršavanje koda bez uticaja na glavni proces agenta
- `register_assembly`: Registruj .NET assembly za kasnije izvršavanje
- `register_file`: Registruj fajl u agent cache za kasniji `execute_*` ili PowerShell tasking
- `run`: Izvršava binary na ciljnom sistemu, koristeći PATH sistema da pronađe executable
- `set_injection_technique`: Promeni injection primitive koji koriste post-exploitation jobs
- `shinject`: Ubacuje shellcode u udaljeni proces, omogućavajući in-memory execution proizvoljnog koda
- `inject`: Ubacuje agent shellcode u udaljeni proces, omogućavajući in-memory execution koda agenta
- `spawn`: Pokreće novu agent session u navedenom executable-u, omogućavajući izvršavanje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Promeni podrazumevani binary koji koriste post-exploitation jobs na navedenu putanju umesto da koriste `rundll32.exe` bez parametara, što je veoma noisy.

### Mythic Forge

Ovo omogućava da se **load COFF/BOF** fajlovi iz Mythic Forge, koji je repozitorijum unapred kompajliranih payloads i tools koji mogu da se izvrše na ciljnom sistemu. Sa svim komandama koje mogu da se učitaju, biće moguće obavljati uobičajene akcije tako što će se izvršavati u trenutnom procesu agenta kao BOFs (obično sa boljim OPSEC nego pokretanje zasebnog procesa).

Počni da ih instaliraš sa:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, upotrebite `forge_collections` da prikažete COFF/BOF module iz Mythic Forge kako biste mogli da ih izaberete i učitate u memoriju agenta za izvršavanje. Podrazumevano, sledeće 2 kolekcije su dodate u Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nakon što se jedan modul učita, pojaviće se u listi kao još jedna komanda poput `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Uvozi novi PowerShell skript (.ps1) u keš agenta za kasnije izvršavanje
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, omogućavajući napredno skriptovanje i automatizaciju
- `powerpick`: Ubrizgava PowerShell loader assembly u sacrificial proces i izvršava PowerShell komandu (bez powershell logging).
- `psinject`: Izvršava PowerShell u navedenom procesu, omogućavajući ciljano izvršavanje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično pokretanju komande u cmd.exe

### Lateral Movement

- `jump_psexec`: Koristi PsExec tehniku za lateralno premeštanje na novi host tako što prvo kopira Apollo agent izvršni fajl (apollo.exe) i izvršava ga.
- `jump_wmi`: Koristi WMI tehniku za lateralno premeštanje na novi host tako što prvo kopira Apollo agent izvršni fajl (apollo.exe) i izvršava ga.
- `link` and `unlink`: Kreira i ukida P2P linkove (na primer preko SMB/TCP) između callback-ova.
- `wmiexecute`: Izvršava komandu na lokalnom ili navedenom udaljenom sistemu koristeći WMI, sa opcionim kredencijalima za impersonaciju.
- `net_dclist`: Preuzima listu domain controller-a za navedeni domain, korisno za identifikovanje potencijalnih meta za lateral movement.
- `net_localgroup`: Prikazuje lokalne grupe na navedenom računaru, podrazumevano localhost ako nijedan računar nije naveden.
- `net_localgroup_member`: Preuzima članstvo lokalne grupe za navedenu grupu na lokalnom ili udaljenom računaru, omogućavajući enumeraciju korisnika u određenim grupama.
- `net_shares`: Prikazuje udaljene share-ove i njihovu dostupnost na navedenom računaru, korisno za identifikovanje potencijalnih meta za lateral movement.
- `socks`: Omogućava SOCKS 5 compliant proxy na ciljanoj mreži, omogućavajući tunneling saobraćaja kroz kompromitovan host. Kompatibilno sa alatima kao što je proxychains.
- `rpfwd`: Pokreće slušanje na navedenom portu na ciljnom hostu i prosleđuje saobraćaj kroz Mythic do udaljenog IP-a i porta, omogućavajući udaljeni pristup servisima na ciljanoj mreži.
- `listpipes`: Prikazuje sve named pipes na lokalnom sistemu, što može biti korisno za lateral movement ili privilege escalation kroz interakciju sa IPC mehanizmima.

Za nižerazinske WMI execution primitive koje se koriste ispod `jump_wmi` ili `wmiexecute`, pogledajte [WmiExec](lateral-movement/wmiexec.md). Za šire pivoting obrasce, pogledajte [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Prikazuje detaljne informacije o specifičnim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Obeležava zadatke kao 'cleared' tako da agenti ne mogu da ih preuzmu. Možete navesti `all` da biste očistili sve zadatke ili `task Num` da biste očistili određeni zadatak.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon je Golang agent koji se kompajlira u **Linux and macOS** izvršne fajlove.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Trenutne napomene o build/profile

- Trenutni Poseidon buildovi ciljaju Linux i macOS na `x86_64` i `arm64`.
- Podržani izlazni formati uključuju native izvršne fajlove plus izlaze u stilu shared-library kao što su `dylib` i `so`.
- Poseidon podržava `http`, `websocket`, `tcp`, i `dynamichttp`, a trenutni builderi izlažu multi-egress podešavanja kao što su `egress_order` i pragovi failover-a.
- Opcije u vreme build-a kao što su `proxy_bypass` i `garble` vredi proveriti kada vam treba ili čistije mrežno ponašanje ili dodatna Go binarna obfuskacija.

Za macOS-specifičan tradecraft oko Mythic-backed operacija, JAMF abuse, ili MDM-as-C2 ideja, pogledajte [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Kada se koristi na Linux-u ili macOS-u, ima neke zanimljive komande:

### Uobičajene radnje

- `cat`: Prikazuje sadržaj fajla
- `cd`: Menja trenutni radni direktorijum
- `chmod`: Menja dozvole fajla
- `config`: Prikazuje trenutnu konfiguraciju i informacije o hostu
- `cp`: Kopira fajl sa jedne lokacije na drugu
- `curl`: Izvršava jedan web zahtev sa opcionim header-ima i metodom
- `upload`: Otprema fajl na cilj
- `download`: Preuzima fajl sa ciljnog sistema na lokalnu mašinu
- I još mnogo toga

### Pretraga osetljivih informacija

- `triagedirectory`: Pronalazi zanimljive fajlove unutar direktorijuma na hostu, kao što su osetljivi fajlovi ili kredencijali.
- `getenv`: Dobija sve trenutne environment varijable.

### Lateralno kretanje

- `ssh`: SSH na host koristeći dodeljene kredencijale i otvara PTY bez pokretanja ssh.
- `sshauth`: SSH na navedeni host(e) koristeći dodeljene kredencijale. Ovo možete koristiti i za izvršavanje određene komande na udaljenim hostovima preko SSH ili za SCP fajlova.
- `link_tcp`: Povezuje se sa drugim agentom preko TCP, omogućavajući direktnu komunikaciju između agenata.
- `link_webshell`: Povezuje se sa agentom koristeći webshell P2P profil, omogućavajući udaljeni pristup web interfejsu agenta.
- `rpfwd`: Pokreće ili zaustavlja Reverse Port Forward, omogućavajući udaljeni pristup servisima na ciljnoj mreži.
- `socks`: Pokreće ili zaustavlja SOCKS5 proxy na ciljnoj mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno sa alatima kao što je proxychains.
- `portscan`: Skenira host(ove) na otvorene portove, korisno za identifikovanje potencijalnih ciljeva za lateralno kretanje ili dalje napade.

### Izvršavanje procesa

- `shell`: Izvršava jednu shell komandu preko /bin/sh, omogućavajući direktno izvršavanje komandi na ciljnom sistemu.
- `run`: Izvršava komandu sa diska sa argumentima, omogućavajući izvršavanje binarnih fajlova ili skripti na ciljnom sistemu.
- `pty`: Otvara interaktivni PTY, omogućavajući direktnu interakciju sa shell-om na ciljnom sistemu.




## Reference

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
