# Mythic

## Šta je Mythic?

Mythic je open-source, modularni komandni i kontrolni (C2) okvir dizajniran za red teaming. Omogućava bezbednosnim profesionalcima da upravljaju i implementiraju različite agente (payloads) na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža korisnički prijateljski web interfejs za upravljanje agentima, izvršavanje komandi i prikupljanje rezultata, što ga čini moćnim alatom za simulaciju stvarnih napada u kontrolisanom okruženju.

### Instalacija

Da biste instalirali Mythic, pratite uputstva na zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**.

### Agenti

Mythic podržava više agenata, koji su **payloads koji obavljaju zadatke na kompromitovanim sistemima**. Svaki agent može biti prilagođen specifičnim potrebama i može raditi na različitim operativnim sistemima.

Podrazumevano, Mythic nema instalirane agente. Međutim, nudi neke open source agente na [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Da biste instalirali agenta iz tog repozitorijuma, jednostavno pokrenite:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Možete dodati nove agente prethodnom komandom čak i ako Mythic već radi.

### C2 Profili

C2 profili u Mythic definišu **kako agenti komuniciraju sa Mythic serverom**. Oni specificiraju komunikacijski protokol, metode enkripcije i druge postavke. Možete kreirati i upravljati C2 profilima putem Mythic web interfejsa.

Podrazumevano, Mythic se instalira bez profila, međutim, moguće je preuzeti neke profile iz repozitorijuma [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) pokretanjem:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C# koristeći 4.0 .NET Framework, dizajniran da se koristi u obukama SpecterOps. 

Instalirajte ga sa:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Ovaj agent ima mnogo komandi koje ga čine veoma sličnim Cobalt Strike-ovom Beacon-u sa nekim dodatnim funkcijama. Među njima, podržava:

### Uobičajene akcije

- `cat`: Ispisuje sadržaj datoteke
- `cd`: Menja trenutni radni direktorijum
- `cp`: Kopira datoteku sa jednog mesta na drugo
- `ls`: Prikazuje datoteke i direktorijume u trenutnom direktorijumu ili navedenoj putanji
- `pwd`: Ispisuje trenutni radni direktorijum
- `ps`: Prikazuje aktivne procese na ciljanom sistemu (sa dodatnim informacijama)
- `download`: Preuzima datoteku sa ciljanog sistema na lokalnu mašinu
- `upload`: Učitava datoteku sa lokalne mašine na ciljani sistem
- `reg_query`: Upit za ključeve i vrednosti registra na ciljanom sistemu
- `reg_write_value`: Upisuje novu vrednost u određeni ključ registra
- `sleep`: Menja interval spavanja agenta, koji određuje koliko često se javlja Mythic serveru
- I mnoge druge, koristite `help` da vidite punu listu dostupnih komandi.

### Eskalacija privilegija

- `getprivs`: Omogućava što više privilegija na trenutnom tokenu niti
- `getsystem`: Otvara handle za winlogon i duplicira token, efikasno eskalirajući privilegije na nivo SISTEMA
- `make_token`: Kreira novu sesiju prijavljivanja i primenjuje je na agenta, omogućavajući impersonaciju drugog korisnika
- `steal_token`: Krade primarni token iz drugog procesa, omogućavajući agentu da impersonira korisnika tog procesa
- `pth`: Pass-the-Hash napad, omogućavajući agentu da se autentifikuje kao korisnik koristeći njihov NTLM hash bez potrebe za plaintext lozinkom
- `mimikatz`: Pokreće Mimikatz komande za ekstrakciju kredencijala, hash-eva i drugih osetljivih informacija iz memorije ili SAM baze podataka
- `rev2self`: Vraća agentov token na njegov primarni token, efikasno vraćajući privilegije na originalni nivo
- `ppid`: Menja roditeljski proces za post-exploitation poslove tako što specificira novi ID roditeljskog procesa, omogućavajući bolju kontrolu nad kontekstom izvršenja posla
- `printspoofer`: Izvršava PrintSpoofer komande da zaobiđe sigurnosne mere štampača, omogućavajući eskalaciju privilegija ili izvršenje koda
- `dcsync`: Sinhronizuje Kerberos ključeve korisnika na lokalnu mašinu, omogućavajući offline razbijanje lozinki ili dalja napada
- `ticket_cache_add`: Dodaje Kerberos tiket trenutnoj sesiji prijavljivanja ili određenoj, omogućavajući ponovnu upotrebu tiketa ili impersonaciju

### Izvršenje procesa

- `assembly_inject`: Omogućava injektovanje .NET assembly loader-a u udaljeni proces
- `execute_assembly`: Izvršava .NET assembly u kontekstu agenta
- `execute_coff`: Izvršava COFF datoteku u memoriji, omogućavajući izvršenje kompajliranog koda u memoriji
- `execute_pe`: Izvršava unmanaged izvršnu datoteku (PE)
- `inline_assembly`: Izvršava .NET assembly u jednokratnom AppDomain-u, omogućavajući privremeno izvršenje koda bez uticaja na glavni proces agenta
- `run`: Izvršava binarnu datoteku na ciljanom sistemu, koristeći sistemski PATH da pronađe izvršnu datoteku
- `shinject`: Injektuje shellcode u udaljeni proces, omogućavajući izvršenje proizvoljnog koda u memoriji
- `inject`: Injektuje agentov shellcode u udaljeni proces, omogućavajući izvršenje agentovog koda u memoriji
- `spawn`: Pokreće novu sesiju agenta u specificiranoj izvršnoj datoteci, omogućavajući izvršenje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Menja podrazumevanu binarnu datoteku korišćenu u post-exploitation poslovima na specificiranu putanju umesto korišćenja `rundll32.exe` bez parametara, što je veoma bučno.

### Mithic Forge

Ovo omogućava **učitavanje COFF/BOF** datoteka iz Mythic Forge-a, što je repozitorijum unapred kompajliranih payload-a i alata koji se mogu izvršiti na ciljanom sistemu. Sa svim komandom koje se mogu učitati, biće moguće izvršiti uobičajene akcije izvršavajući ih u trenutnom procesu agenta kao BOF-ove (obično više stealth). 

Počnite sa instalacijom:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Zatim, koristite `forge_collections` da prikažete COFF/BOF module iz Mythic Forge kako biste mogli da ih odaberete i učitate u memoriju agenta za izvršenje. Podrazumevano, sledeće 2 kolekcije su dodate u Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nakon što se jedan modul učita, pojaviće se na listi kao druga komanda poput `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

### Powershell & izvršenje skripti

- `powershell_import`: Uvozi novu PowerShell skriptu (.ps1) u keš agenta za kasnije izvršenje
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, omogućavajući napredno skriptovanje i automatizaciju
- `powerpick`: Injektuje PowerShell loader assembly u žrtvovani proces i izvršava PowerShell komandu (bez powershell logovanja).
- `psinject`: Izvršava PowerShell u određenom procesu, omogućavajući ciljno izvršenje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično kao pokretanje komande u cmd.exe

### Lateralno kretanje

- `jump_psexec`: Koristi PsExec tehniku za lateralno kretanje ka novom hostu tako što prvo kopira izvršni fajl Apollo agenta (apollo.exe) i izvršava ga.
- `jump_wmi`: Koristi WMI tehniku za lateralno kretanje ka novom hostu tako što prvo kopira izvršni fajl Apollo agenta (apollo.exe) i izvršava ga.
- `wmiexecute`: Izvršava komandu na lokalnom ili određenom udaljenom sistemu koristeći WMI, sa opcionim kredencijalima za impersonaciju.
- `net_dclist`: Preuzima listu kontrolera domena za određeni domen, korisno za identifikaciju potencijalnih ciljeva za lateralno kretanje.
- `net_localgroup`: Prikazuje lokalne grupe na određenom računaru, podrazumevano na localhost ako nije specificiran računar.
- `net_localgroup_member`: Preuzima članstvo lokalne grupe za određenu grupu na lokalnom ili udaljenom računaru, omogućavajući enumeraciju korisnika u specifičnim grupama.
- `net_shares`: Prikazuje udaljene deljene resurse i njihovu dostupnost na određenom računaru, korisno za identifikaciju potencijalnih ciljeva za lateralno kretanje.
- `socks`: Omogućava SOCKS 5 kompatibilan proxy na ciljanom mrežnom okruženju, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno sa alatima poput proxychains.
- `rpfwd`: Počinje da sluša na određenom portu na ciljanom hostu i prosleđuje saobraćaj kroz Mythic na udaljenu IP adresu i port, omogućavajući daljinski pristup uslugama na ciljanom mrežnom okruženju.
- `listpipes`: Prikazuje sve imenovane cevi na lokalnom sistemu, što može biti korisno za lateralno kretanje ili eskalaciju privilegija interakcijom sa IPC mehanizmima.

### Razno
- `help`: Prikazuje detaljne informacije o specifičnim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Označava zadatke kao 'obrisane' tako da ih agenti ne mogu preuzeti. Možete specificirati `all` da obrišete sve zadatke ili `task Num` da obrišete određeni zadatak.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon je Golang agent koji se kompajlira u **Linux i macOS** izvršne fajlove.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Kada korisnik koristi linux, postoje neki zanimljivi komandi:

### Uobičajene radnje

- `cat`: Ispisuje sadržaj datoteke
- `cd`: Menja trenutni radni direktorijum
- `chmod`: Menja dozvole datoteke
- `config`: Prikazuje trenutne konfiguracije i informacije o hostu
- `cp`: Kopira datoteku sa jednog mesta na drugo
- `curl`: Izvršava jedan web zahtev sa opcionim zaglavljima i metodom
- `upload`: Učitava datoteku na cilj
- `download`: Preuzima datoteku sa ciljnog sistema na lokalnu mašinu
- I još mnogo toga

### Pretraživanje osetljivih informacija

- `triagedirectory`: Pronalazi zanimljive datoteke unutar direktorijuma na hostu, kao što su osetljive datoteke ili akreditivi.
- `getenv`: Dobija sve trenutne promenljive okruženja.

### Lateralno kretanje

- `ssh`: SSH na host koristeći dodeljene akreditive i otvara PTY bez pokretanja ssh.
- `sshauth`: SSH na određeni host(e) koristeći dodeljene akreditive. Takođe možete koristiti ovo za izvršavanje specifične komande na udaljenim hostovima putem SSH ili za SCP datoteke.
- `link_tcp`: Povezuje se sa drugim agentom preko TCP, omogućavajući direktnu komunikaciju između agenata.
- `link_webshell`: Povezuje se sa agentom koristeći webshell P2P profil, omogućavajući daljinski pristup web interfejsu agenta.
- `rpfwd`: Pokreće ili zaustavlja obrnuti port forwarding, omogućavajući daljinski pristup uslugama na ciljnjoj mreži.
- `socks`: Pokreće ili zaustavlja SOCKS5 proxy na ciljnjoj mreži, omogućavajući tunelovanje saobraćaja kroz kompromitovani host. Kompatibilno sa alatima kao što je proxychains.
- `portscan`: Skener host(e) za otvorene portove, korisno za identifikaciju potencijalnih ciljeva za lateralno kretanje ili dalja napada.

### Izvršavanje procesa

- `shell`: Izvršava jednu shell komandu putem /bin/sh, omogućavajući direktno izvršavanje komandi na ciljnim sistemima.
- `run`: Izvršava komandu sa diska sa argumentima, omogućavajući izvršavanje binarnih datoteka ili skripti na ciljnim sistemima.
- `pty`: Otvara interaktivni PTY, omogućavajući direktnu interakciju sa shell-om na ciljnim sistemima.
