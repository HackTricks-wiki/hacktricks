# Mythic

{{#include ../banners/hacktricks-training.md}}

## Šta je Mythic?

Mythic je modularni framework otvorenog koda za command and control (C2), namenjen red teamingu i timskoj saradnji. Omogućava operatorima da upravljaju agentima (payloads) i pokreću ih na različitim operativnim sistemima, uključujući Windows, Linux i macOS. Mythic pruža browser UI za zadavanje zadataka većem broju operatora, rukovanje datotekama, upravljanje SOCKS/rpfwd vezama i generisanje payloads.

Za razliku od monolitnih frameworka, sam Mythic repozitorijum **ne** isporučuje tipove payloads niti C2 profile. Agenti, wrapperi i C2 profili obično se instaliraju kao spoljne komponente i mogu se ažurirati nezavisno od Mythic jezgra.

### Instalacija

Da biste instalirali Mythic, pratite uputstva u zvaničnom **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Uobičajeno početno podešavanje iz Mythic direktorijuma izgleda ovako:

```bash
sudo make
sudo ./mythic-cli start
```

Ako je Mythic već pokrenut, obično možete dodati novog agent-a ili profile pomoću komande `./mythic-cli install github ...`, a zatim ponovo pokrenuti Mythic ili direktno pokrenuti novu komponentu.

### Agents

Mythic podržava više agent-a, odnosno **payloads koji obavljaju zadatke na kompromitovanim sistemima**. Svaki agent može da se prilagodi određenim potrebama i može da radi na različitim operativnim sistemima.

Mythic podrazumevano nema instalirane agente. Open-source agenti zajednice nalaze se na [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**matrica funkcionalnosti zajednice**](https://mythicmeta.github.io/overview/agent_matrix.html) korisna je za brzu proveru podržanih operativnih sistema, formata payload-a, wrappers i C2 profila.<sup>[[1]](#references)</sup>

Da biste instalirali agenta iz te organizacije, možete pokrenuti:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Forma `sudo -E` korisna je kada instalirate iz okruženja koje nije root. Nove agente možete dodati prethodnom komandom čak i ako je Mythic već pokrenut.

### C2 Profiles

C2 profili u Mythicu definišu **kako agenti komuniciraju sa Mythic serverom**. Oni određuju protokol komunikacije, metode šifrovanja i druga podešavanja. C2 profile možete kreirati i njima upravljati putem Mythic veb-interfejsa.

Mythic se podrazumevano instalira bez profila, ali neke profile možete preuzeti iz repozitorijuma [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) izvršavanjem:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Trenutno relevantni profili za operatere koje treba imati na umu:

- [`http`](https://github.com/MythicC2Profiles/http): osnovni asinhroni GET/POST saobraćaj.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): fleksibilniji HTTP saobraćaj sa više callback domena, fail-over/round-robin rotacijom, prilagođenim zaglavljima/parametrima upita i transformacijama poruka (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) smeštenim u cookies, zaglavlja, parametre upita ili telo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): oblikovanje HTTP poruka pomoću JSON/TOML konfiguracije, kada je statički `http` profil prepoznatljiv.

### Trenutne napomene o platformi

- Mnogi javni agenti i profili sada se instaliraju pomoću unapred izgrađenih udaljenih kontejnerskih image-a.
  Ako napravite fork komponente ili je lokalno zakrpite, a Mythic i dalje koristi staro
  ponašanje, proverite generisane `.env` unose za `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; podešavanje
  `*_USE_BUILD_CONTEXT="true"` obično navodi Mythic da ponovo izgradi komponentu
  iz vašeg lokalnog Docker konteksta umesto da neprimetno ponovo koristi udaljeni image.
- Browser skripte su jedna od najkorisnijih funkcija Mythic-a za operatere: mogu
  da pretvore sirovi izlaz komandi u tabele, prikazivače snimaka ekrana, linkove za
  preuzimanje, linkove za pretragu i dugmad koja direktno iz UI-ja pokreću naredne
  taskove. Aktuelne verzije Mythic-a omogućavaju svakom operateru da zadrži svoje
  skripte, da ih uključi ili isključi globalno ili za pojedinačni task, a najbolje
  rezultate daju kada agenti vraćaju strukturirani JSON umesto običnog teksta.
  Ovo je naročito korisno za ponavljajuće `ls`, `ps`, trijažne i file-browser tokove rada.<sup>[[4]](#references)[[6]](#references)</sup>
- Novije verzije Mythic-a podržavaju i interaktivno tasking i Push C2 obrasce,
  koji smanjuju potrebu za polling-om pomoću `sleep 0` tokom operacija koje se
  intenzivno oslanjaju na PTY/SOCKS/rpfwd. Kada ih agent/profil podržava, to
  obično pravi manje opterećenje nego neprestano slanje zahteva serveru samo da bi
  interaktivni kanal ostao upotrebljiv.<sup>[[3]](#references)</sup>
- Aktuelni Mythic builder-i iz ere 3.4 uzimaju više konteksta u obzir nego što
  stariji tekstovi sugerišu: parametri za build sada mogu da se grupišu ili sakriju
  na osnovu izabranog OS-a ili drugih opcija za build, tipovi payload-a mogu da
  navedu da li podržavaju više C2 profila ili više instanci istog C2 u jednom
  build-u, a odstupanja C2 parametara omogućavaju agentu da sakrije polja koja
  zapravo ne implementira. Ovo je važno pri prelasku između `http`, `httpx`, `smb`,
  `tcp` i `websocket`, jer bezbedan/važeći skup opcija za build više nije
  nepromenljiv statički obrazac.<sup>[[5]](#references)</sup>
- Ako pravite prilagođeni par agent/profil i ne želite Mythic-ov JSON format
  poruka ili podrazumevanu kriptografiju na mreži, koristite
  `translation_container`: Mythic uklanja UUID, prosleđuje šifrovani blob i
  ključni materijal prevodiocu preko gRPC-a i očekuje da dobije bajtove u
  izvornom formatu agenta. Ovo je čist način za podršku binarnim protokolima,
  prilagođenom uokviravanju ili šifrovanju na strani agenta, bez prepravljanja
  celog servera.
- Imajte na umu da linked/P2P callback-ovi ne prosleđuju samo tasking. Mythic-ov
  tok `get_tasking` može da prenosi i odgovore, kao i podatke `delegates`,
  `socks`, `rpfwd` i `interactive`. U praksi, jedan egress callback može da opslužuje
  unutrašnje callback-ove i pivot kanale u istoj polling petlji; ako podređeni
  agenti obavljaju sopstvene periodične check-in-e, `get_delegate_tasks=false`
  sprečava nadređeni agent da slučajno preuzme poslove na čekanju za unutrašnji callback.

## Wrapper payloads

Wrapper payloads omogućavaju da zadržite istu logiku agenta, a da promenite
reprezentaciju na disku koja se isporučuje ili čuva.

- `service_wrapper`: pretvara drugi payload u Windows service izvršnu datoteku, što je korisno kada putanja izvršavanja zahteva ispravnu service binarnu datoteku.
- `scarecrow_wrapper`: obavija kompatibilni shellcode ScareCrow loader-om kako bi generisao izlaze koje podržava loader, kao što su EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo je Windows agent napisan u C# koristeći 4.0 .NET Framework, namenjen
korišćenju u edukativnim ponudama kompanije SpecterOps.<sup>[[2]](#references)</sup>

Instalirajte ga pomoću:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Napomene o aktuelnoj build konfiguraciji/profilima

- Apollo trenutno može da emituje `WinExe`, `Shellcode`, `Service` i `Source` payload-e.
- Profili za Apollo koji se najčešće koriste su `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` je obično fleksibilnija opcija kada su vam potrebni rotacija domena, podrška za proxy, prilagođeno pozicioniranje poruka i transformacije poruka, umesto starijeg statičkog profila `http`.
- Apollo je jedan od community agenata sa najviše funkcionalnosti i trenutno izlaže integracije na Mythic strani, kao što su skripte za browser, prikazi browsera za fajlove/procese, snimci ekrana, keylogging, SOCKS, rpfwd, Push C2 i P2P rutiranje.
- Apollo podržava wrapper payload-e kao što su `service_wrapper` i `scarecrow_wrapper`.
- Apollo podržava dinamičko učitavanje komandi, pa početni payload može da ostane mali, a dodatne komande ili Forge module možete učitati kasnije, umesto da svaku post-ex capability kompajlirate u prvu build konfiguraciju.
- Prilikom generisanja shellcode izlaza, trenutni Apollo builder izlaže i izbore Donut formata (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) i Donut ponašanja za zaobilaženje (`None`, `Abort on fail`, `Continue on fail`). Ovo je korisno ako je krajnji cilj da shellcode ponovo upakujete pomoću `service_wrapper`, `scarecrow_wrapper` ili prilagođenog loader-a.
- `register_file` i `register_assembly` su staging primitive za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. U trenutnim Apollo build-ovima, ti staged artefakti se keširaju na klijentskoj strani kao DPAPI-zaštićeni AES256 blob-ovi.
- Rezultati komandi `ls` i `ps` posebno dobro rade sa Mythic skriptama za browser i browserom za fajlove/procese, što primetno ubrzava trijažu operatora u zajedničkim operacijama.
- Apollo fork-and-run poslovi nasleđuju podešavanja sacrificial process-a iz
  `spawnto_x86` / `spawnto_x64`, izbor parent procesa iz `ppid`, a zatim
  koriste trenutno izabranu injection primitive. U praksi to znači da vaša
  OPSEC podešavanja za jednu komandu često istovremeno utiču na `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i `spawn`.
- Trenutno dokumentovani Apollo injection backends obuhvataju `CreateRemoteThread`,
  `QueueUserAPC` (early-bird stil) i `NtCreateThreadEx` preko syscalls. Koristite
  `get_injection_techniques` pre bučnih post-exploitation aktivnosti i
  `set_injection_technique` ako treba da pređete sa primitive koja nije
  kompatibilna sa metom ili komandom koju želite da pokrenete.
- `blockdlls` utiče samo na sacrificial procese koji se kreiraju za post-exploitation
  poslove. U kombinaciji sa manje sumnjivim ciljem `spawnto_x64` od podrazumevanog
  golog `rundll32.exe`, ovo je jedna od najjednostavnijih izmena na Apollo strani koju možete da napravite
  pre pokretanja tasking-a koji se intenzivno oslanja na assembly/PowerShell.

### Pipeline za build .NET agenta koji uvažava detekciju

Apollo fork koji uvažava detekciju treba posmatrati kao **problem celog build sistema**, a ne kao završni korak `obfuscate.exe`. Ova studija slučaja dopunjuje opštu [metodologiju za AV evasion](av-bypass.md) i [alate za .NET inspekciju](../reversing/reversing-tools-basic-methods/README.md): izmene wire identifikatora, IL metapodataka, pakovanja zavisnosti, reflection-a i dinamički kompajliranih task-ova čine jednu granicu kompatibilnosti.<sup>[[8]](#references)</sup>

#### Mutacija protokola uz uvažavanje YARA pravila

Pre izmene koda, proverite javna pravila za fajlove/memoriju. Na primer, Elastic-ovo pravilo `Multi_Trojan_Mythic_4beb7e17` poklapa se kada je prisutno bilo kojih **7 od 11** Mythic JSON/action nizova, uključujući `task_id`, `post_response`, `c2_profile`, `get_tasking` i `get_delegate_tasks`. Preimenovanjem dovoljnog broja polja možete zaobići taj prag, ali to su vrednosti protokola, a ne kozmetički simboli: agent i odgovarajuća server/profile implementacija moraju da se menjaju zajedno.<sup>[[7]](#references)[[8]](#references)</sup>

Ovim se uklanja samo jedan skup statičkih karakteristika. Učestalost check-in-a, oblik poruke, tok zadataka/odgovora i rekonstrukcija stringova tokom izvršavanja i dalje mogu biti indikatori ponašanja ili memorije; zato proverite i izgrađeni artefakt i aktivirani callback, umesto da čist rezultat skeniranja stringova smatrate uspehom.<sup>[[8]](#references)</sup>

#### Spajanje pre primene globalnih transformacija

Ugrađivanje resursa pomoću alata kao što je Costura ostavlja prateće assembly-je kao kompresovane resurse. Obfuscator koji obrađuje samo spoljašnji modul zato propušta njihove nazive tipova i metapodatke; zasebna obfuscation svakog DLL-a može, s druge strane, da dodeli nekompatibilna imena ugovorima između assembly-ja. Najpre spojite build izlaze na IL nivou (na primer pomoću [ILRepack](https://github.com/gluck/il-repack)), a zatim primenite jednu mapu preimenovanja na dobijeni modul.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Prilagođeni pass može da koristi [dnlib](https://github.com/0xd4d/dnlib) za transformacije upravljanog IL-a/metapodataka, a [AsmResolver](https://github.com/Washi1337/AsmResolver) za naknadno patchovanje PE-a/resursa. U studiji slučaja, podobne `ldstr` instrukcije zamenjene su pozivima koji koriste celobrojne tokene i decryptor, a oslanjaju se na novi 16-bajtni rolling-XOR ključ. Simboli i prostori imena mapirani su na uverljive nazive u poslovnom stilu umesto na kratke sekvencijalne identifikatore. Drugi pass-ovi uklonili su odabrane atribute kompajlera/debuggera, očistili reference na merger/embedding, preimenovali resurse i patchovali informacije o verziji. Za svaku nezavisnu kompilaciju ponovo generišite nazive, dead code i materijal za šifrovanje: promena šifroteksta uklanja stabilne bajtove, ali stabilan decryptor ili prepoznatljiv obrazac transformacije sam po sebi predstavlja potpis.<sup>[[8]](#references)</sup>

#### Održavajte dinamičke zadatke usklađenim sa payload-om

Apollo može da kompajlira izvorni kod zadatka na serveru, pošalje bajtove DLL-a i učita ih pomoću `Assembly.Load()`. Kada se preimenuju javni tipovi osnovnog agenta, kasniji zadaci kompajlirani prema originalnom API-ju više se ne razrešavaju. Tretirajte izvezenu mapu preimenovanja kao ABI artefakt specifičan za payload:<sup>[[8]](#references)</sup>

1. Povežite mapu i kontekst tipova sa tačnim identifikatorom payload-a/kompilacije.
2. Za svaku kompilaciju zadatka preuzmite tu mapu i prepišite privremeno stablo izvornog koda.
3. Prepišite samo razrešene reference na prostore imena, tipove, ugnježdene/generičke tipove, polja i svojstva, a zatim kompajlirajte prema spojenom assembly-ju sa obfuskovanim imenima.
4. Odbijte isporuku zadatka ako mapa nedostaje ili se ne podudara i nakon kompilacije pokrenite test inicijalizacije.

Slepa globalna zamena nije bezbedna jer se identifikator može pojaviti i u stringu, lokalnoj deklaraciji, pristupu članu, tipu framework-a ili nepovezanom prostoru imena. Ako zadržite prepisivač zasnovan na tekstu/regex-u, izričito zaštitite te kontekste i testirajte regresije kad god se promene šema mape ili pass za preimenovanje.<sup>[[8]](#references)</sup>

#### Učinite ugovore refleksije nezavisnim od prostora imena

Kod za pronalaženje koji proverava `t.FullName.StartsWith("Tasks.")` čini prostor imena ključnim i otkazuje nakon njegovog preslikavanja. Umesto toga, tipove pronalazite na osnovu stabilne veze između njih, a nazive klasa komandi sačuvajte ako se za dispatch i dalje koristi `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Održavajte eksplicitnu listu dozvoljenih naziva vidljivih putem reflection-a, polja serializer-a, ulaznih tačaka i API-ja između sklopova koji se ne smeju preimenovati. Na kraju dekompajlirajte rezultat pomoću ILSpy/dnSpy, skenirajte prikaz u datotekama i memoriji i isprobajte svaku putanju komandi/loader-a u EDR labu; uspešno pokretanje build-a ne znači da zadaci nisu pokvareni preimenovanjem ili da se ponašanje neće otkriti tek tokom izvršavanja.<sup>[[8]](#references)</sup>

Ovaj agent ima mnogo komandi, zbog čega je veoma sličan Cobalt Strike-ovom Beacon-u, uz neke dodatne mogućnosti. Između ostalog, podržava:

### Uobičajene radnje

- `cat`: Prikaži sadržaj datoteke
- `cd`: Promeni trenutni radni direktorijum
- `cp`: Kopiraj datoteku sa jedne lokacije na drugu
- `ls`: Prikaži datoteke i direktorijume u trenutnom direktorijumu ili na navedenoj putanji
- `ifconfig`: Dohvati mrežne adaptere i interfejse
- `netstat`: Dohvati informacije o TCP i UDP vezama
- `pwd`: Prikaži trenutni radni direktorijum
- `ps`: Prikaži pokrenute procese na ciljnom sistemu (uz dodatne informacije)
- `jobs`: Prikaži sve pokrenute poslove povezane sa dugotrajnim zadacima
- `download`: Preuzmi datoteku sa ciljnog sistema na lokalni računar
- `upload`: Otpremi datoteku sa lokalnog računara na ciljni sistem
- `reg_query`: Upit za ključeve i vrednosti registra na ciljnom sistemu
- `reg_write_value`: Upiši novu vrednost u navedeni ključ registra
- `sleep`: Promeni interval spavanja agenta, koji određuje koliko često se javlja Mythic serveru
- I mnoge druge; upotrebite `help` da biste videli celu listu dostupnih komandi.

### Eskalacija privilegija

- `getprivs`: Omogući što više privilegija na tokenu trenutne niti
- `getsystem`: Otvori handle ka winlogon-u i dupliciraj token, čime se efektivno podižu privilegije na nivo SYSTEM
- `make_token`: Kreiraj novu logon sesiju i primeni je na agenta, omogućavajući impersonation drugog korisnika
- `steal_token`: Ukradi primarni token iz drugog procesa, čime agent može da impersonate korisnika tog procesa
- `pth`: Pass-the-Hash napad, koji omogućava agentu da se autentifikuje kao korisnik pomoću njegovog NTLM hash-a, bez potrebe za lozinkom u otvorenom tekstu
- `mimikatz`: Pokreni Mimikatz komande za izvlačenje credentials, hash-eva i drugih osetljivih informacija iz memorije ili SAM baze podataka
- `rev2self`: Vrati token agenta na njegov primarni token, čime se privilegije efektivno vraćaju na prvobitni nivo
- `ppid`: Promeni roditeljski proces za post-exploitation poslove navođenjem novog ID-ja roditeljskog procesa, što omogućava bolju kontrolu nad kontekstom izvršavanja poslova
- `printspoofer`: Izvrši PrintSpoofer komande za zaobilaženje bezbednosnih mera print spooler-a, što omogućava eskalaciju privilegija ili izvršavanje koda
- `dcsync`: Sinhronizuj korisnikove Kerberos ključeve na lokalni računar, što omogućava offline razbijanje lozinke ili dalje napade
- `ticket_cache_add`: Dodaj Kerberos ticket u trenutnu logon sesiju ili navedenu sesiju, što omogućava ponovnu upotrebu ticket-a ili impersonation

### Izvršavanje procesa

- `assembly_inject`: Omogućava ubacivanje .NET assembly loader-a u udaljeni proces
- `blockdlls`: Blokiraj učitavanje DLL-ova koji nisu potpisani od strane Microsoft-a u post-exploitation poslovima
- `execute_assembly`: Izvrši .NET assembly u kontekstu agenta
- `execute_coff`: Izvrši COFF datoteku u memoriji, što omogućava izvršavanje kompajliranog koda u memoriji
- `execute_pe`: Izvrši unmanaged executable (PE)
- `keylog_inject`: Ubaci keylogger u drugi proces i prosleđuj pritiske tastera u Mythic-ov prikaz keylog-a
- `screenshot` / `screenshot_inject`: Snimi trenutnu radnu površinu direktno ili
  ubacivanjem screenshot assembly-ja u ciljni proces/sesiju
- `get_injection_techniques`: Prikaži dostupne tehnike injection-a i trenutno izabranu tehniku
- `inline_assembly`: Izvrši .NET assembly u privremenom AppDomain-u, čime se omogućava privremeno izvršavanje koda bez uticaja na glavni proces agenta
- `register_assembly`: Registruj .NET assembly za kasnije izvršavanje
- `register_file`: Registruj datoteku u kešu agenta za kasnije `execute_*` ili PowerShell zadatke
- `run`: Izvrši binarnu datoteku na ciljnom sistemu, koristeći sistemsku PATH promenljivu za pronalaženje izvršne datoteke
- `set_injection_technique`: Promeni injection primitiv koji koriste post-exploitation poslovi
- `shinject`: Ubaci shellcode u udaljeni proces, što omogućava izvršavanje proizvoljnog koda u memoriji
- `inject`: Ubaci shellcode agenta u udaljeni proces, što omogućava izvršavanje koda agenta u memoriji
- `spawn`: Pokreni novu sesiju agenta u navedenoj izvršnoj datoteci, što omogućava izvršavanje shellcode-a u novom procesu
- `spawnto_x64` i `spawnto_x86`: Promeni podrazumevanu binarnu datoteku koju koriste post-exploitation poslovi na navedenu putanju, umesto korišćenja `rundll32.exe` bez parametara, što je veoma upadljivo.

### Mythic Forge

Ovo omogućava **učitavanje COFF/BOF** datoteka iz Mythic Forge-a, repozitorijuma unapred kompajliranih payload-ova i alata koji se mogu izvršiti na ciljnom sistemu. Pomoću svih komandi koje se mogu učitati biće moguće obavljati uobičajene radnje njihovim izvršavanjem kao BOF-ova u procesu trenutnog agenta (obično uz bolji OPSEC nego pri pokretanju zasebnog procesa).

Počnite sa njihovom instalacijom ovde:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Zatim upotrebite `forge_collections` da prikažete COFF/BOF module iz Mythic Forge-a, kako biste mogli da ih izaberete i učitate u memoriju agenta radi izvršavanja. Podrazumevano se u Apollo dodaju sledeće 2 kolekcije:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Kada se učita modul, pojaviće se na listi kao dodatna komanda, na primer `forge_bof_sa-whoami` ili `forge_bof_sa-netuser`.

Za BOF-ove imajte na umu da Forge **ne** prosleđuje Apollo-u samo jedan ravan niz argumenata. Mapira BOF parametre u Mythic-ov format tipiziranog niza, a zatim ih prosleđuje kroz Apollo-ov tok `execute_coff`. Ako se BOF učitan iz Forge-a ponaša neočekivano, proverite očekivane tipove BOF argumenata i ulaznu tačku, a ne samo unetu komandnu liniju. Takođe imajte na umu da je noviji BOF loader u Apollo-u promenio rukovanje argumentima u odnosu na mnogo starije verzije iz perioda 2.3.1, pa zastareli BOF-ovi ili stare kolekcije mogu da ne rade isključivo zbog promenjenih očekivanja pri maršalovanju.

### Izvršavanje PowerShell-a i skripti

- `powershell_import`: Uvozi novu PowerShell skriptu (.ps1) u keš agenta za kasnije izvršavanje
- `powershell`: Izvršava PowerShell komandu u kontekstu agenta, što omogućava napredno skriptovanje i automatizaciju
- `powerpick`: Umeće PowerShell loader assembly u žrtveni proces i izvršava PowerShell komandu (bez PowerShell logovanja).
- `psinject`: Izvršava PowerShell u navedenom procesu, što omogućava ciljano izvršavanje skripti u kontekstu drugog procesa
- `shell`: Izvršava shell komandu u kontekstu agenta, slično pokretanju komande u cmd.exe

### Lateralno kretanje

- `jump_psexec`: Koristi PsExec tehniku za lateralno kretanje na novi host tako što prvo kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `jump_wmi`: Koristi WMI tehniku za lateralno kretanje na novi host tako što prvo kopira izvršnu datoteku Apollo agenta (apollo.exe), a zatim je izvršava.
- `link` i `unlink`: Uspostavljaju i prekidaju P2P veze (na primer, preko SMB/TCP) između callback-ova.
- `wmiexecute`: Izvršava komandu na lokalnom ili navedenom udaljenom sistemu pomoću WMI-ja, uz opcione akreditive za impersonaciju.
- `net_dclist`: Dobavlja listu kontrolera domena za navedeni domen, što je korisno za pronalaženje potencijalnih ciljeva za lateralno kretanje.
- `net_localgroup`: Prikazuje lokalne grupe na navedenom računaru; ako računar nije naveden, podrazumevano se koristi localhost.
- `net_localgroup_member`: Dobavlja članstvo u lokalnoj grupi za navedenu grupu na lokalnom ili udaljenom računaru, što omogućava nabrajanje korisnika u određenim grupama.
- `net_shares`: Prikazuje udaljene deljene resurse i njihovu dostupnost na navedenom računaru, što je korisno za pronalaženje potencijalnih ciljeva za lateralno kretanje.
- `socks`: Omogućava SOCKS 5 kompatibilan proxy na ciljnoj mreži, što omogućava tunelovanje saobraćaja kroz kompromitovani host. Kompatibilan je sa alatima kao što je proxychains.
- `rpfwd`: Počinje da osluškuje na navedenom portu na ciljnom hostu i prosleđuje saobraćaj kroz Mythic do udaljene IP adrese i porta, omogućavajući udaljeni pristup uslugama na ciljnoj mreži.
- `listpipes`: Prikazuje sve imenovane cevi na lokalnom sistemu, što može biti korisno za lateralno kretanje ili eskalaciju privilegija putem interakcije sa IPC mehanizmima.

Za WMI primitive nižeg nivoa koje se koriste ispod `jump_wmi` ili `wmiexecute`, pogledajte [WmiExec](lateral-movement/wmiexec.md). Za šire obrasce pivotiranja pogledajte [Tunelovanje i prosleđivanje portova](../generic-hacking/tunneling-and-port-forwarding.md).

### Razne komande
- `help`: Prikazuje detaljne informacije o određenim komandama ili opšte informacije o svim dostupnim komandama u agentu.
- `clear`: Označava zadatke kao „očišćene“ tako da ih agenti ne mogu preuzeti. Možete navesti `all` da biste očistili sve zadatke ili `task Num` da biste očistili određeni zadatak.  


## [Poseidon agent](https://github.com/MythicAgents/poseidon)

Poseidon je Golang agent koji se kompajlira u izvršne datoteke za **Linux i macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Napomene o trenutnoj verziji/profilu

- Trenutne Poseidon verzije ciljaju Linux i macOS na `x86_64` i `arm64`.
- Podržani izlazni formati obuhvataju nativne izvršne datoteke i izlaze u stilu deljenih biblioteka, kao što su `dylib` i `so`.
- Poseidon podržava `http`, `websocket`, `tcp` i `dynamichttp`, a trenutni builder-i nude podešavanja za više egress veza, kao što su `egress_order` i pragovi za failover.
- Trenutni metapodaci o mogućnostima Poseidona navode i browser scripts, integraciju file/process browser-a, interaktivni tasking, keylogging, snimke ekrana, Push C2, SOCKS, rpfwd i P2P, tako da može da služi kao pravi Linux/macOS pivot čvor, a ne samo kao jednostavna remote shell sesija.
- Vredi proveriti opcije pri izgradnji kao što su `proxy_bypass` i `garble` kada su vam potrebni ili čistije mrežno ponašanje ili dodatna obfuskacija Go binarnih datoteka.
- `pty` je jedna od najkorisnijih novijih komandi za kvalitet rada u Linux/macOS operacijama, jer otvara interaktivni PTY i može da izloži Mythic port za potpuniju interakciju sa terminalom, bez pribegavanja starijem zaobilaznom rešenju `sleep 0` + SOCKS.
- Trenutna Poseidon dokumentacija posebno je zanimljiva za tradecraft usmeren na macOS: `jxa` izvršava JavaScript for Automation u memoriji, `screencapture` snima radnu površinu prijavljenog korisnika, `clipboard_monitor` prosleđuje promene u pasteboard-u, `execute_library` učitava lokalni dylib i poziva njegovu funkciju, a `libinject` primorava udaljeni proces da učita dylib sa diska.
- Kod dugotrajnih poslova imajte na umu da Poseidon izvršava post-exploitation rad u gorutinama/nitima koji sarađuju, pa ih nije moguće nasilno prekinuti. Dokumentacija takođe izričito navodi da trenutno nema ugrađenu obfuskaciju agenta, pa su tradecraft na nivou izgradnje/profila važniji nego kod komercijalnih implantata sa snažnom obfuskacijom.

Za macOS-specifični tradecraft u Mythic operacijama, zloupotrebu JAMF-a ili ideje za MDM-as-C2, pogledajte [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Kada se koristi na Linux-u ili macOS-u, nudi neke zanimljive komande:

### Uobičajene radnje

- `cat`: Prikaži sadržaj datoteke
- `cd`: Promeni trenutni radni direktorijum
- `chmod`: Promeni dozvole datoteke
- `config`: Prikaži trenutnu konfiguraciju i informacije o hostu
- `cp`: Kopiraj datoteku sa jedne lokacije na drugu
- `curl`: Izvrši jedan web zahtev uz opcionalna zaglavlja i metod
- `upload`: Otpremi datoteku na cilj
- `download`: Preuzmi datoteku sa ciljnog sistema na lokalnu mašinu
- I mnoge druge

### Pretraga osetljivih informacija

- `triagedirectory`: Pronađi zanimljive datoteke u direktorijumu na hostu, kao što su osetljive datoteke ili akreditivi.
- `getenv`: Prikaži sve trenutne promenljive okruženja.

### macOS-specifični tradecraft

- `jxa`: Izvrši JavaScript for Automation u memoriji preko `OSAScript`, što je korisno za nativni macOS post-exploitation bez ostavljanja zasebnih skriptnih datoteka.
- `clipboard_monitor`: Proverava pasteboard i prosleđuje promene Mythic-u, što je korisno za krađu akreditiva/tokena koja se oslanja na copy/paste.
- `screencapture`: Napravi snimak korisnikove radne površine na macOS-u.
- `execute_library`: Učitaj dylib sa diska i pozovi određenu izvezenu funkciju.
- `libinject`: Ubaci shellcode stub koji primorava drugi macOS proces da učita dylib sa diska.
- `persist_launchd`: Kreiraj LaunchAgent / LaunchDaemon persistence direktno iz agenta.

### Lateralno kretanje

- `ssh`: Poveži se na host koristeći određene akreditive i otvori PTY bez pokretanja ssh procesa.
- `sshauth`: Poveži se na navedeni host ili hostove koristeći određene akreditive. Ovo možete da koristite i za izvršavanje određene komande na udaljenim hostovima preko SSH-a ili za prenos datoteka pomoću SCP-a.
- `link_tcp`: Poveži se sa drugim agentom preko TCP-a, što omogućava direktnu komunikaciju između agenata.
- `link_webshell`: Poveži se sa agentom koristeći webshell P2P profil, što omogućava udaljeni pristup web interfejsu agenta.
- `rpfwd`: Pokreni ili zaustavi Reverse Port Forward, omogućavajući udaljeni pristup servisima na ciljnoj mreži.
- `socks`: Pokreni ili zaustavi SOCKS5 proxy na ciljnoj mreži, omogućavajući tuneliranje saobraćaja kroz kompromitovani host. Kompatibilno je sa alatima kao što je proxychains.
- `portscan`: Skeniraj host ili hostove u potrazi za otvorenim portovima, što je korisno za pronalaženje potencijalnih ciljeva za lateralno kretanje ili dalje napade.

### Izvršavanje procesa

- `shell`: Izvrši jednu shell komandu preko /bin/sh, što omogućava direktno izvršavanje komandi na ciljnom sistemu.
- `run`: Izvrši komandu sa diska uz argumente, što omogućava izvršavanje binarnih datoteka ili skripti na ciljnom sistemu.
- `pty`: Otvori interaktivni PTY, što omogućava direktnu interakciju sa shell-om na ciljnom sistemu.

## References

- [1] [Matrica funkcija Mythic Community agenta](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2: novosti — interaktivni tasking, Push C2 i dinamički preglednik datoteka](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts — Mythic dokumentacija](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 ažuriranja](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Unapređenje Red Team operacija uz skrivene dragulje Mythic-a: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: YARA pravila za Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Od fork-a do framework-a: šta nas je modifikovanje Apollo-a naučilo o invaziji agenata](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
