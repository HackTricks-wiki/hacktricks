# Mythic

## Wat is Mythic?

Mythic is 'n oopbron, modulaire bevel en beheer (C2) raamwerk ontwerp vir red teaming. Dit stel sekuriteitsprofessionals in staat om verskillende agente (payloads) oor verskillende bedryfstelsels, insluitend Windows, Linux, en macOS, te bestuur en te ontplooi. Mythic bied 'n gebruikersvriendelike webkoppelvlak vir die bestuur van agente, die uitvoering van opdragte, en die insameling van resultate, wat dit 'n kragtige hulpmiddel maak om werklike aanvalle in 'n beheerde omgewing te simuleer.

### Installasie

Om Mythic te installeer, volg die instruksies op die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)**.

### Agente

Mythic ondersteun verskeie agente, wat die **payloads is wat take op die gecompromitteerde stelsels uitvoer**. Elke agent kan aangepas word vir spesifieke behoeftes en kan op verskillende bedryfstelsels loop.

Standaard het Mythic nie enige agente geïnstalleer nie. Dit bied egter 'n paar oopbron agente in [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Om 'n agent van daardie repo te installeer, moet jy net die volgende uitvoer:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
U kan nuwe agente byvoeg met die vorige opdrag selfs al is Mythic reeds aan die gang.

### C2 Profiele

C2 profiele in Mythic definieer **hoe agente met die Mythic bediener kommunikeer**. Hulle spesifiseer die kommunikasieprotokol, versleutelingmetodes, en ander instellings. U kan C2 profiele skep en bestuur deur die Mythic webkoppelvlak.

Standaard word Mythic geïnstalleer sonder profiele, egter, dit is moontlik om 'n paar profiele van die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is 'n Windows-agent geskryf in C# met die 4.0 .NET Framework wat ontwerp is om in SpecterOps opleidingsaanbiedinge gebruik te word.

Installeer dit met:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Hierdie agent het 'n baie opdragte wat dit baie soortgelyk maak aan Cobalt Strike se Beacon met 'n paar ekstra's. Onder hulle ondersteun dit:

### Algemene aksies

- `cat`: Druk die inhoud van 'n lêer
- `cd`: Verander die huidige werksgids
- `cp`: Kopieer 'n lêer van een plek na 'n ander
- `ls`: Lys lêers en gidse in die huidige gids of gespesifiseerde pad
- `pwd`: Druk die huidige werksgids
- `ps`: Lys lopende prosesse op die teikenstelsel (met bygevoegde inligting)
- `download`: Laai 'n lêer van die teikenstelsel na die plaaslike masjien af
- `upload`: Laai 'n lêer van die plaaslike masjien na die teikenstelsel op
- `reg_query`: Vra registriesleutels en waardes op die teikenstelsel
- `reg_write_value`: Skryf 'n nuwe waarde na 'n gespesifiseerde registriesleutel
- `sleep`: Verander die agent se slaapinterval, wat bepaal hoe gereeld dit met die Mythic bediener incheck
- En nog ander, gebruik `help` om die volledige lys van beskikbare opdragte te sien.

### Privilege escalasie

- `getprivs`: Aktiveer soveel privilige as moontlik op die huidige draadtoken
- `getsystem`: Maak 'n handvatsel oop na winlogon en dupliceer die token, wat effektief privilige na die SYSTEM vlak verhoog
- `make_token`: Skep 'n nuwe aanmeldsessie en pas dit toe op die agent, wat die verpersoonliking van 'n ander gebruiker moontlik maak
- `steal_token`: Steel 'n primêre token van 'n ander proses, wat die agent toelaat om daardie proses se gebruiker te verpersoonlik
- `pth`: Pass-the-Hash aanval, wat die agent toelaat om as 'n gebruiker te autentiseer met hul NTLM-hash sonder om die platte wagwoord te benodig
- `mimikatz`: Voer Mimikatz-opdragte uit om akrediteer, hashes en ander sensitiewe inligting uit geheue of die SAM-databasis te onttrek
- `rev2self`: Herstel die agent se token na sy primêre token, wat effektief privilige terug na die oorspronklike vlak laat daal
- `ppid`: Verander die ouer proses vir post-exploitatie take deur 'n nuwe ouer proses-ID te spesifiseer, wat beter beheer oor taakuitvoering konteks toelaat
- `printspoofer`: Voer PrintSpoofer-opdragte uit om druk spooler sekuriteitsmaatreëls te omseil, wat privilige eskalasie of kode-uitvoering moontlik maak
- `dcsync`: Sinchroniseer 'n gebruiker se Kerberos sleutels na die plaaslike masjien, wat offline wagwoordkraking of verdere aanvalle moontlik maak
- `ticket_cache_add`: Voeg 'n Kerberos kaartjie by die huidige aanmeldsessie of 'n gespesifiseerde een, wat kaartjie hergebruik of verpersoonliking moontlik maak

### Proses uitvoering

- `assembly_inject`: Laat toe om 'n .NET assembly loader in 'n afstand proses in te spuit
- `execute_assembly`: Voer 'n .NET assembly uit in die konteks van die agent
- `execute_coff`: Voer 'n COFF-lêer in geheue uit, wat in-geheue uitvoering van gecompileerde kode moontlik maak
- `execute_pe`: Voer 'n onbeheerde uitvoerbare (PE) uit
- `inline_assembly`: Voer 'n .NET assembly uit in 'n weggooibare AppDomain, wat tydelike uitvoering van kode toelaat sonder om die agent se hoofproses te beïnvloed
- `run`: Voer 'n binêre op die teikenstelsel uit, met die stelsel se PATH om die uitvoerbare te vind
- `shinject`: Spuit shellcode in 'n afstand proses, wat in-geheue uitvoering van arbitrêre kode moontlik maak
- `inject`: Spuit agent shellcode in 'n afstand proses, wat in-geheue uitvoering van die agent se kode moontlik maak
- `spawn`: Skep 'n nuwe agent sessie in die gespesifiseerde uitvoerbare, wat die uitvoering van shellcode in 'n nuwe proses moontlik maak
- `spawnto_x64` en `spawnto_x86`: Verander die standaard binêre wat in post-exploitatie take gebruik word na 'n gespesifiseerde pad in plaas van om `rundll32.exe` sonder params te gebruik wat baie geraas maak.

### Mithic Forge

Dit laat toe om **COFF/BOF** lêers van die Mythic Forge te laai, wat 'n repository van vooraf-gecompileerde payloads en gereedskap is wat op die teikenstelsel uitgevoer kan word. Met al die opdragte wat gelaai kan word, sal dit moontlik wees om algemene aksies uit te voer deur hulle in die huidige agent proses as BOFs uit te voer (meer stealth gewoonlik).

Begin om hulle te installeer met:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Dan, gebruik `forge_collections` om die COFF/BOF modules van die Mythic Forge te wys sodat jy dit kan kies en in die agent se geheue kan laai vir uitvoering. Standaard word die volgende 2 versamelings in Apollo bygevoeg:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nadat een module gelaai is, sal dit in die lys verskyn as 'n ander opdrag soos `forge_bof_sa-whoami` of `forge_bof_sa-netuser`.

### Powershell & skrip uitvoering

- `powershell_import`: Importeer 'n nuwe PowerShell skrip (.ps1) in die agent kas vir latere uitvoering
- `powershell`: Voer 'n PowerShell opdrag uit in die konteks van die agent, wat geavanceerde skripting en outomatisering moontlik maak
- `powerpick`: Injekteer 'n PowerShell laaier samestelling in 'n sakrifisiele proses en voer 'n PowerShell opdrag uit (sonder PowerShell logging).
- `psinject`: Voer PowerShell uit in 'n gespesifiseerde proses, wat gerigte uitvoering van skripte in die konteks van 'n ander proses moontlik maak
- `shell`: Voer 'n shell opdrag uit in die konteks van die agent, soortgelyk aan die uitvoering van 'n opdrag in cmd.exe

### Laterale Beweging

- `jump_psexec`: Gebruik die PsExec tegniek om lateraal na 'n nuwe gasheer te beweeg deur eers die Apollo agent uitvoerbare lêer (apollo.exe) oor te kopieer en dit uit te voer.
- `jump_wmi`: Gebruik die WMI tegniek om lateraal na 'n nuwe gasheer te beweeg deur eers die Apollo agent uitvoerbare lêer (apollo.exe) oor te kopieer en dit uit te voer.
- `wmiexecute`: Voer 'n opdrag uit op die plaaslike of gespesifiseerde afstandstelsel met behulp van WMI, met opsionele akrediteer vir impersonasie.
- `net_dclist`: Verkry 'n lys van domeinbeheerder vir die gespesifiseerde domein, nuttig om potensiële teikens vir laterale beweging te identifiseer.
- `net_localgroup`: Lys plaaslike groepe op die gespesifiseerde rekenaar, wat standaard na localhost terugval as geen rekenaar gespesifiseer is nie.
- `net_localgroup_member`: Verkry plaaslike groep lidmaatskap vir 'n gespesifiseerde groep op die plaaslike of afstandrekenaar, wat moontlik maak om gebruikers in spesifieke groepe te tel.
- `net_shares`: Lys afstandlike gedeeltes en hul toeganklikheid op die gespesifiseerde rekenaar, nuttig om potensiële teikens vir laterale beweging te identifiseer.
- `socks`: Stel 'n SOCKS 5-konforme proxy op die teiken netwerk in, wat moontlik maak om verkeer deur die gecompromitteerde gasheer te tonnel. Dit is versoenbaar met gereedskap soos proxychains.
- `rpfwd`: Begin luister op 'n gespesifiseerde poort op die teiken gasheer en stuur verkeer deur Mythic na 'n afstandlike IP en poort, wat afstandlike toegang tot dienste op die teiken netwerk moontlik maak.
- `listpipes`: Lys al die benoemde pype op die plaaslike stelsel, wat nuttig kan wees vir laterale beweging of bevoegdheidstoename deur met IPC meganismes te werk.

### Verskeie Opdragte
- `help`: Vertoon gedetailleerde inligting oor spesifieke opdragte of algemene inligting oor al beskikbare opdragte in die agent.
- `clear`: Merk take as 'gekuis' sodat dit nie deur agente opgetel kan word nie. Jy kan `all` spesifiseer om al die take te kuis of `task Num` om 'n spesifieke taak te kuis.

## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon is 'n Golang agent wat saamgestel word in **Linux en macOS** uitvoerbare lêers.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Wanneer gebruiker oor linux het dit 'n paar interessante opdragte:

### Algemene aksies

- `cat`: Druk die inhoud van 'n lêer
- `cd`: Verander die huidige werksgids
- `chmod`: Verander die regte van 'n lêer
- `config`: Beskou huidige konfigurasie en gasheerinligting
- `cp`: Kopieer 'n lêer van een plek na 'n ander
- `curl`: Voer 'n enkele webversoek uit met opsionele koptekste en metode
- `upload`: Laai 'n lêer op na die teiken
- `download`: Laai 'n lêer af van die teikenstelsel na die plaaslike masjien
- En nog baie meer

### Soek Sensitiewe Inligting

- `triagedirectory`: Vind interessante lêers binne 'n gids op 'n gasheer, soos sensitiewe lêers of akrediteer.
- `getenv`: Kry al die huidige omgewing veranderlikes.

### Beweeg lateraal

- `ssh`: SSH na gasheer met die aangewese akrediteer en open 'n PTY sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde gasheer(s) met die aangewese akrediteer. Jy kan dit ook gebruik om 'n spesifieke opdrag op die afstand gasheer via SSH uit te voer of dit gebruik om lêers te SCP.
- `link_tcp`: Skakel na 'n ander agent oor TCP, wat direkte kommunikasie tussen agente moontlik maak.
- `link_webshell`: Skakel na 'n agent met die webshell P2P-profiel, wat afstandstoegang tot die agent se webkoppelvlak moontlik maak.
- `rpfwd`: Begin of Stop 'n Reverse Port Forward, wat afstandstoegang tot dienste op die teiken netwerk moontlik maak.
- `socks`: Begin of Stop 'n SOCKS5-proxy op die teiken netwerk, wat tunneling van verkeer deur die gecompromitteerde gasheer moontlik maak. Kompatibel met gereedskap soos proxychains.
- `portscan`: Skandeer gasheer(s) vir oop poorte, nuttig om potensiële teikens vir laterale beweging of verdere aanvalle te identifiseer.

### Proses uitvoering

- `shell`: Voer 'n enkele shell-opdrag uit via /bin/sh, wat direkte uitvoering van opdragte op die teikenstelsel moontlik maak.
- `run`: Voer 'n opdrag vanaf skyf met argumente uit, wat die uitvoering van binaries of skripte op die teikenstelsel moontlik maak.
- `pty`: Maak 'n interaktiewe PTY oop, wat direkte interaksie met die shell op die teikenstelsel moontlik maak.
