# Mythic

{{#include ../banners/hacktricks-training.md}}

## Wat is Mythic?

Mythic is ’n oopbron-, modulêre en samewerkende command and control (C2)-raamwerk wat vir red teaming ontwerp is. Dit stel operators in staat om agents (payloads) oor verskillende bedryfstelsels, insluitend Windows, Linux en macOS, te bestuur en te ontplooi. Mythic bied ’n blaaier-UI vir taaktoewysing aan verskeie operators, lêerhantering, SOCKS/rpfwd-bestuur en payload-generering.

Anders as monolitiese raamwerke, bevat die Mythic-bewaarplek self **nie** payload-tipes of C2-profiele nie. Agents, wrappers en C2-profiele word gewoonlik as eksterne komponente geïnstalleer en kan onafhanklik van Mythic core opgedateer word.

### Installasie

Volg die instruksies in die amptelike **[Mythic repo](https://github.com/its-a-feature/Mythic)** om Mythic te installeer. ’n Algemene bootstrap vanaf die Mythic-gids is:

```bash
sudo make
sudo ./mythic-cli start
```

As Mythic reeds loop, kan jy gewoonlik ’n nuwe agent of profile byvoeg met `./mythic-cli install github ...` en dan óf Mythic herbegin óf net die nuwe komponent direk begin.

### Agents

Mythic ondersteun verskeie agents, wat die **payloads is wat take op die gekompromitteerde stelsels uitvoer**. Elke agent kan vir spesifieke behoeftes aangepas word en op verskillende bedryfstelsels loop.

Mythic het by verstek geen agents geïnstalleer nie. Die open-source community agents is by [**https://github.com/MythicAgents**](https://github.com/MythicAgents) beskikbaar, en die [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) is nuttig om vinnig na te gaan watter bedryfstelsels, payload-formate, wrappers en C2 profiles ondersteun word.<sup>[[1]](#references)</sup>

Om ’n agent van daardie org te installeer, kan jy die volgende uitvoer:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Die `sudo -E`-vorm is nuttig wanneer jy vanuit ’n nie-root-omgewing installeer. Jy kan nuwe agents met die vorige opdrag byvoeg, selfs al loop Mythic reeds.

### C2 Profiles

C2 profiles in Mythic definieer **hoe agents met die Mythic-bediener kommunikeer**. Hulle spesifiseer die kommunikasieprotokol, enkripsiemetodes en ander instellings. Jy kan C2 profiles deur die Mythic-webkoppelvlak skep en bestuur.

Mythic word by verstek sonder profiles geïnstalleer, maar dit is moontlik om sommige profiles van die repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) af te laai deur die volgende uit te voer:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Huidige profiele wat operateurs in gedagte moet hou:

- [`http`](https://github.com/MythicC2Profiles/http): basiese asinkrone GET/POST-verkeer.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): meer buigsame HTTP-verkeer met verskeie callback-domeine, failover-/rondtalrotasie, pasgemaakte opskrifte/navraagparameters en boodskaptransformasies (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) wat in koekies, opskrifte, navraagparameters of die inhoud geplaas word.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-gedrewe HTTP-boodskapvorming wanneer die statiese `http`-profile te herkenbaar is.

### Huidige platformnotas

- Baie publieke agents en profiele installeer nou met voorafgeboude afgeleë container-beelde.
  As jy ’n komponent forkeer of dit plaaslik regmaak, maar Mythic steeds die ou gedrag gebruik, ondersoek die gegenereerde `.env`-inskrywings vir `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` en `*_USE_VOLUME`; deur
  `*_USE_BUILD_CONTEXT="true"` te aktiveer, laat jy Mythic gewoonlik herbou met jou plaaslike Docker-konteks in plaas daarvan om stilweg die afgeleë beeld te hergebruik.
- Blaaierskripte is een van Mythic se waardevolste gehalte-van-lewe-kenmerke vir operateurs: dit kan rou opdraguitvoer omskep in tabelle, skermskootkykers, aflaaiskakels, soekskakels en knoppies wat opvolg-tasking direk vanaf die UI uitvoer. Huidige Mythic-bouweergawes laat elke operateur toe om hul eie skripte te hou, hulle wêreldwyd of per taak aan of af te skakel, en die beste resultate te kry wanneer agents gestruktureerde JSON eerder as gewone teks terugstuur. Dit is veral nuttig vir herhalende `ls`-, `ps`-, triage- en lêerblaaierwerkvloei.<sup>[[4]](#references)[[6]](#references)</sup>
- Nuwer Mythic-bouweergawes ondersteun ook interaktiewe tasking- en Push C2-patrone wat die behoefte aan `sleep 0`-polling tydens PTY/SOCKS/rpfwd-swaar operasies verminder. Wanneer ’n agent/profile dit ondersteun, verg dit gewoonlik minder hulpbronne as om die bediener voortdurend met check-ins te bestook net om ’n interaktiewe kanaal bruikbaar te hou.<sup>[[3]](#references)</sup>
- Huidige Mythic-bouers uit die 3.4-era is meer konteksbewus as wat ouer skrywes aandui: bouparameters kan nou gegroepeer of versteek word op grond van die gekose bedryfstelsel of ander bouopsies; payload-tipes kan verklaar of hulle verskeie C2-profiele of verskeie instansies van dieselfde C2 in een bou ondersteun; en C2-parameterafwykings laat ’n agent toe om velde te versteek wat hy nie werklik implementeer nie. Dit is belangrik wanneer jy tussen `http`, `httpx`, `smb`,
  `tcp` en `websocket` wissel, omdat die veilige/geldige bouopsies nie meer ’n plat, statiese vorm is nie.<sup>[[5]](#references)</sup>
- As jy ’n pasgemaakte agent/profile-paar bou en nie Mythic se JSON-boodskapformaat of verstek-enkripsie oor die netwerk wil gebruik nie, gebruik ’n
  `translation_container`: Mythic verwyder die UUID, stuur die geënkripteerde blob en sleuteldata oor gRPC aan die vertaler, en verwag agent-inheemse grepe terug. Dit is die skoon manier om binêre protokolle, pasgemaakte raamwerk of enkripsie aan die agentkant te ondersteun sonder om die hele bediener te herskryf.
- Onthou dat gekoppelde/P2P-callbacks nie net tasking aanstuur nie. Mythic se `get_tasking`-vloei kan ook responses plus `delegates`,
  `socks`, `rpfwd` en `interactive`-data dra. In die praktyk kan een egress-callback innerlike callbacks en pivot-kanale in dieselfde polling-lus bedien; as die child agents hul eie periodieke check-ins uitvoer, keer `get_delegate_tasks=false` dat die ouer per ongeluk die innerlike callback se taakwaglys verbruik.

### Wrapper-payloads

Wrapper-payloads laat jou dieselfde agent-logika behou terwyl jy die voorstelling op skyf verander van wat afgelewer of volgehou word.

- `service_wrapper`: omskep ’n ander payload in ’n Windows-diensuitvoerbare lêer, wat nuttig is wanneer die uitvoeringspad ’n geldige diensbinêre lêer vereis.
- `scarecrow_wrapper`: omhul versoenbare shellcode met die ScareCrow-loader om loader-gesteunde uitvoerlêers soos EXE/DLL/CPL te genereer.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is ’n Windows-agent wat in C# met die 4.0 .NET Framework geskryf is en ontwerp is vir gebruik in SpecterOps se opleidingsaanbiedinge.<sup>[[2]](#references)</sup>

Installeer dit met:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Huidige bou-/profielaantekeninge

- Apollo kan tans `WinExe`-, `Shellcode`-, `Service`- en `Source`-payloads uitstuur.
- Die Apollo-profiele wat die meeste gebruik word, is `http`, `httpx`, `smb`, `tcp` en `websocket`.
- `httpx` is gewoonlik die meer buigsame opsie wanneer jy domeinrotasie, proxy-ondersteuning, pasgemaakte boodskapplasing en boodskaptransformasies nodig het, eerder as die ouer statiese `http`-profiel.
- Apollo is een van die gemeenskapsagente met die meeste funksies en bied tans Mythic-kant-integrasies soos browserskripte, lêer-/prosesblaaieraansigte, skermkiekies, keylogging, SOCKS, rpfwd, Push C2 en P2P-roetering.
- Apollo ondersteun wrapper-payloads soos `service_wrapper` en `scarecrow_wrapper`.
- Apollo ondersteun dinamiese command loading, sodat jy die aanvanklike payload klein kan hou en later ekstra commands of Forge-modules kan laai, eerder as om elke post-ex-vermoë in die eerste bou in te sluit.
- Wanneer shellcode-uitvoer gegenereer word, bied Apollo se huidige builder ook Donut-formaatkeuses (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) en Donut-bypassgedrag (`None`, `Abort on fail`, `Continue on fail`). Dit is nuttig as die einddoel is om die shellcode weer met `service_wrapper`, `scarecrow_wrapper` of ’n pasgemaakte loader te omhul.
- `register_file` en `register_assembly` is die staging-primitiewe vir `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` en `powerpick`. In huidige Apollo-bouweergawes word daardie gestage artefakte kliëntkant as DPAPI-beskermde AES256-blobs gekas.
- `ls`- en `ps`-resultate integreer besonder goed met Mythic se browserskripte en lêer-/prosesblaaier, wat operator-triage in samewerkende operasies merkbaar vinniger maak.
- Apollo se fork-and-run-take erf hul sacrificial process-instellings van
  `spawnto_x86` / `spawnto_x64`, erf ouerseleksie van `ppid`, en
  gebruik dan die tans geselekteerde injection primitive. In die praktyk beteken
  dit dat jou OPSEC-instelling vir een command dikwels tegelyk `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` en `spawn` beïnvloed.
- Tans gedokumenteerde Apollo-injection-backends sluit `CreateRemoteThread`,
  `QueueUserAPC` (early-bird-styl) en `NtCreateThreadEx` via syscalls in. Gebruik
  `get_injection_techniques` voor lawaaierige post-exploitation en
  `set_injection_technique` as jy moet oorskakel van ’n primitive wat
  met die teiken of die command wat jy wil uitvoer bots.
- `blockdlls` raak slegs sacrificial processes wat vir post-exploitation-take geskep word. Saam met ’n minder verdagte `spawnto_x64`-teiken as die verstek-`rundll32.exe` sonder argumente, is dit een van die maklikste Apollo-kant-veranderinge om aan te bring voordat jy take uitvoer wat baie assemblies/PowerShell gebruik.

### Opsporingsbewuste .NET-agentbou-pyplyn

’n Opsporingsbewuste Apollo-fork moet as ’n **hele boustelselprobleem** beskou word, nie as ’n laaste `obfuscate.exe`-stap nie. Hierdie gevallestudie vul die algemene [AV-ontduikingsmetodologie](av-bypass.md) en die [ .NET-inspeksienutsgoed](../reversing/reversing-tools-basic-methods/README.md) aan: veranderinge aan wire-identifiseerders, IL-metadata, afhanklikheidspakkettering, reflection en dinamies saamgestelde take vorm saam een verenigbaarheidsgrens.<sup>[[8]](#references)</sup>

#### YARA-bewuste protokolmutasie

Oudit openbare lêer-/geheëreëls voordat jy kode verander. Byvoorbeeld, Elastic se `Multi_Trojan_Mythic_4beb7e17` pas wanneer enige **7 van 11** Mythic JSON-/action-stringe teenwoordig is, insluitend `task_id`, `post_response`, `c2_profile`, `get_tasking` en `get_delegate_tasks`. Om genoeg velde te hernoem, kan daardie drempel verslaan, maar dit is protokolwaardes, nie kosmetiese simbole nie: die agent en die ooreenstemmende server-/profile-implementasie moet saam verander word.<sup>[[7]](#references)[[8]](#references)</sup>

Dit verwyder net een stel statiese kenmerke. Kontrolefrekwensie, boodskapvorm, taak-/responsvloei en rekonstruksie van stringe tydens looptyd kan steeds gedrags- of geheue-aanwysers wees; bekragtig dus beide die geboude artefak en ’n uitgeoefende callback, eerder as om ’n skoon stringskandering as sukses te beskou.<sup>[[8]](#references)</sup>

#### Voeg saam voordat globale transformasies toegepas word

Hulpbroninbedding met nutsgoed soos Costura laat metgesel-assemblies as saamgepersde hulpbronne agter. ’n Obfuscator wat net die buitenste module verwerk, mis dus hul tipe-name en metadata; om elke DLL afsonderlik te obfuscate, kan eerder onversoenbare name aan kontrakte tussen assemblies toeken. Voeg bouuitsette eers op IL-vlak saam (byvoorbeeld met [ILRepack](https://github.com/gluck/il-repack)), en pas dan een hernoemingskaart op die resulterende module toe.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

'n Pasgemaakte pass kan [dnlib](https://github.com/0xd4d/dnlib) gebruik vir transforms van managed IL/metadata en [AsmResolver](https://github.com/Washi1337/AsmResolver) vir PE/resource-patching ná skryf. In die gevallestudie het geskikte `ldstr`-instruksies integer-token-/decryptor-oproepe geword, gerugsteun deur 'n nuwe 16-byte rolling-XOR-sleutel, terwyl simbole en namespaces na geloofwaardige name in ondernemingsstyl omgeskakel is, eerder as kort opeenvolgende identifiseerders. Ander passes het geselekteerde compiler-/debugger-attribuutte verwyder, merger-/embedding-verwysings skoongemaak, resources hernoem en weergawe-inligting gepatch. Genereer nuwe name, dead code en enkripsiemateriaal vir elke onafhanklike build: die verandering van ciphertext verwyder stabiele grepe, maar 'n stabiele decryptor of herkenbare transformasiepatroon is self 'n signature.<sup>[[8]](#references)</sup>

#### Hou dinamiese take met die payload gesinchroniseer

Apollo kan taakbronkode aan die bedienerkant compileer, die DLL-grepe stuur en dit met `Assembly.Load()` laai. Sodra die basiese agent se publieke tipes hernoem is, kan latere take wat teen die oorspronklike API gecompileer is, nie meer opgelos word nie. Behandel die uitgevoerde rename map as 'n payload-spesifieke ABI-artefak:<sup>[[8]](#references)</sup>

1. Koppel die map en tipe-konteks aan die presiese payload-/build-identifiseerder.
2. Kry vir elke taakbuild daardie map en herskryf 'n tydelike bronboom.
3. Herskryf slegs opgeloste verwysings na namespace, tipe, geneste/generiese tipe, veld en eienskap, en compileer dan teen die verduisterde saamgevoegde assembly.
4. Verwerp ontbrekende of onverwante maps voordat take afgelewer word, en voer ná compilering 'n initialiseringstoets uit.

Blinde globale vervanging is onveilig omdat 'n identifiseerder ook in 'n string, plaaslike verklaring, lidtoegang, framework-tipe of onverwante namespace kan voorkom. As 'n teks-/regex-herskrywer behou word, beskerm daardie kontekste uitdruklik en voer regressietoetse uit wanneer die map-skema of 'n rename-pass verander.<sup>[[8]](#references)</sup>

#### Maak reflection-kontrakte onafhanklik van namespaces

Ontdekkingskode wat `t.FullName.StartsWith("Tasks.")` nagaan, maak die namespace noodsaaklik en faal ná namespace-herkartering. Ontdek eerder tipes deur 'n stabiele tipeverwantskap te gebruik, terwyl klasname behou word as dispatch steeds `t.Name` gebruik:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Handhaaf ’n eksplisiete allowlist van name wat deur reflection sigbaar is, serializer-velde, entry points en API’s tussen assemblies wat nie hernoem mag word nie. Decompileer laastens die resultaat met ILSpy/dnSpy, skandeer die lêer- en geheueweergawes, en toets elke command- en loader-pad in ’n EDR-laboratorium; ’n build wat suksesvol begin, kan steeds take bevat wat deur hernoeming gebreek is, of gedrag hê wat eers ná uitvoering opgespoor word.<sup>[[8]](#references)</sup>

Hierdie agent het baie commands, wat dit baie soortgelyk aan Cobalt Strike se Beacon maak, met ’n paar ekstras. Dit ondersteun onder andere:

### Algemene aksies

- `cat`: Druk die inhoud van ’n lêer uit
- `cd`: Verander die huidige werkgids
- `cp`: Kopieer ’n lêer van een ligging na ’n ander
- `ls`: Lys lêers en gidse in die huidige gids of die gespesifiseerde pad
- `ifconfig`: Kry netwerkadapters en -koppelvlakke
- `netstat`: Kry TCP- en UDP-verbindinginligting
- `pwd`: Druk die huidige werkgids uit
- `ps`: Lys lopende prosesse op die teikenstelsel (met bykomende inligting)
- `jobs`: Lys alle lopende take wat met langlopende taakuitvoering verband hou
- `download`: Laai ’n lêer van die teikenstelsel na die plaaslike masjien af
- `upload`: Laai ’n lêer van die plaaslike masjien na die teikenstelsel op
- `reg_query`: Doen navraag oor register-sleutels en -waardes op die teikenstelsel
- `reg_write_value`: Skryf ’n nuwe waarde na ’n gespesifiseerde registersleutel
- `sleep`: Verander die agent se slaapinterval, wat bepaal hoe dikwels dit by die Mythic-bediener aanmeld
- En vele ander; gebruik `help` om die volledige lys beskikbare commands te sien.

### Privilege escalation

- `getprivs`: Aktiveer soveel moontlik privileges op die huidige thread-token
- `getsystem`: Maak ’n handle na winlogon oop en dupliseer die token, wat privileges effektief tot SYSTEM-vlak verhoog
- `make_token`: Skep ’n nuwe aanmeldingsessie en pas dit op die agent toe, sodat ’n ander gebruiker nageboots kan word
- `steal_token`: Steel ’n primêre token van ’n ander proses, sodat die agent die gebruiker van daardie proses kan naboots
- `pth`: Pass-the-Hash-aanval, waarmee die agent as ’n gebruiker kan verifieer deur hul NTLM-hash te gebruik, sonder dat die gewone tekswagwoord nodig is
- `mimikatz`: Voer Mimikatz-commands uit om credentials, hashes en ander sensitiewe inligting uit geheue of die SAM-databasis te onttrek
- `rev2self`: Stel die agent se token na sy primêre token terug, wat privileges effektief na die oorspronklike vlak verlaag
- `ppid`: Verander die ouerproses vir post-exploitation-take deur ’n nuwe ouerproses-ID te spesifiseer, wat beter beheer oor die taakuitvoeringskonteks moontlik maak
- `printspoofer`: Voer PrintSpoofer-commands uit om sekuriteitsmaatreëls van die print spooler te omseil, wat privilege escalation of kode-uitvoering moontlik maak
- `dcsync`: Sinkroniseer ’n gebruiker se Kerberos-sleutels na die plaaslike masjien, wat offline-wagwoordkraking of verdere aanvalle moontlik maak
- `ticket_cache_add`: Voeg ’n Kerberos-ticket by die huidige of ’n gespesifiseerde aanmeldingsessie, wat hergebruik van tickets of nabootsing moontlik maak

### Prosesuitvoering

- `assembly_inject`: Laat toe dat ’n .NET assembly-loader in ’n afgeleë proses ingespuit word
- `blockdlls`: Blokkeer die laai van DLL’s wat nie deur Microsoft onderteken is nie, in post-exploitation-take
- `execute_assembly`: Voer ’n .NET assembly in die agent se konteks uit
- `execute_coff`: Voer ’n COFF-lêer in geheue uit, wat uitvoering van saamgestelde kode in geheue moontlik maak
- `execute_pe`: Voer ’n unmanaged uitvoerbare lêer (PE) uit
- `keylog_inject`: Spuit ’n keylogger in ’n ander proses in en stroom toetsaanslae terug na Mythic se keylog-aansig
- `screenshot` / `screenshot_inject`: Neem die huidige lessenaar direk vas, of
  deur ’n screenshot-assembly in ’n teikenproses/-sessie in te spuit
- `get_injection_techniques`: Wys beskikbare injection-tegnieke en die tans geselekteerde een
- `inline_assembly`: Voer ’n .NET assembly in ’n weggooibare AppDomain uit, wat tydelike kode-uitvoering moontlik maak sonder om die agent se hoofproses te beïnvloed
- `register_assembly`: Registreer ’n .NET assembly vir latere uitvoering
- `register_file`: Registreer ’n lêer in die agent se cache vir latere `execute_*`- of PowerShell-taakuitvoering
- `run`: Voer ’n binêre lêer op die teikenstelsel uit en gebruik die stelsel se PATH om die uitvoerbare lêer te vind
- `set_injection_technique`: Verander die injection-primitief wat deur post-exploitation-take gebruik word
- `shinject`: Spuit shellcode in ’n afgeleë proses in, wat uitvoering van arbitrêre kode in geheue moontlik maak
- `inject`: Spuit agent-shellcode in ’n afgeleë proses in, wat uitvoering van die agent se kode in geheue moontlik maak
- `spawn`: Begin ’n nuwe agentsessie in die gespesifiseerde uitvoerbare lêer, wat shellcode-uitvoering in ’n nuwe proses moontlik maak
- `spawnto_x64` en `spawnto_x86`: Verander die verstekbinêre lêer wat in post-exploitation-take gebruik word na ’n gespesifiseerde pad, in plaas daarvan om `rundll32.exe` sonder parameters te gebruik, wat baie opvallend is.

### Mythic Forge

Dit laat jou toe om **COFF/BOF**-lêers vanaf die Mythic Forge te laai. Dit is ’n bewaarplek van vooraf saamgestelde payloads en tools wat op die teikenstelsel uitgevoer kan word. Met al die commands wat gelaai kan word, sal dit moontlik wees om algemene aksies uit te voer deur hulle as BOF’s in die huidige agentproses uit te voer (gewoonlik met beter OPSEC as wanneer ’n aparte proses begin word).

Begin hulle installeer met:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Gebruik dan `forge_collections` om die COFF/BOF-modules van die Mythic Forge te wys, sodat jy hulle kan kies en in die agent se geheue laai vir uitvoering. By verstek word die volgende 2 versamelings in Apollo bygevoeg:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Nadat ’n module gelaai is, sal dit in die lys verskyn as nog ’n opdrag, soos `forge_bof_sa-whoami` of `forge_bof_sa-netuser`.

Onthou vir BOFs dat Forge nie bloot een plat argumentstring
aan Apollo deurgee nie. Dit karteer BOF-parameters na Mythic se getikte skikkingformaat en stuur hulle dan deur Apollo se `execute_coff`-vloei. As ’n Forge-gelaaide BOF vreemd optree, kontroleer die verwagte BOF-argumenttipes / toegangspunt, eerder as net die opdragreël wat jy ingetik het. Let ook daarop dat Apollo se nuwer BOF-laaier die hantering van argumente verander het in vergelyking met baie ouer 2.3.1-era bouweergawes. Verouderde BOFs of ou versamelings kan dus misluk bloot omdat die verwagtinge vir die marshalering verander het.

### PowerShell- en skripuitvoering

- `powershell_import`: Voer ’n nuwe PowerShell-skrip (.ps1) in die agentkas in vir latere uitvoering
- `powershell`: Voer ’n PowerShell-opdrag in die agent se konteks uit, wat gevorderde skripte en outomatisering moontlik maak
- `powerpick`: Spuit ’n PowerShell-laaierassembly in ’n offerproses in en voer ’n PowerShell-opdrag uit (sonder powershell-logging).
- `psinject`: Voer PowerShell in ’n gespesifiseerde proses uit, wat geteikende uitvoering van skripte in die konteks van ’n ander proses moontlik maak
- `shell`: Voer ’n shell-opdrag in die agent se konteks uit, soortgelyk aan die uitvoering van ’n opdrag in cmd.exe

### Laterale beweging

- `jump_psexec`: Gebruik die PsExec-tegniek om lateraal na ’n nuwe gasheer te beweeg deur eers die Apollo-agentuitvoerbare lêer (apollo.exe) daarheen te kopieer en dit uit te voer.
- `jump_wmi`: Gebruik die WMI-tegniek om lateraal na ’n nuwe gasheer te beweeg deur eers die Apollo-agentuitvoerbare lêer (apollo.exe) daarheen te kopieer en dit uit te voer.
- `link` en `unlink`: Skep en verbreek P2P-skakels (byvoorbeeld oor SMB/TCP) tussen callbacks.
- `wmiexecute`: Voer ’n opdrag op die plaaslike of gespesifiseerde afgeleë stelsel uit met WMI, met opsionele geloofsbriewe vir nabootsing.
- `net_dclist`: Kry ’n lys domeinbeheerders vir die gespesifiseerde domein, nuttig om potensiële teikens vir laterale beweging te identifiseer.
- `net_localgroup`: Lys plaaslike groepe op die gespesifiseerde rekenaar; indien geen rekenaar gespesifiseer word nie, is die verstek localhost.
- `net_localgroup_member`: Kry lidmaatskap van ’n plaaslike groep vir ’n gespesifiseerde groep op die plaaslike of afgeleë rekenaar, wat opsomming van gebruikers in spesifieke groepe moontlik maak.
- `net_shares`: Lys afgeleë delings en hul toeganklikheid op die gespesifiseerde rekenaar, nuttig om potensiële teikens vir laterale beweging te identifiseer.
- `socks`: Aktiveer ’n SOCKS 5-versoenbare proxy op die teikennetwerk, wat tonnelvorming van verkeer deur die gekompromitteerde gasheer moontlik maak. Versoenbaar met nutsmiddels soos proxychains.
- `rpfwd`: Begin luister op ’n gespesifiseerde poort op die teikengasheer en stuur verkeer deur Mythic na ’n afgeleë IP en poort, wat afgeleë toegang tot dienste op die teikennetwerk moontlik maak.
- `listpipes`: Lys alle benoemde pype op die plaaslike stelsel. Dit kan nuttig wees vir laterale beweging of regteverhoging deur met IPC-meganismes te werk.

Vir die laervlak-WMI-uitvoeringsprimitiewe wat onderliggend aan `jump_wmi` of `wmiexecute` gebruik word, kyk na [WmiExec](lateral-movement/wmiexec.md). Vir breër patrone vir pivoting, kyk na [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Diverse opdragte
- `help`: Vertoon gedetailleerde inligting oor spesifieke opdragte of algemene inligting oor alle beskikbare opdragte in die agent.
- `clear`: Merk take as 'cleared' sodat agente hulle nie kan optel nie. Jy kan `all` spesifiseer om alle take skoon te maak, of `task Num` om ’n spesifieke taak skoon te maak.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is ’n Golang-agent wat na **Linux en macOS**-uitvoerbare lêers gekompileer word.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Huidige bou-/profielaantekeninge

- Huidige Poseidon-builds teiken Linux en macOS op beide `x86_64` en `arm64`.
- Ondersteunde uitvoerformate sluit inheemse uitvoerbare lêers in, plus uitvoere in gedeeldebiblioteekstyl soos `dylib` en `so`.
- Poseidon ondersteun `http`, `websocket`, `tcp` en `dynamichttp`, en huidige builders stel multi-egress-instellings soos `egress_order` en failover-drempels beskikbaar.
- Poseidon se huidige vermoëmetadata adverteer ook blaaierskripte, lêer-/prosesblaaierintegrasie, interaktiewe tasking, keylogging, skermkiekies, Push C2, SOCKS, rpfwd en P2P. Dit beteken dat dit as ’n werklike Linux-/macOS-pivot node kan werk, eerder as net ’n eenvoudige remote shell.
- Bou-tyd-opsies soos `proxy_bypass` en `garble` is die moeite werd om na te gaan wanneer jy óf skoner netwerkgedrag óf ekstra Go-binêre obfuscation nodig het.
- `pty` is een van die nuttigste nuwer gehalte-van-lewe-opdragte vir Linux-/macOS-bewerkings, omdat dit ’n interaktiewe PTY oopmaak en ’n Mythic-kantpoort kan blootstel vir meer volledige terminaalinteraksie, sonder dat jy die ouer `sleep 0` + SOCKS-ompad hoef te gebruik.
- Poseidon se huidige dokumentasie is veral interessant vir macOS-swaar tradecraft: `jxa` voer JavaScript for Automation in-geheue uit, `screencapture` neem ’n kiekie van die aangemelde lessenaar, `clipboard_monitor` stroom veranderinge aan die pasteboard, `execute_library` laai ’n plaaslike dylib en roep ’n funksie daarin aan, en `libinject` dwing ’n afgeleë proses om ’n dylib vanaf die skyf te laai.
- Onthou vir langlopende take dat Poseidon post-exploitation-werk in goroutines/threads uitvoer wat saamwerkend is, eerder as om hard doodgemaak te kan word. Die dokumentasie meld ook uitdruklik dat daar tans geen ingeboude agent-obfuscation is nie, dus is tradecraft op bou-/profielvlak belangriker as met kommersiële implants wat sterk geobfuskeer is.

Vir macOS-spesifieke tradecraft rondom Mythic-gesteunde bewerkings, JAMF-misbruik of MDM-as-C2-idees, kyk na [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Wanneer dit op Linux of macOS gebruik word, het dit ’n paar interessante opdragte:

### Algemene aksies

- `cat`: Druk die inhoud van ’n lêer uit
- `cd`: Verander die huidige werkgids
- `chmod`: Verander die toestemmings van ’n lêer
- `config`: Bekyk huidige konfigurasie en gasheerinligting
- `cp`: Kopieer ’n lêer van een ligging na ’n ander
- `curl`: Voer ’n enkele webversoek uit met opsionele opskrifte en metode
- `upload`: Laai ’n lêer na die teiken op
- `download`: Laai ’n lêer vanaf die teikenstelsel na die plaaslike masjien af
- En nog baie meer

### Soek na sensitiewe inligting

- `triagedirectory`: Soek interessante lêers in ’n gids op ’n gasheer, soos sensitiewe lêers of geloofsbriewe.
- `getenv`: Kry al die huidige omgewingsveranderlikes.

### macOS-spesifieke tradecraft

- `jxa`: Voer JavaScript for Automation in-geheue uit via `OSAScript`, wat nuttig is vir inheemse macOS post-exploitation sonder om aparte skriplêers neer te laat.
- `clipboard_monitor`: Peil die pasteboard en rapporteer veranderinge aan Mythic, wat handig is vir workflows vir diefstal van geloofsbriewe/tokens wat op kopieer/plak staatmaak.
- `screencapture`: Neem ’n skermkiekie van die gebruiker se lessenaar op macOS.
- `execute_library`: Laai ’n dylib vanaf die skyf en roep ’n spesifieke uitgevoerde funksie aan.
- `libinject`: Spuit ’n shellcode-stub in wat ’n ander macOS-proses dwing om ’n dylib vanaf die skyf te laai.
- `persist_launchd`: Skep LaunchAgent-/LaunchDaemon-volharding direk vanaf die agent.

### Beweeg lateraal

- `ssh`: SSH na ’n gasheer met die aangewese geloofsbriewe en open ’n PTY sonder om ssh te spawn.
- `sshauth`: SSH na gespesifiseerde gasheer(s) met die aangewese geloofsbriewe. Jy kan dit ook gebruik om ’n spesifieke opdrag op die afgeleë gashere via SSH uit te voer, of om dit te gebruik om lêers met SCP te kopieer.
- `link_tcp`: Skakel via TCP na ’n ander agent, sodat direkte kommunikasie tussen agents moontlik is.
- `link_webshell`: Skakel na ’n agent met die webshell P2P-profiel, sodat afstandtoegang tot die agent se webkoppelvlak moontlik is.
- `rpfwd`: Begin of stop ’n Reverse Port Forward, wat afstandtoegang tot dienste op die teikennetwerk moontlik maak.
- `socks`: Begin of stop ’n SOCKS5-proxy op die teikennetwerk, wat verkeer deur die gekompromitteerde gasheer laat tonnel. Versoenbaar met nutsmiddels soos proxychains.
- `portscan`: Skandeer gasheer(s) vir oop poorte, nuttig om potensiële teikens vir laterale beweging of verdere aanvalle te identifiseer.

### Prosesuitvoering

- `shell`: Voer ’n enkele shell-opdrag via /bin/sh uit, wat direkte uitvoering van opdragte op die teikenstelsel moontlik maak.
- `run`: Voer ’n opdrag vanaf die skyf met argumente uit, wat die uitvoering van binaries of skripte op die teikenstelsel moontlik maak.
- `pty`: Maak ’n interaktiewe PTY oop, wat direkte interaksie met die shell op die teikenstelsel moontlik maak.

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2-hoogtepunte: Interaktiewe tasking, Push C2 en dinamiese lêerblaaier](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Blaaierskripte - Mythic-dokumentasie](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4-opdaterings](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformeer Red Team-bewerkings met Mythic se versteekte juwele: Blaaierskripte](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Multi_Trojan_Mythic YARA-reëls](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Van fork tot framework: Wat die wysiging van Apollo ons oor agentinval geleer het](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
