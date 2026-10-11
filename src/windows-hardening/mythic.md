# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic ni nini?

Mythic ni framework ya C2 iliyo open-source, modular na collaborative, iliyoundwa kwa red teaming. Huwaruhusu operators kudhibiti na kusambaza agents (payloads) kwenye mifumo tofauti ya uendeshaji, ikiwemo Windows, Linux na macOS. Mythic hutoa UI ya kivinjari kwa tasking ya operators wengi, kushughulikia faili, usimamizi wa SOCKS/rpfwd na kutengeneza payloads.

Tofauti na frameworks za monolithic, repository ya Mythic yenyewe **haisafirishi** aina za payload au C2 profiles. Agents, wrappers na C2 profiles kwa kawaida husakinishwa kama vipengele vya nje na vinaweza kusasishwa bila kutegemea Mythic core.

### Usakinishaji

Ili kusakinisha Mythic, fuata maagizo kwenye **[Mythic repo](https://github.com/its-a-feature/Mythic)** rasmi. Njia ya kawaida ya bootstrap kutoka kwenye directory ya Mythic ni:

```bash
sudo make
sudo ./mythic-cli start
```

Ikiwa Mythic tayari inaendesha, kwa kawaida unaweza kuongeza agent au profile mpya kwa kutumia `./mythic-cli install github ...`, kisha uwashe upya Mythic au uanzishe tu component mpya moja kwa moja.

### Agents

Mythic inasaidia agents nyingi, ambazo ni **payloads zinazotekeleza kazi kwenye mifumo iliyoathiriwa**. Kila agent inaweza kubinafsishwa kulingana na mahitaji mahususi na inaweza kuendeshwa kwenye mifumo tofauti ya uendeshaji.

Kwa chaguomsingi, Mythic haina agents zozote zilizosakinishwa. Agents za jamii ya open-source zinapatikana kwenye [**https://github.com/MythicAgents**](https://github.com/MythicAgents), na [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) ni muhimu kwa kuangalia kwa haraka mifumo ya uendeshaji inayotumika, miundo ya payload, wrappers, na C2 profiles.<sup>[[1]](#references)</sup>

Ili kusakinisha agent kutoka kwenye org hiyo, unaweza kutekeleza:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Umbo la `sudo -E` linafaa unaposakinisha kutoka kwenye mazingira yasiyo ya root. Unaweza kuongeza agents wapya kwa kutumia amri iliyotangulia hata kama Mythic tayari inaendeshwa.

### C2 Profiles

C2 profiles katika Mythic hufafanua **jinsi agents wanavyowasiliana na seva ya Mythic**. Hubainisha itifaki ya mawasiliano, mbinu za usimbaji fiche na mipangilio mingine. Unaweza kuunda na kudhibiti C2 profiles kupitia kiolesura cha wavuti cha Mythic.

Kwa chaguomsingi, Mythic husakinishwa bila profiles zozote; hata hivyo, unaweza kupakua baadhi ya profiles kutoka kwenye repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) kwa kutekeleza:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Profiles zinazohusika na operator kwa sasa za kuzingatia:

- [`http`](https://github.com/MythicC2Profiles/http): trafiki ya msingi ya GET/POST isiyosawazishwa.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): trafiki ya HTTP inayoweza kunyumbulika zaidi, yenye callback domains nyingi, mzunguko wa fail-over/round-robin, headers/query parameters maalum, na message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) zinazowekwa kwenye cookies, headers, query parameters, au body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): uundaji wa ujumbe wa HTTP unaoendeshwa na JSON/TOML pale ambapo profile tuli ya `http` inatambulika kirahisi mno.

### Maelezo ya sasa ya jukwaa

- Agents na profiles nyingi za umma sasa husakinishwa kwa kutumia picha za container za mbali zilizoundwa awali.
  Ukifork component au uifanyie patch kwenye mashine yako na Mythic ikaendelea kutumia
  tabia ya zamani, kagua maingizo ya `.env` yaliyotengenezwa kwa `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT`, na `*_USE_VOLUME`; kuweka
  `*_USE_BUILD_CONTEXT="true"` ndiko kwa kawaida kunakoifanya Mythic ijenge upya kutoka
  kwenye Docker context yako ya ndani badala ya kutumia kimyakimya picha ya mbali.
- Browser scripts ni miongoni mwa vipengele vya Mythic vinavyoboresha sana urahisi wa matumizi kwa operators: zinaweza kubadilisha matokeo ghafi ya amri kuwa majedwali, vionyeshi vya screenshot, viungo vya upakuaji, viungo vya utafutaji, na vitufe vinavyotuma tasking inayofuata moja kwa moja kutoka kwenye UI. Builds za sasa za Mythic humwezesha kila operator kuweka scripts zake, kuzibadilisha kwa pamoja au kwa kila task, na kupata matokeo bora zaidi pale agents zinaporudisha JSON iliyopangwa badala ya plaintext. Hili linafaa sana kwa workflows zinazojirudia za `ls`, `ps`, triage, na file-browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Builds mpya zaidi za Mythic pia zinaunga mkono tasking shirikishi na miundo ya Push C2, ambayo hupunguza hitaji la polling ya `sleep 0` wakati wa shughuli zinazotumia sana PTY/SOCKS/rpfwd. Agent/profile inapoiunga mkono, kwa kawaida hutumia rasilimali chache kuliko kuipiga server kwa check-ins za mara kwa mara ili tu kuweka channel shirikishi itumike.<sup>[[3]](#references)</sup>
- Builders za sasa za Mythic za enzi ya 3.4 zina ufahamu zaidi wa context kuliko inavyoashiriwa na maandishi ya zamani: build parameters sasa zinaweza kupangwa kwenye makundi au kufichwa kulingana na OS iliyochaguliwa au build options nyingine, payload types zinaweza kutangaza iwapo zinaunga mkono C2 profiles nyingi au instances nyingi za C2 ileile ndani ya build moja, na C2 parameter deviations huruhusu agent kuficha fields ambazo haitekelezi. Hili ni muhimu unapobadilisha kati ya `http`, `httpx`, `smb`,
  `tcp`, na `websocket` kwa sababu maeneo salama/halali ya build si fomu tuli bapa tena.<sup>[[5]](#references)</sup>
- Ikiwa unaunda jozi maalum ya agent/profile na hutaki format ya ujumbe ya JSON ya Mythic au crypto yake chaguo-msingi itumike kwenye wire, tumia
  `translation_container`: Mythic huondoa UUID, hukabidhi blob iliyosimbwa na
  key material kwa translator kupitia gRPC, na hutazamia bytes za asili za agent zirudishwe.
  Hii ndiyo njia safi ya kuunga mkono binary protocols, custom framing, au
  usimbaji fiche upande wa agent bila kuandika upya server nzima.
- Kumbuka kwamba callbacks zilizounganishwa/P2P hazipitishi tasking pekee. Mtiririko wa Mythic wa `get_tasking` unaweza pia kubeba responses pamoja na data za `delegates`, `socks`,
  `rpfwd`, na `interactive`. Kwa vitendo, callback moja ya egress inaweza kuhudumia
  callbacks za ndani na pivot channels kwenye polling loop moja; ikiwa child
  agents zinajifanya check-ins za mara kwa mara, `get_delegate_tasks=false` huzuia
  parent kutumia kwa bahati mbaya jobs zilizowekwa kwenye foleni ya callback ya ndani.

### Wrapper payloads

Wrapper payloads hukuruhusu kubaki na mantiki ileile ya agent huku ukibadilisha uwakilishi wa kwenye diski unaowasilishwa au kuhifadhiwa.

- `service_wrapper`: hubadilisha payload nyingine kuwa executable ya Windows service, jambo linalofaa pale njia ya utekelezaji inapohitaji service binary halali.
- `scarecrow_wrapper`: hufunga shellcode inayooana kwa kutumia loader ya ScareCrow ili kuzalisha matokeo yanayotegemea loader kama vile EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo ni agent ya Windows iliyoandikwa kwa C# kwa kutumia .NET Framework 4.0, iliyoundwa kutumika katika mafunzo ya SpecterOps.<sup>[[2]](#references)</sup>

Isakinishe kwa kutumia:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Maelezo ya sasa ya build/profile

- Apollo kwa sasa inaweza kutoa payload za `WinExe`, `Shellcode`, `Service`, na `Source`.
- Profile za Apollo zinazotumiwa sana ni `http`, `httpx`, `smb`, `tcp`, na `websocket`.
- `httpx` kwa kawaida ni chaguo linaloweza kubadilishwa zaidi unapohitaji domain rotation, usaidizi wa proxy, uwekaji maalum wa ujumbe, na message transforms badala ya profile ya zamani tuli ya `http`.
- Apollo ni mojawapo ya community agents zenye vipengele vingi zaidi, na kwa sasa inaonyesha integrations za upande wa Mythic kama vile browser scripts, mwonekano wa file/process browser, screenshots, keylogging, SOCKS, rpfwd, Push C2, na P2P routing.
- Apollo inasaidia wrapper payloads kama `service_wrapper` na `scarecrow_wrapper`.
- Apollo inasaidia dynamic command loading, kwa hivyo unaweza kuweka payload ya awali ndogo na kupakia commands au Forge modules za ziada baadaye badala ya kukusanya kila uwezo wa post-ex kwenye build ya kwanza.
- Unapozalisha shellcode output, builder ya sasa ya Apollo pia hutoa chaguo za Donut format (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) na tabia za Donut bypass (`None`, `Abort on fail`, `Continue on fail`). Hii ni muhimu ikiwa lengo la mwisho ni kuifunga upya shellcode kwa `service_wrapper`, `scarecrow_wrapper`, au custom loader.
- `register_file` na `register_assembly` ni staging primitives za `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, na `powerpick`. Katika Apollo builds za sasa, artifacts hizo zilizowekwa staging huhifadhiwa kwenye cache ya upande wa client kama blobs za AES256 zilizolindwa na DPAPI.
- Matokeo ya `ls` na `ps` huunganishwa vizuri hasa na browser scripts za Mythic na file/process browser, jambo linaloharakisha kwa kiasi kikubwa triage ya operator katika operations za ushirikiano.
- Kazi za Apollo za fork-and-run hurithi mipangilio ya sacrificial process kutoka
  `spawnto_x86` / `spawnto_x64`, hurithi uchaguzi wa parent kutoka `ppid`, na
  kisha hutumia injection primitive iliyochaguliwa kwa sasa. Kwa vitendo, hii ina maana
  kwamba marekebisho yako ya OPSEC kwa command moja mara nyingi huathiri
  `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, na `spawn` kwa
  wakati mmoja.
- Injection backends za Apollo zilizoorodheshwa kwenye nyaraka za sasa ni `CreateRemoteThread`,
  `QueueUserAPC` (mtindo wa early-bird), na `NtCreateThreadEx` kupitia syscalls. Tumia
  `get_injection_techniques` kabla ya post-exploitation yenye kelele na
  `set_injection_technique` ikiwa unahitaji kubadilisha primitive ambayo
  haipatani na target au command unayotaka kuendesha.
- `blockdlls` huathiri tu sacrificial processes zinazoundwa kwa ajili ya kazi za post-exploitation.
  Ikiunganishwa na target ya `spawnto_x64` isiyo na mashaka mengi kuliko `rundll32.exe` tupu ya default, hii ni mojawapo ya mabadiliko rahisi zaidi ya upande wa Apollo kufanya
  kabla ya kuendesha tasking inayotegemea sana assembly/PowerShell.

### Mchakato wa build wa .NET agent unaozingatia ugunduzi

Apollo fork inayozingatia ugunduzi inapaswa kuchukuliwa kama **tatizo la mfumo mzima wa build**, si hatua ya mwisho ya `obfuscate.exe`. Case study hii inakamilisha [mbinu ya AV evasion](av-bypass.md) na [zana za .NET inspection](../reversing/reversing-tools-basic-methods/README.md): mabadiliko kwa wire identifiers, IL metadata, ufungashaji wa dependencies, reflection, na tasks zinazokompiliwa dynamically huunda mpaka mmoja wa ulinganifu.<sup>[[8]](#references)</sup>

#### Mabadiliko ya protocol yanayozingatia YARA

Kagua public file/memory rules kabla ya kubadilisha code. Kwa mfano, `Multi_Trojan_Mythic_4beb7e17` ya Elastic hulingana pale strings zozote **7 kati ya 11** za Mythic JSON/action zinapokuwepo, zikiwemo `task_id`, `post_response`, `c2_profile`, `get_tasking`, na `get_delegate_tasks`. Kubadilisha majina ya fields za kutosha kunaweza kushinda kiwango hicho, lakini hizi ni protocol values, si alama za mapambo: agent na utekelezaji unaolingana wa server/profile lazima zibadilishwe pamoja.<sup>[[7]](#references)[[8]](#references)</sup>

Hii huondoa seti moja tu ya static features. Muda wa check-in, umbo la ujumbe, mtiririko wa task/response, na uundaji upya wa strings wakati wa runtime bado vinaweza kuwa viashiria vya tabia au memory; kwa hiyo, thibitisha artifact iliyojengwa na callback iliyotekelezwa badala ya kuchukulia scan safi ya strings kuwa mafanikio.<sup>[[8]](#references)</sup>

#### Unganisha kabla ya kutumia global transforms

Kuingiza resources kwa kutumia zana kama Costura huacha companion assemblies kama compressed resources. Obfuscator inayochakata outer module pekee hukosa majina ya types na metadata zake; obfuscating kila DLL kivyake kunaweza badala yake kugawa majina yasiyolingana kwa mikataba ya cross-assembly. Unganisha build outputs kwanza katika kiwango cha IL (kwa mfano kwa [ILRepack](https://github.com/gluck/il-repack)), kisha tumia rename map moja kwenye module iliyotokana.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Pass maalum inaweza kutumia [dnlib](https://github.com/0xd4d/dnlib) kwa mabadiliko ya managed IL/metadata na [AsmResolver](https://github.com/Washi1337/AsmResolver) kwa patching ya PE/resource baada ya kuandika. Katika case study, maagizo yanayostahili ya `ldstr` yalibadilishwa kuwa miito ya integer-token/decryptor inayotumia ufunguo mpya wa rolling-XOR wa baiti 16, huku symbols na namespaces zikipewa majina yanayofanana na yale ya biashara badala ya vitambulishi vifupi vya mfuatano. Pass nyingine ziliondoa attributes zilizochaguliwa za compiler/debugger, zikafuta marejeleo ya merger/embedding, zikabadilisha majina ya resources na kupatch taarifa za version. Tengeneza upya majina, dead code na nyenzo za usimbaji kwa kila build huru: kubadilisha ciphertext huondoa baiti thabiti, lakini decryptor thabiti au muundo wa mabadiliko unaotambulika wenyewe ni signature.<sup>[[8]](#references)</sup>

#### Sawazisha tasks zinazobadilika na payload

Apollo inaweza ku-compile source ya task upande wa server, kutuma baiti za DLL na kuzipakia kwa kutumia `Assembly.Load()`. Mara tu public types za base agent zinapobadilishwa majina, tasks za baadaye zinazo-compile dhidi ya API asilia hazitatatuliwa tena. Chukulia rename map iliyosafirishwa kama artifact ya ABI inayohusishwa na payload mahususi:<sup>[[8]](#references)</sup>

1. Unganisha map na muktadha wa type na kitambulisho halisi cha payload/build.
2. Kwa kila build ya task, pata map hiyo na uandike upya mti wa source wa muda.
3. Andika upya marejeleo yaliyotatuliwa pekee ya namespace, type, nested/generic type, field na property, kisha u-compile dhidi ya assembly iliyounganishwa na kufichwa.
4. Kataa map zinazokosekana au zisizolingana kabla ya kuwasilisha task, na ufanye jaribio la uanzishaji baada ya compilation.

Kubadilisha maandishi yote bila kuchagua si salama, kwa sababu kitambulishi kinaweza pia kutokea ndani ya string, tamko la local, member access, framework type au namespace isiyohusiana. Ikiwa text/regex rewriter itatumika, linda miktadha hiyo waziwazi na ifanyie regression test kila schema ya map au pass ya kubadilisha majina inapobadilika.<sup>[[8]](#references)</sup>

#### Fanya mikataba ya reflection isitegemee namespace

Discovery code inayokagua `t.FullName.StartsWith("Tasks.")` hufanya namespace kuwa muhimu na hushindwa baada ya namespace remapping. Fanya discovery kwa kutumia uhusiano thabiti wa type badala yake, huku ukihifadhi majina ya command class ikiwa dispatch bado inatumia `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Dumisha allowlist iliyo wazi ya majina yanayoonekana kupitia reflection, sehemu za serializer, entry point na API za assemblies tofauti ambazo hazipaswi kubadilishwa majina. Mwishowe, decompile matokeo kwa kutumia ILSpy/dnSpy, kagua uwakilishi wa faili na wa memory, na ujaribu kila njia ya command/loader katika EDR lab; build inayoanza kwa mafanikio bado inaweza kuwa na tasks zilizoharibika kwa sababu ya kubadilishwa majina, au tabia inayotambuliwa baada tu ya kutekelezwa.<sup>[[8]](#references)</sup>

Agent hii ina commands nyingi zinazoufanya ufanane sana na Beacon ya Cobalt Strike, pamoja na ziada kadhaa. Miongoni mwa hizo, inasaidia:

### Vitendo vya kawaida

- `cat`: Chapisha yaliyomo kwenye faili
- `cd`: Badilisha working directory ya sasa
- `cp`: Nakili faili kutoka eneo moja hadi jingine
- `ls`: Orodhesha faili na directories katika directory ya sasa au path maalum
- `ifconfig`: Pata adapta na interfaces za mtandao
- `netstat`: Pata maelezo ya miunganisho ya TCP na UDP
- `pwd`: Chapisha working directory ya sasa
- `ps`: Orodhesha michakato inayoendeshwa kwenye mfumo lengwa (pamoja na maelezo ya ziada)
- `jobs`: Orodhesha jobs zote zinazoendeshwa zinazohusiana na tasking ya muda mrefu
- `download`: Pakua faili kutoka kwenye mfumo lengwa hadi kwenye mashine ya ndani
- `upload`: Pakia faili kutoka kwenye mashine ya ndani hadi kwenye mfumo lengwa
- `reg_query`: Uliza funguo na thamani za registry kwenye mfumo lengwa
- `reg_write_value`: Andika thamani mpya kwenye ufunguo maalum wa registry
- `sleep`: Badilisha muda wa kusubiri wa agent, unaoamua ni mara ngapi hukagua mawasiliano na seva ya Mythic
- Na nyingine nyingi; tumia `help` kuona orodha kamili ya commands zinazopatikana.

### Kupandisha haki

- `getprivs`: Washa privileges nyingi iwezekanavyo kwenye token ya thread ya sasa
- `getsystem`: Fungua handle kwa winlogon na unakili token, hivyo kupandisha privileges hadi kiwango cha SYSTEM
- `make_token`: Unda logon session mpya na uitumie kwa agent, kuruhusu kuiga mtumiaji mwingine
- `steal_token`: Chukua token ya msingi kutoka kwa mchakato mwingine, kuruhusu agent kuiga mtumiaji wa mchakato huo
- `pth`: Shambulio la Pass-the-Hash, linalomruhusu agent kujithibitisha kama mtumiaji kwa kutumia NTLM hash yake bila kuhitaji nenosiri lisilosimbwa
- `mimikatz`: Tekeleza commands za Mimikatz ili kutoa credentials, hashes na taarifa nyingine nyeti kutoka kwenye memory au hifadhidata ya SAM
- `rev2self`: Rejesha token ya agent kwenye token yake ya msingi, hivyo kushusha privileges hadi kiwango cha awali
- `ppid`: Badilisha mchakato mzazi wa jobs za post-exploitation kwa kubainisha process ID mpya ya mzazi, ili kudhibiti vyema muktadha wa utekelezaji wa job
- `printspoofer`: Tekeleza commands za PrintSpoofer ili kukwepa hatua za usalama za print spooler, na kuruhusu kupandisha privileges au kutekeleza code
- `dcsync`: Sawazisha funguo za Kerberos za mtumiaji kwenye mashine ya ndani, na kuruhusu kuvunja nenosiri offline au kufanya mashambulizi zaidi
- `ticket_cache_add`: Ongeza ticket ya Kerberos kwenye logon session ya sasa au iliyobainishwa, na kuruhusu kutumia tena ticket au kuiga mtumiaji

### Utekelezaji wa michakato

- `assembly_inject`: Huruhusu kuingiza .NET assembly loader kwenye mchakato wa mbali
- `blockdlls`: Zuia DLL ambazo hazijasainiwa na Microsoft zisipakiwe kwenye jobs za post-exploitation
- `execute_assembly`: Tekeleza .NET assembly katika muktadha wa agent
- `execute_coff`: Tekeleza faili la COFF kwenye memory, na kuruhusu code iliyokusanywa kutekelezwa ndani ya memory
- `execute_pe`: Tekeleza executable isiyosimamiwa (PE)
- `keylog_inject`: Ingiza keylogger kwenye mchakato mwingine na utiririshe mibofyo ya vitufe hadi kwenye mwonekano wa keylog wa Mythic
- `screenshot` / `screenshot_inject`: Nasa desktop ya sasa moja kwa moja au
  kwa kuingiza screenshot assembly kwenye mchakato/session lengwa
- `get_injection_techniques`: Onyesha mbinu za injection zinazopatikana na iliyochaguliwa kwa sasa
- `inline_assembly`: Tekeleza .NET assembly kwenye AppDomain ya muda, na kuruhusu code kutekelezwa kwa muda bila kuathiri mchakato mkuu wa agent
- `register_assembly`: Sajili .NET assembly kwa ajili ya utekelezaji wa baadaye
- `register_file`: Sajili faili kwenye cache ya agent kwa ajili ya `execute_*` au tasking ya PowerShell ya baadaye
- `run`: Tekeleza binary kwenye mfumo lengwa, ukitumia PATH ya mfumo kutafuta executable
- `set_injection_technique`: Badilisha primitive ya injection inayotumiwa na jobs za post-exploitation
- `shinject`: Ingiza shellcode kwenye mchakato wa mbali, na kuruhusu utekelezaji wa code yoyote ndani ya memory
- `inject`: Ingiza shellcode ya agent kwenye mchakato wa mbali, na kuruhusu code ya agent kutekelezwa ndani ya memory
- `spawn`: Anzisha session mpya ya agent ndani ya executable iliyobainishwa, na kuruhusu shellcode kutekelezwa katika mchakato mpya
- `spawnto_x64` na `spawnto_x86`: Badilisha binary chaguomsingi inayotumiwa na jobs za post-exploitation iwe path iliyobainishwa badala ya kutumia `rundll32.exe` bila params, ambayo huacha dalili nyingi sana.

### Mythic Forge

Hii huruhusu **kupakia** faili za COFF/BOF kutoka Mythic Forge, ambayo ni hifadhi ya payloads na tools zilizokusanywa awali zinazoweza kutekelezwa kwenye mfumo lengwa. Kwa commands zote zinazoweza kupakiwa, itawezekana kutekeleza vitendo vya kawaida ndani ya mchakato wa sasa wa agent kama BOFs (kwa kawaida zikiwa na OPSEC bora kuliko kuanzisha mchakato tofauti).

Anza kuzisakinisha kwa:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Kisha, tumia `forge_collections` kuonyesha modules za COFF/BOF kutoka Mythic Forge ili uweze kuzichagua na kuzisakia kwenye memory ya agent kwa ajili ya execution. Kwa chaguo-msingi, collections 2 zifuatazo huongezwa kwenye Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Baada ya module moja kusakiwa, itaonekana kwenye orodha kama command nyingine, kwa mfano `forge_bof_sa-whoami` au `forge_bof_sa-netuser`.

Kwa BOFs, kumbuka kwamba Forge **haipitishi tu mfuatano mmoja tambarare wa argument** kwenda kwa Apollo. Hupanga BOF parameters katika format ya typed-array ya Mythic, kisha huzipitisha kwenye flow ya `execute_coff` ya Apollo. Ikiwa BOF iliyosakiwa kupitia Forge inafanya kazi kwa namna isiyo ya kawaida, kagua aina za argument za BOF zinazotarajiwa na entrypoint badala ya kuangalia tu command line uliyoandika. Pia kumbuka kwamba loader mpya zaidi ya BOF ya Apollo ilibadilisha ushughulikiaji wa argument ikilinganishwa na builds za zamani sana za enzi ya 2.3.1, kwa hiyo BOFs zilizopitwa na wakati au collections za zamani zinaweza kushindwa kwa sababu tu matarajio ya marshaling yalibadilika.

### Utekelezaji wa PowerShell na scripting

- `powershell_import`: Huleta script mpya ya PowerShell (.ps1) kwenye cache ya agent ili itekelezwe baadaye
- `powershell`: Hutekeleza command ya PowerShell katika muktadha wa agent, na kuruhusu scripting na automation ya hali ya juu
- `powerpick`: Huingiza loader assembly ya PowerShell kwenye process ya kujitolea, kisha hutekeleza command ya PowerShell (bila logging ya powershell).
- `psinject`: Hutekeleza PowerShell katika process iliyobainishwa, na kuruhusu scripts kutekelezwa kwa kulenga muktadha wa process nyingine
- `shell`: Hutekeleza command ya shell katika muktadha wa agent, sawa na kuendesha command kwenye cmd.exe

### Lateral Movement

- `jump_psexec`: Hutumia mbinu ya PsExec kufanya lateral movement kwenda kwa host mpya kwa kunakili kwanza executable ya Apollo agent (apollo.exe) na kisha kuitekeleza.
- `jump_wmi`: Hutumia mbinu ya WMI kufanya lateral movement kwenda kwa host mpya kwa kunakili kwanza executable ya Apollo agent (apollo.exe) na kisha kuitekeleza.
- `link` na `unlink`: Huunda na kuvunja viungo vya P2P (kwa mfano kupitia SMB/TCP) kati ya callbacks.
- `wmiexecute`: Hutekeleza command kwenye mfumo wa ndani au remote uliobainishwa kwa kutumia WMI, na inaruhusu credentials za impersonation.
- `net_dclist`: Hupata orodha ya domain controllers za domain iliyobainishwa, na kusaidia kutambua malengo yanayowezekana kwa lateral movement.
- `net_localgroup`: Huorodhesha makundi ya ndani kwenye computer iliyobainishwa; hutumia localhost kwa chaguo-msingi ikiwa hakuna computer iliyobainishwa.
- `net_localgroup_member`: Hupata uanachama wa kundi la ndani kwa kundi lililobainishwa kwenye computer ya ndani au remote, na kuruhusu enumeration ya watumiaji katika makundi mahususi.
- `net_shares`: Huorodhesha shares za remote na ufikikaji wake kwenye computer iliyobainishwa, na kusaidia kutambua malengo yanayowezekana kwa lateral movement.
- `socks`: Huwasha proxy inayotii SOCKS 5 kwenye mtandao lengwa, na kuruhusu tunneling ya traffic kupitia host iliyoathiriwa. Inaoana na zana kama proxychains.
- `rpfwd`: Huanza kusikiliza kwenye port iliyobainishwa kwenye host lengwa na kuelekeza traffic kupitia Mythic hadi IP na port ya remote, na kuruhusu ufikiaji wa mbali wa services kwenye mtandao lengwa.
- `listpipes`: Huorodhesha named pipes zote kwenye mfumo wa ndani, ambazo zinaweza kusaidia lateral movement au privilege escalation kupitia kuingiliana na mifumo ya IPC.

Kwa primitive za kiwango cha chini za WMI execution zinazotumiwa na `jump_wmi` au `wmiexecute`, angalia [WmiExec](lateral-movement/wmiexec.md). Kwa mifumo mipana zaidi ya pivoting, angalia [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Commands Mbalimbali
- `help`: Huonyesha maelezo ya kina kuhusu commands mahususi au maelezo ya jumla kuhusu commands zote zinazopatikana kwenye agent.
- `clear`: Huweka tasks kuwa 'cleared' ili agents zisiweze kuzichukua. Unaweza kubainisha `all` ili kusafisha tasks zote au `task Num` ili kusafisha task mahususi.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon ni agent ya Golang inayocompile kuwa executables za **Linux na macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Maelezo ya sasa ya build/profile

- Build za sasa za Poseidon hulenga Linux na macOS kwenye `x86_64` na `arm64`.
- Miundo ya matokeo inayotumika inajumuisha executable za native pamoja na matokeo ya mtindo wa shared library kama `dylib` na `so`.
- Poseidon inasaidia `http`, `websocket`, `tcp`, na `dynamichttp`, na builders za sasa zina mipangilio ya multi-egress kama `egress_order` na viwango vya failover.
- Metadata ya uwezo wa sasa ya Poseidon pia inatangaza browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, na P2P, hivyo inaweza kufanya kazi kama pivot node halisi ya Linux/macOS badala ya remote shell rahisi tu.
- Chaguo za wakati wa build kama `proxy_bypass` na `garble` zinafaa kuchunguzwa unapohitaji tabia safi zaidi ya mtandao au obfuscation ya ziada ya Go binary.
- `pty` ni mojawapo ya amri mpya zenye manufaa zaidi kwa Linux/macOS, kwa kuwa hufungua PTY shirikishi na inaweza kufichua port upande wa Mythic kwa mwingiliano kamili zaidi wa terminal bila kutumia njia ya zamani ya `sleep 0` + SOCKS.
- Nyaraka za sasa za Poseidon zinavutia hasa kwa tradecraft inayohusu sana macOS: `jxa` huendesha JavaScript for Automation ndani ya memory, `screencapture` hunasa desktop ya mtumiaji aliyeingia, `clipboard_monitor` hutiririsha mabadiliko ya pasteboard, `execute_library` hupakia dylib ya ndani na kuita function kutoka humo, na `libinject` hulazimisha process ya mbali kupakia dylib iliyo kwenye diski.
- Kwa kazi zinazoendelea kwa muda mrefu, kumbuka kuwa Poseidon huendesha kazi za post-exploitation katika goroutines/threads zinazoshirikiana badala ya kuweza kusimamishwa kwa nguvu. Nyaraka pia zinasema wazi kuwa kwa sasa hakuna obfuscation ya agent iliyojengewa ndani, kwa hiyo tradecraft ya kiwango cha build/profile ina umuhimu zaidi kuliko ilivyo kwa implants za kibiashara zilizofanyiwa obfuscation nzito.

Kwa tradecraft mahususi ya macOS kuhusu shughuli zinazotumia Mythic, matumizi mabaya ya JAMF, au mawazo ya MDM-as-C2, angalia [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Inapotumika kwenye Linux au macOS, ina baadhi ya amri za kuvutia:

### Vitendo vya kawaida

- `cat`: Chapisha yaliyomo kwenye faili
- `cd`: Badilisha working directory ya sasa
- `chmod`: Badilisha ruhusa za faili
- `config`: Tazama config ya sasa na taarifa za host
- `cp`: Nakili faili kutoka eneo moja hadi jingine
- `curl`: Tekeleza ombi moja la web ukiwa na headers na method za hiari
- `upload`: Pakia faili kwenye target
- `download`: Pakua faili kutoka kwenye mfumo wa target hadi kwenye mashine ya ndani
- Na mengine mengi

### Tafuta taarifa nyeti

- `triagedirectory`: Tafuta faili zinazovutia ndani ya directory kwenye host, kama faili nyeti au credentials.
- `getenv`: Pata environment variables zote za sasa.

### Tradecraft mahususi ya macOS

- `jxa`: Tekeleza JavaScript for Automation ndani ya memory kupitia `OSAScript`, jambo linalofaa kwa post-exploitation ya native ya macOS bila kuweka faili tofauti za script.
- `clipboard_monitor`: Kagua pasteboard na kuripoti mabadiliko kwa Mythic, jambo linalofaa kwa workflows za wizi wa credentials/token zinazotegemea copy/paste.
- `screencapture`: Nasa desktop ya mtumiaji kwenye macOS.
- `execute_library`: Pakia dylib kutoka kwenye diski na uite function maalum iliyofanyiwa export.
- `libinject`: Ingiza stub ya shellcode inayolazimisha process nyingine ya macOS kupakia dylib kutoka kwenye diski.
- `persist_launchd`: Unda persistence ya LaunchAgent / LaunchDaemon moja kwa moja kutoka kwa agent.

### Sogea kwa upande

- `ssh`: Tumia SSH kuingia kwenye host kwa credentials zilizobainishwa na ufungue PTY bila kuanzisha ssh.
- `sshauth`: Tumia SSH kuingia kwenye host(s) zilizobainishwa kwa credentials zilizobainishwa. Unaweza pia kutumia hii kutekeleza amri maalum kwenye host za mbali kupitia SSH au kutumia SCP kunakili faili.
- `link_tcp`: Unganisha na agent nyingine kupitia TCP, kuruhusu mawasiliano ya moja kwa moja kati ya agents.
- `link_webshell`: Unganisha na agent kwa kutumia webshell P2P profile, kuruhusu ufikiaji wa mbali wa web interface ya agent.
- `rpfwd`: Anzisha au simamisha Reverse Port Forward, ili kuruhusu ufikiaji wa mbali wa services kwenye mtandao wa target.
- `socks`: Anzisha au simamisha proxy ya SOCKS5 kwenye mtandao wa target, ili kuruhusu traffic kupitishwa kupitia host iliyoathiriwa. Inaoana na zana kama proxychains.
- `portscan`: Changanua host(s) kutafuta ports zilizo wazi, jambo linalofaa kutambua targets zinazowezekana za lateral movement au mashambulizi zaidi.

### Utekelezaji wa process

- `shell`: Tekeleza amri moja ya shell kupitia /bin/sh, ili kuruhusu utekelezaji wa moja kwa moja wa amri kwenye mfumo wa target.
- `run`: Tekeleza amri kutoka kwenye diski pamoja na arguments, ili kuruhusu utekelezaji wa binaries au scripts kwenye mfumo wa target.
- `pty`: Fungua PTY shirikishi, ili kuruhusu mwingiliano wa moja kwa moja na shell kwenye mfumo wa target.

## References

- [1] [Matrix ya Vipengele vya Mythic Community Agent](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README ya Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Vivutio vya Mythic v3.2: Interactive Tasking, Push C2, na Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Nyaraka za Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mabadiliko ya Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Kuboresha Red Team Ops kwa kutumia Vipengele Vilivyofichika vya Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Sheria za YARA za Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Kutoka Fork hadi Framework: Mambo Tuliyojifunza Kuhusu Agent Invasion kwa Kurekebisha Apollo](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
