# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Wigo

Implant baada ya compromise inaweza kupakia signed kernel driver kama service na kutoa control plane ya user-mode kupitia `IRP_MJ_DEVICE_CONTROL`. Driver signing huthibitisha tu kwamba Windows inakubali image; haihakikishi kwamba uidhinishaji wa IOCTL, shughuli za memory, callbacks, au hooks ni salama. Rootkit moja iliyochanganuliwa ilitumia handlers tatu wakati wa utendaji wa kawaida, lakini ilitoa primitives nyingine nyingi za post-exploitation. Kwa hiyo, reverse engineering lazima ichunguze dispatcher nzima, si maombi tu yaliyoonekana kwenye rekodi ya malware.<sup>[[1]](#references)</sup>

## Uchunguzi wa awali wa signed-driver na IOCTL

Anza kwenye `DriverEntry`, andika device objects na DOS symbolic links, tafuta routine ya `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, kisha tambua kila ulinganisho/ingizo la jedwali linaloelekeza kwenye handler. Linganisha majina yanayofunguliwa na user mode na majina yanayoundwa na driver: kwenye mnyororo mmoja ulioonekana, programu ilifungua `\\.\msagent`, huku driver yake ikiunda `\Device\ToolTool` na `\DosDevices\ToolTool`. Kutolingana huku kunaweza kuonyesha sample/configuration nyingine, logic ya setup inayokosekana, au kutolingana kwa uchanganuzi.<sup>[[1]](#references)</sup>

Decode kila control code kabla ya kuunda upya input structure yake.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Misimbo hii mitatu inasimbuliwa kama `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, na `METHOD_BUFFERED`. Hii **haithibitishi** kwamba mpigaji asiye na mamlaka anaweza kuzifikia: kagua pia DACL ya kifaa, dispatch ya create/open, ukaguzi wa mpigaji kwa kila ombi, urefu unaotarajiwa wa buffer, embedded pointers, ushughulikiaji wa muda wa PID, na iwapo handler inaamini PID au flag iliyotolewa na mpigaji.<sup>[[1]](#references)</sup>

Implant inapotumia sehemu tu ya amri, panga handlers zilizosalia kwa primitive badala ya kuzipuuza kama code isiyotumika. Driver moja yenye kazi nyingi imefichua aina zote zifuatazo:<sup>[[1]](#references)</sup>

- **Udhibiti/us sanidi:** kuwasha au kuzima hali ya rootkit; kuongeza, kuondoa, kuuliza kuhusu, au kufuta njia, michakato, na anwani za C2 zinazolindwa.
- **Udanganyifu wa mchakato:** kusitisha PID, ku-unmap image yake, kuingiza kwa kutumia `NtCreateThreadEx`, kuficha/kurejesha michakato au user modules, na kuondoa ulinzi wa PPL.
- **Udanganyifu wa kernel:** kuondoa driver iliyopakiwa kwenye orodha, kuorodhesha/kuzima/kurejesha notification callbacks, ku-map driver nyingine mwenyewe, na kuandika kwenye anwani yoyote ya kernel.
- **Udanganyifu wa object:** kufuta/kusimbua faili na kuunda au kurekebisha thamani za registry.

## Ku-map kernel kwa mikono kupitia driver iliyosainiwa iliyo hatarini

Driver iliyosainiwa yenye operesheni za kusoma/kuandika kumbukumbu ya kernel inaweza kutumika kupakia image ya driver ambayo haijasainiwa, bila kuiomba Windows ipakie image hiyo kama driver ya kawaida.<sup>[[2]](#references)[[7]](#references)</sup> Mfano wa LocalStranger hufungua kifaa kilichopo cha `\\.\WinNotify`; source yake haionyeshi kwamba mtumiaji asiye na mamlaka anaweza kusakinisha, kuwasha, au kufungua driver hiyo kwenye host yoyote.<sup>[[2]](#references)[[3]](#references)</sup> Mapper hupokea njia ya image, hutafuta base ya kernel iliyopakiwa, na hutumia IOCTL za kifaa za kusoma/kuandika virtual memory.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Ili kubadilisha ufikiaji huo wa kusoma/kuandika kuwa mwito wa kernel, mapper husoma immediate ya PTE-base kutoka `MmGetVirtualForPhysical` na kupitia entries za paging zinazofunika `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Hesabu yake ya PTE ni `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; code pia hukagua kama kuna large-page PDE.<sup>[[5]](#references)[[7]](#references)</sup> Hufanya entry inayofunika eneo hilo iwe writable kwa muda, hubadilisha syscall entry iwe jump kuelekea kernel function inayotakiwa, huita user-mode `NtAddAtom` stub, kisha hurejesha bytes na page entry za awali.<sup>[[6]](#references)</sup>

Mapper hutumia njia hiyo ya mwito kwa `ExAllocatePool`, hu-map PE sections, imports na relocations ndani ya image, huiandika kwenye allocation, kisha huita entry point yake.<sup>[[7]](#references)[[8]](#references)</sup> Utekelezaji huu unakubali PE images za x64 zinazoweza kuhamishwa pekee; usomaji wake wa PTE-base pia hudhani mpangilio usiobadilika wa `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Ichukulie kama inayotegemea build, si KASLR bypass inayojitegemea wala uthibitisho kwamba HVCI au PatchGuard huruhusu mapping hiyo.<sup>[[5]](#references)[[8]](#references)</sup> Kwa matumizi ya kernel R/W yanayohusu data pekee, tazama [wizi wa SYSTEM token](arbitrary-kernel-rw-token-theft.md).

## Misamaha kwa michakato inayoaminika

Muundo muhimu ni IOCTL inayosajili PID pamoja na flag ya **trusted**. Utafutaji huohuo wa trust hutumiwa na vichujio vya faili, registry, mchakato, na thread: zana zisizoaminika hupokea matokeo yaliyochujwa ya enumeration, ruhusa chache za handle, au `STATUS_ACCESS_DENIED`, huku implant ikiendelea kusasisha objects zake zilizofichwa. Ichukulie hii kama mpaka wa idhini na uhakikishe jinsi entries zinavyothibitishwa, kusawazishwa, na kuondolewa baada ya mchakato kutoka au PID kutumika tena.<sup>[[1]](#references)</sup>

Rootkits zinaweza kuhifadhi sera kwenye thamani za `REG_MULTI_SZ` na kukusanya orodha za faili, directory, registry-key, registry-value, ignored-image, protected-image, na hidden-image kuwa AVL trees. Wakati wa uchanganuzi, fuatilia kila msomaji na mwandishi wa trees hizi za pamoja; huunganisha usanidi wa registry, IOCTL, callbacks, na mantiki ya uchujaji hata majina ya functions yanapoondolewa.<sup>[[1]](#references)</sup>

## Kuficha michakato na modules kwa DKOM

### `EPROCESS.ActiveProcessLinks`

Offsets za `ActiveProcessLinks` hutofautiana kulingana na Windows build. Rootkit inayostahimili matoleo tofauti inaweza kujaribu offsets zinazojulikana, kisha kutafuta ndani ya `EPROCESS` `LIST_ENTRY` inayojithibitisha, ambayo majirani zake hurejelea candidate hiyo. Huhifadhi offset iliyopatikana, huficha mchakato kwa kuunganisha upya `Flink`/`Blink` za majirani zake, na huhifadhi hali ili iweze kuunganisha entry hiyo tena baadaye. Mchakato huendelea kufanya kazi lakini hutoweka kwenye enumerators zinazopitia orodha ya michakato inayoendelea.<sup>[[1]](#references)</sup>

Hii ni **DKOM**, si kusitisha mchakato. Ugunduzi unapaswa kulinganisha matokeo ya orodha na ushahidi huru kama vile ukaguzi wa pool/object, umiliki wa thread, handle tables, alama za scheduler, na ukaguzi wa kumbukumbu ya kernel. Mchakato unaoonekana kwenye scan lakini haupo kwenye orodha ya msingi una maana zaidi kuliko mojawapo ya mitazamo hiyo peke yake.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Primitive sawia ya kuficha module hupata entry lengwa ndani ya `PsLoadedModuleList` na kubadilisha pointers za `Flink`/`Blink` za entries zilizo karibu. Driver hubaki ikiwa ime-map na inaweza kutekelezwa, lakini module queries zinazotegemea orodha hazionyeshi. Linganisha orodha ya loader na kernel mappings zinazoweza kutekelezwa, pool tags, device/driver objects, service keys, anwani za callbacks, na dispatch pointers zinazoelekeza nje ya image iliyo kwenye orodha.<sup>[[1]](#references)</sup>

## Ulinzi na ufichaji unaotegemea callback

Rootkit inaweza kuchanganya callback frameworks zilizorekodiwa na DKOM pamoja na hooks:<sup>[[1]](#references)</sup>

- Handlers za pre-operation za `ObRegisterCallbacks` kwa `PsProcessType` na `PsThreadType` huondoa ruhusa zinazotumika kusitisha, kufikia VM, kunakili, au kudanganya thread wakati mpigaji asiyeaminika anafungua target inayolindwa. Rekodi callback altitude na tambua module inayomiliki kila anwani ya callback.
- `PsSetCreateProcessNotifyRoutineEx` na `PsSetLoadImageNotifyRoutine` hudumisha hali ya michakato iliyolindwa/iliyopuuzwa/iliyofichwa kadri michakato na images zinavyojitokeza; kutembea mara moja kwenye michakato kunaweza kujaza objects zilizokuwepo kabla ya usajili.
- Minifilter ya filesystem huzuia ufikiaji wa njia zilizosanidiwa. Utekelezaji usio wa kawaida unaweza kuunda key yake ya `Instances`, kuchagua altitude kwa nguvu, na kuongeza thamani/kujaribu tena `FltRegisterFilter` inaporipoti mgongano.
- Routine ya `CmRegisterCallbackEx` inaweza kuficha majina yaliyolindwa kwenye enumeration na kukataa open, rename, set, au delete ya moja kwa moja, huku ikitoa msamaha kwa michakato inayoaminika iliyosajiliwa.

Linganisha usajili wa `ObRegisterCallbacks`, registry-callback altitudes, matokeo ya `fltmc filters`, service `Instances` keys, na anwani za callbacks. Ikiwa tools za kawaida zinachujwa, kagua miundo hii kutoka kwenye offline memory image au njia nyingine ya kuaminika ya kupata data.<sup>[[1]](#references)</sup>

## Uchujaji wa matokeo ya Nsiproxy

Ufichaji wa mtandao unaweza kulenga `\Driver\Nsiproxy`: pata driver object kwa `ObReferenceObjectByName`, hifadhi handler pointer, ibadilishe na wrapper, kisha uondoe rekodi za IPv4 zinazolingana na orodha ya C2 inayodhibitiwa na IOCTL kabla user mode haijazipokea. Huenda applications zinazotegemea data iliyochujwa ya NSI zisionyeshe tena connection ingawa trafiki bado ipo.<sup>[[1]](#references)</sup>

Linganisha mitazamo ya host kuhusu connections na packet capture, WFP/ETW telemetry, na network objects za kumbukumbu ya kernel. Kagua pia dispatch/handler pointers za `Nsiproxy` na uthibitishe kwamba kila moja inaelekea ndani ya signed module inayotarajiwa; pointer inayoelekea kwenye mapping isiyoorodheshwa inaweza kuunganisha uchujaji wa mtandao na DKOM ya `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Orodha hakiki ya uchunguzi

Ishara yenye nguvu zaidi ni kutokubaliana kati ya tabaka, si jina moja la faili au hash. Linganisha:<sup>[[1]](#references)</sup>

1. Uundaji wa kernel-service na driver iliyosainiwa ambayo umri wa certificate, publisher, au njia yake haiendani na bidhaa iliyosakinishwa.
2. Uundaji wa device, DOS links, na trafiki ya IOCTL, ikiwemo majina ya device ya user mode na kernel yasiyolingana.
3. Ombi la kusajili PID likifuatiwa na michakato mingine kushindwa kufungua, kuorodhesha, kurekebisha, au kufuta objects zilezile.
4. Object/registry/process/image callbacks, minifilter instances, na hooks ambazo anwani zake hazimilikiwi na driver iliyoorodheshwa kawaida.
5. Tofauti kati ya orodha zinazotegemea list na scan za michakato, modules, callbacks, na inventories za mtandao.

## References

- [1] [Kaspersky Securelist - HoneyMyte huboresha CoolClient kwa Windows Kernel Rootkit iliyosainiwa](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README ya LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Uanzishaji wa driver ya LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Command line ya mapper ya LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Utatuzi wa kernel exports na PTE-base wa LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Kernel-call trampoline ya LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Uallocation wa mapper na mwito wa entry wa LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [PE mapping ya LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Muktadha wa kernel na syscall wa LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappers za virtual-memory IOCTL za LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
