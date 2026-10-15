# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Omvang

’n Implantaat ná kompromittering kan ’n getekende kernel driver as ’n diens laai en ’n user-mode-beheerlaag via `IRP_MJ_DEVICE_CONTROL` beskikbaar stel. Driver-ondertekening bevestig slegs dat Windows die beeld aanvaar; dit maak nie die IOCTL-magtiging, geheuebewerkings, callbacks of hooks veilig nie. Een ontlede rootkit het drie handlers tydens normale werking gebruik, maar dosyne bykomende post-exploitation-primitiewe beskikbaar gestel. Daarom moet reverse engineering die volledige dispatcher dek, nie net die versoeke wat in ’n malware-trace waargeneem is nie.<sup>[[1]](#references)</sup>

## Triage van getekende drivers en IOCTL's

Begin by `DriverEntry`, teken device objects en DOS-simboliese skakels aan, spoor die `MajorFunction[IRP_MJ_DEVICE_CONTROL]`-roetine op, en karteer elke vergelyking/tabelinskrywing wat na ’n handler lei. Vergelyk die name wat deur user mode oopgemaak word met die name wat die driver werklik skep: een waargenome ketting het `\\.\msagent` oopgemaak, terwyl sy driver `\Device\ToolTool` en `\DosDevices\ToolTool` geskep het. Hierdie teenstrydigheid kan op ’n ander sample/configurasie, ontbrekende opstellogika of ’n teenstrydigheid in die ontleding dui.<sup>[[1]](#references)</sup>

Dekodeer elke beheer-kode voordat jy die insetstruktuur rekonstrueer.<sup>[[1]](#references)</sup>

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

Hierdie drie kodes dekodeer as `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` en `METHOD_BUFFERED`. Dit **bewys nie** dat ’n ongeprivilegieerde caller hulle kan bereik nie: ondersoek ook die device-DACL, create/open-dispatch, caller-kontroles per versoek, verwagte bufferlengtes, ingebedde pointers, PID-leeftydhantering, en of die handler ’n PID of vlag vertrou wat deur die caller verskaf is.<sup>[[1]](#references)</sup>

Wanneer die implant slegs ’n subset van opdragte gebruik, groepeer die oorblywende handlers volgens primitive eerder as om hulle as dooie kode af te maak. Een multifunksie-driver het al die volgende klasse blootgestel:<sup>[[1]](#references)</sup>

- **Beheer/konfigurasie:** skakel rootkit-toestand aan of af; voeg beskermde paaie, prosesse en C2-adresse by, verwyder hulle, vra daaroor navraag of maak hulle skoon.
- **Prosesmanipulasie:** beëindig ’n PID, ontmap sy image, injecteer met `NtCreateThreadEx`, versteek/herstel prosesse of user-modules, en verwyder PPL-beskerming.
- **Kernel-manipulasie:** unlink ’n gelaaide driver, lys/deaktiveer/herstel notification callbacks, map ’n ander driver handmatig, en skryf na ’n arbitrêre kernel-adres.
- **Objekmanipulasie:** verwyder/dekripteer lêers en skep of wysig registry-waardes.

## Handmatige kernel-mapping deur ’n kwesbare ondertekende driver

’n Ondertekende driver met kernel-memory lees-/skryfbewerkings kan ’n loader vir ’n ongetekende driver-image bied sonder om Windows te vra om daardie image as ’n gewone driver te laai.<sup>[[2]](#references)[[7]](#references)</sup> Die LocalStranger-voorbeeld maak ’n bestaande `\\.\WinNotify`-device oop; sy bronkode wys nie dat ’n ongeprivilegieerde user die driver op ’n arbitrêre host kan installeer, begin of oopmaak nie.<sup>[[2]](#references)[[3]](#references)</sup> Die mapper neem ’n image-pad, bepaal die base van die gelaaide kernel en gebruik die device se virtual-memory lees-/skryf-IOCTL’s.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Om daardie lees-/skryftoegang in ’n kernel-aanroep te omskep, lees die mapper ’n PTE-base-immediate vanaf `MmGetVirtualForPhysical` en loop deur die paging-inskrywings wat `NtAddAtom` dek.<sup>[[5]](#references)[[7]](#references)</sup> Sy PTE-berekening is `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; die kode kontroleer ook vir ’n large-page PDE.<sup>[[5]](#references)[[7]](#references)</sup> Dit maak die inskrywing wat die bladsy dek tydelik skryfbaar, vervang die syscall-inskrywing met ’n jump na die verlangde kernelfunksie, roep die user-mode `NtAddAtom`-stub aan en herstel dan beide die oorspronklike grepe en die page-inskrywing.<sup>[[6]](#references)</sup>

Die mapper gebruik daardie aanroeppad vir `ExAllocatePool`, map PE-seksies, imports en relocations in die image, skryf dit na die allocation en roep sy entry point aan.<sup>[[7]](#references)[[8]](#references)</sup> Hierdie implementering aanvaar slegs x64, relocatable PE-images; sy PTE-base-lesing neem ook ’n vaste `MmGetVirtualForPhysical + 34`-uitleg aan.<sup>[[5]](#references)[[8]](#references)</sup> Beskou dit as build-afhanklik, nie as ’n onafhanklike KASLR-bypass of bewys dat HVCI of PatchGuard die mapping toelaat nie.<sup>[[5]](#references)[[8]](#references)</sup> Sien [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md) vir ’n data-only gebruik van kernel R/W.

## Uitsonderings vir trusted prosesse

’n Nuttige ontwerppatroon is ’n IOCTL wat ’n PID plus ’n **trusted**-vlag registreer. Dieselfde trust-opsoek word dan deur file-, registry-, process- en thread-filters geraadpleeg: untrusted tools ontvang gefiltreerde enumerasie-resultate, verminderde handle-regte of `STATUS_ACCESS_DENIED`, terwyl die implant steeds sy eie versteekte objekte kan bywerk. Beskou dit as ’n magtigingsgrens en verifieer hoe inskrywings geverifieer, gesinchroniseer en ná proses-exit of PID-hergebruik verwyder word.<sup>[[1]](#references)</sup>

Rootkits kan beleid in `REG_MULTI_SZ`-waardes behou en lyste van lêers, directories, registry-sleutels, registry-waardes, geïgnoreerde images, beskermde images en versteekte images in AVL-bome saamstel. Volg tydens analise elke leser en skrywer van hierdie gedeelde bome; dit koppel registry-konfigurasie, IOCTL’s, callbacks en filtering-logika, selfs wanneer funksiename verwyder is.<sup>[[1]](#references)</sup>

## DKOM-proses- en module-verberging

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks`-offsets wissel tussen Windows-builds. ’n Weergaweverdraagsame rootkit kan bekende kandidate toets en dan `EPROCESS` deursoek vir ’n selfkonsekwente `LIST_ENTRY` waarvan die bure na die kandidaat terugwys. Dit behou die ontdekte offset, versteek ’n proses deur sy bure se `Flink`/`Blink` weer te koppel, en bewaar toestand om die inskrywing later weer te skakel. Die proses bly loop, maar verdwyn uit enumerators wat die active-process-lys deurloop.<sup>[[1]](#references)</sup>

Dit is **DKOM**, nie beëindiging nie. Opsporing behoort resultate wat op lyste gebaseer is met onafhanklike bewyse te vergelyk, soos pool-/object-scans, thread-eienaarskap, handle-tabelle, scheduler-artefakte en kernel-memory-inspeksie. ’n Proses wat in ’n scan sigbaar is maar uit die kanonieke lys ontbreek, is betekenisvoller as enigeen van die twee aansigte op sy eie.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Die ooreenstemmende module-verbergingsprimitive vind die teikeninskrywing in `PsLoadedModuleList` en patch aangrensende `Flink`/`Blink`-pointers. Die driver bly gemap en uitvoerbaar, maar module-navrae wat op die lys staatmaak, laat dit weg. Vergelyk die loader-lys met uitvoerbare kernel-mappings, pool-tags, device-/driver-objekte, service-sleutels, callback-adresse en dispatch-pointers wat buite ’n gelysde image uitkom.<sup>[[1]](#references)</sup>

## Callback-gebaseerde beskerming en cloaking

’n Rootkit kan gedokumenteerde callback-frameworks met DKOM en hooks kombineer:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation-handlers vir `PsProcessType` en `PsThreadType` verwyder regte wat vir beëindiging, VM-toegang, duplisering of thread-manipulasie gebruik word wanneer ’n untrusted caller ’n beskermde teiken oopmaak. Teken die callback-altitude aan en bepaal aan watter module elke callback-adres behoort.
- `PsSetCreateProcessNotifyRoutineEx` en `PsSetLoadImageNotifyRoutine` hou beskermde/geïgnoreerde/versteekte prosestoestand by soos prosesse en images verskyn; ’n eenmalige prosesdeursoeking kan objekte invul wat reeds voor registrasie bestaan het.
- ’n Filesystem-minifilter weier toegang tot gekonfigureerde paaie. ’n Ongewone implementering kan sy `Instances`-sleutel skep, ’n altitude dinamies kies en dit verhoog/herprobeer wanneer `FltRegisterFilter` ’n botsing rapporteer.
- ’n `CmRegisterCallbackEx`-roetine kan beskermde name uit enumerasie onderdruk en direkte oopmaak-, hernoem-, stel- of verwyderbewerkings weier, terwyl geregistreerde trusted prosesse uitgesonder word.

Korrelleer `ObRegisterCallbacks`-registrasies, registry-callback-altitudes, `fltmc filters`-afvoer, service-`Instances`-sleutels en callback-adresse. As normale tools gefiltreer word, ondersoek hierdie strukture vanuit ’n offline memory-image of ’n ander trusted verkrygingslaag.<sup>[[1]](#references)</sup>

## Nsiproxy-resultaatfiltrering

Netwerkverberging kan `\Driver\Nsiproxy` teiken: verkry die driver-object met `ObReferenceObjectByName`, stoor ’n handler-pointer, vervang dit met ’n wrapper en verwyder IPv4-rekords wat met ’n IOCTL-beheerde C2-lys ooreenstem voordat user mode hulle ontvang. Toepassings wat op die gefiltreerde NSI-data steun, vertoon moontlik nie meer die verbinding nie, al bestaan die verkeer steeds.<sup>[[1]](#references)</sup>

Vergelyk host-verbindingsaansigte met packet capture, WFP/ETW-telemetrie en kernel-memory-netwerkobjekte. Ondersoek ook `Nsiproxy`-dispatch-/handler-pointers en bevestig dat elkeen binne die verwagte ondertekende module resolve; ’n pointer na ’n ongelyste mapping kan netwerkfiltrering met `PsLoadedModuleList`-DKOM verbind.<sup>[[1]](#references)</sup>

## Ondersoekkontrolelys

Die sterkste sein is teenstrydigheid tussen lae, nie een lêernaam of hash nie. Korrelleer:<sup>[[1]](#references)</sup>

1. Kernel-service-skepping en ’n ondertekende driver waarvan die sertifikaatouderdom, uitgewer of pad nie met die geïnstalleerde produk ooreenstem nie.
2. Device-skepping, DOS-links en IOCTL-verkeer, insluitend verskille tussen user-mode- en kernel-device-name.
3. ’n PID-registrasieversoek gevolg deur mislukkings wanneer ander prosesse probeer om dieselfde objekte oop te maak, te enumeriseer, te wysig of te verwyder.
4. Object-/registry-/process-/image-callbacks, minifilter-instances en hooks waarvan die adresse nie aan ’n normaal geënumeerde driver behoort nie.
5. Verskille tussen lysgebaseerde en scan-gebaseerde inventarisse van prosesse, modules, callbacks en netwerke.

## References

- [1] [Kaspersky Securelist - HoneyMyte verbeter CoolClient met ’n ondertekende Windows-kernel-rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger-driver-initialisering](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger-mapper-opdragreël](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger-kern uitvoer- en PTE-base-resolusie](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger-kernel-aanroep-trampoline](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger-mapper-toekenning en entry-aanroep](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger-PE-mapping](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger-kernel- en syscall-konteks](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger-virtual-memory-IOCTL-wrappers](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
