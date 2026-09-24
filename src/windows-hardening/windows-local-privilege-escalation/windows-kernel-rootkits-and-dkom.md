# Windows Kernel Rootkits en DKOM

{{#include ../../banners/hacktricks-training.md}}

## Omvang

’n post-compromise implant kan ’n signed kernel driver as ’n service laai en ’n user-mode control plane deur middel van `IRP_MJ_DEVICE_CONTROL` blootstel. Driver signing bevestig slegs dat Windows die image aanvaar; dit maak nie die IOCTL authorization, memory operations, callbacks of hooks veilig nie. Een geanaliseerde rootkit het drie handlers tydens normale werking gebruik, maar dosyne bykomende post-exploitation primitives blootgestel. Daarom moet reverse engineering die volledige dispatcher dek, eerder as slegs die requests wat in ’n malware trace waargeneem is.<sup>[[1]](#references)</sup>

## Signed-driver en IOCTL-triage

Begin by `DriverEntry`, teken device objects en DOS symbolic links aan, vind die `MajorFunction[IRP_MJ_DEVICE_CONTROL]`-routine, en karteer elke comparison/table entry wat ’n handler bereik. Vergelyk die name wat deur user mode oopgemaak word met die name wat werklik deur die driver geskep word: een waargenome chain het `\\.\msagent` oopgemaak, terwyl sy driver `\Device\ToolTool` en `\DosDevices\ToolTool` geskep het. Hierdie mismatch kan ’n ander sample/configuration, ontbrekende setup logic of ’n analysis inconsistency identifiseer.<sup>[[1]](#references)</sup>

Decode elke control code voordat jy die input structure rekonstrueer.<sup>[[1]](#references)</sup>
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
Hierdie drie kodes dekodeer as `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` en `METHOD_BUFFERED`. Dit **bewys nie** dat ’n onbevoorregte caller toegang daartoe kan verkry nie: ondersoek ook die device DACL, create/open dispatch, caller-kontroles per versoek, verwagte bufferlengtes, ingebedde pointers, PID-lifetime-hantering, en of die handler ’n PID of flag wat deur die caller verskaf is, vertrou.<sup>[[1]](#references)</sup>

Wanneer die implant slegs ’n subset van commands gebruik, groepeer die oorblywende handlers volgens primitive eerder as om hulle as dead code af te maak. ’n Enkele multifunksie-driver het al die volgende klasse blootgestel:<sup>[[1]](#references)</sup>

- **Control/configuration:** skakel rootkit-status; voeg beskermde paths, processes en C2 addresses by, verwyder, bevraagteken of maak hulle skoon.
- **Process manipulation:** beëindig ’n PID, unmap sy image, injecteer met `NtCreateThreadEx`, versteek/herstel processes of user modules, en verwyder PPL-protection.
- **Kernel manipulation:** unlink ’n gelaaide driver, enumerate/disable/herstel notification callbacks, map ’n ander driver handmatig, en skryf na ’n arbitrêre kernel-adres.
- **Object manipulation:** delete/decrypt files en skep of wysig registry values.

## Trusted-process exemptions

’n Nuttige design pattern is ’n IOCTL wat ’n PID plus ’n **trusted** flag registreer. Dieselfde trust lookup word dan deur file-, registry-, process- en thread-filters geraadpleeg: untrusted tools ontvang gefiltreerde enumeration-resultate, verminderde handle-regte of `STATUS_ACCESS_DENIED`, terwyl die implant steeds sy eie versteekte objects kan bywerk. Behandel dit as ’n authorization boundary en verifieer hoe entries geauthentiseer, gesinchroniseer en verwyder word ná process-exit of PID-hergebruik.<sup>[[1]](#references)</sup>

Rootkits kan policy in `REG_MULTI_SZ` values behou en file-, directory-, registry-key-, registry-value-, ignored-image-, protected-image- en hidden-image-lists in AVL trees saamstel. Tydens analysis, trace elke reader en writer van hierdie gedeelde trees; dit koppel registry-konfigurasie, IOCTLs, callbacks en filtering-logika, selfs wanneer funksiename gestroop is.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks`-offsets verskil volgens Windows-build. ’n Version-tolerant rootkit kan bekende candidates toets en dan `EPROCESS` scan vir ’n self-consistente `LIST_ENTRY` waarvan die neighbors terugwys na die candidate. Dit behou die ontdekte offset, versteek ’n process deur sy neighbors se `Flink`/`Blink` weer te verbind, en behou state om die entry later weer te link. Die process hou aan loop, maar verdwyn uit enumerators wat deur die active-process list loop.<sup>[[1]](#references)</sup>

Dit is **DKOM**, nie termination nie. Detection behoort list-gebaseerde resultate met onafhanklike evidence te vergelyk, soos pool/object-scans, thread ownership, handle tables, scheduler artifacts en kernel-memory inspection. ’n Process wat vir ’n scan sigbaar is maar uit die canonical list ontbreek, is betekenisvoller as enigeen van die twee views alleen.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Die ekwivalente module-hiding primitive vind die target entry in `PsLoadedModuleList` en patch aangrensende `Flink`/`Blink` pointers. Die driver bly gemap en uitvoerbaar, maar list-backed module queries laat dit weg. Vergelyk die loader list met executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses en dispatch pointers wat buite ’n gelyste image land.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

’n Rootkit kan gedokumenteerde callback-frameworks met DKOM en hooks kombineer:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handlers vir `PsProcessType` en `PsThreadType` verwyder regte wat vir termination, VM access, duplication of thread manipulation gebruik word wanneer ’n untrusted caller ’n protected target open. Teken die callback-altitude aan en resolve elke callback-adres na sy owning module.
- `PsSetCreateProcessNotifyRoutineEx` en `PsSetLoadImageNotifyRoutine` handhaaf protected/ignored/hidden process-state soos processes en images verskyn; ’n eenmalige process-walk kan objects wat voor registration bestaan het, backfill.
- ’n Filesystem minifilter weier toegang tot gekonfigureerde paths. ’n Ongewone implementasie kan sy `Instances`-key skep, ’n altitude dinamies kies, en dit verhoog/herprobeer wanneer `FltRegisterFilter` ’n collision rapporteer.
- ’n `CmRegisterCallbackEx`-routine kan protected names uit enumeration onderdruk en direkte open-, rename-, set- of delete-operasies weier, terwyl geregistreerde trusted processes vrygestel word.

Korrelleer `ObRegisterCallbacks`-registrations, registry-callback-altitudes, `fltmc filters`-output, service-`Instances`-keys en callback-addresses. Indien normale tools gefiltreer word, ondersoek hierdie structures vanuit ’n offline memory image of ’n ander trusted acquisition layer.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment kan `\Driver\Nsiproxy` teiken: verkry die driver-object met `ObReferenceObjectByName`, stoor ’n handler-pointer, vervang dit met ’n wrapper, en verwyder teruggestuurde IPv4-records wat met ’n IOCTL-managed C2-list ooreenstem voordat user mode dit ontvang. Applications wat deur die gefiltreerde NSI-data ondersteun word, sal moontlik nie meer die connection vertoon nie, al bestaan die traffic steeds.<sup>[[1]](#references)</sup>

Vergelyk host connection-views met packet capture, WFP/ETW-telemetry en kernel-memory-network-objects. Ondersoek ook `Nsiproxy` dispatch/handler-pointers en bevestig dat elkeen binne die verwagte signed module resolve; ’n pointer na ’n ongelyste mapping kan network filtering met `PsLoadedModuleList` DKOM verbind.<sup>[[1]](#references)</sup>

## Investigation checklist

Die sterkste signal is onenigheid tussen layers, nie een filename of hash nie. Korrelleer:<sup>[[1]](#references)</sup>

1. Kernel-service creation en ’n signed driver waarvan die certificate age, publisher of path nie met die geïnstalleerde product ooreenstem nie.
2. Device creation, DOS-links en IOCTL-traffic, insluitend mismatches tussen user-mode- en kernel-device-names.
3. ’n PID-registration-request gevolg deur failures van ander processes om dieselfde objects te open, enumerate, modify of delete.
4. Object/registry/process/image-callbacks, minifilter-instances en hooks waarvan die addresses nie aan ’n normaal geënumeerde driver behoort nie.
5. Verskille tussen list-based en scan-based inventories van processes, modules, callbacks en networks.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
