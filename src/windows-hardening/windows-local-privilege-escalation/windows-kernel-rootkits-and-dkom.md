# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Wigo

A post-compromise implant inaweza kupakia signed kernel driver kama service na kuwasilisha user-mode control plane kupitia `IRP_MJ_DEVICE_CONTROL`. Driver signing huonyesha tu kwamba Windows inakubali image; haimaanishi kwamba IOCTL authorization, memory operations, callbacks, au hooks ni salama. Rootkit moja iliyochanganuliwa ilitumia handlers tatu wakati wa uendeshaji wa kawaida, lakini iliweka wazi primitives kadhaa za ziada za post-exploitation, hivyo reverse engineering lazima ihusishe dispatcher nzima badala ya maombi yaliyobainika tu katika malware trace.<sup>[[1]](#references)</sup>

## Signed-driver na IOCTL triage

Anza kwenye `DriverEntry`, rekodi device objects na DOS symbolic links, tafuta routine ya `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, na ramani kila comparison/table entry inayofikia handler. Linganisha majina yanayofunguliwa na user mode na majina yanayoundwa hasa na driver: chain moja iliyobainika ilifungua `\\.\msagent`, wakati driver yake iliunda `\Device\ToolTool` na `\DosDevices\ToolTool`. Mismatch hii inaweza kutambua sample/configuration nyingine, setup logic iliyokosekana, au inconsistency ya analysis.<sup>[[1]](#references)</sup>

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
Misimbo hii mitatu inadecode kuwa `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, na `METHOD_BUFFERED`. Hilo **halithibitishi** kwamba caller asiye na privileges anaweza kuzifikia: pia kagua device DACL, create/open dispatch, ukaguzi wa caller kwa kila request, urefu unaotarajiwa wa buffer, pointers zilizopachikwa, ushughulikiaji wa muda wa maisha wa PID, na ikiwa handler inaamini PID au flag iliyotolewa na caller.<sup>[[1]](#references)</sup>

Implant inapotumia subset tu ya commands, panga handlers zilizobaki kulingana na primitive badala ya kuzipuuza kama dead code. Driver moja ya multifunction imefichua madarasa yote yafuatayo:<sup>[[1]](#references)</sup>

- **Control/configuration:** badilisha hali ya rootkit; ongeza, ondoa, uliza, au futa paths, processes, na C2 addresses zilizolindwa.
- **Process manipulation:** terminate PID, unmap image yake, inject kwa `NtCreateThreadEx`, ficha/rejesha processes au user modules, na ondoa PPL protection.
- **Kernel manipulation:** unlink driver iliyopakiwa, enumerate/disable/restore notification callbacks, manually map driver nyingine, na andika kwenye kernel address yoyote.
- **Object manipulation:** delete/decrypt files na create au modify registry values.

## Trusted-process exemptions

Design pattern muhimu ni IOCTL inayosajili PID pamoja na flag ya **trusted**. Lookup hiyo hiyo ya trust hutumiwa na file, registry, process, na thread filters: tools zisizo trusted hupokea matokeo ya enumeration yaliyofilteriwa, handle rights zilizopunguzwa, au `STATUS_ACCESS_DENIED`, huku implant ikiendelea kusasisha objects zake zilizofichwa. Ichukulie hii kama authorization boundary na uhakikishe jinsi entries zinavyothibitishwa, kusawazishwa, na kuondolewa baada ya process kutoka au PID kutumika tena.<sup>[[1]](#references)</sup>

Rootkits zinaweza kuhifadhi policy katika values za `REG_MULTI_SZ` na kucompile lists za file, directory, registry-key, registry-value, ignored-image, protected-image, na hidden-image kuwa AVL trees. Wakati wa analysis, fuatilia kila reader na writer wa shared trees hizi; inaunganisha registry configuration, IOCTLs, callbacks, na filtering logic hata function names zinapokuwa zimeondolewa.<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

Offsets za `ActiveProcessLinks` hutofautiana kulingana na Windows build. Rootkit inayostahimili mabadiliko ya version inaweza kujaribu candidates zinazojulikana, kisha iscan `EPROCESS` kutafuta `LIST_ENTRY` yenye uthabiti wa ndani ambayo neighbors zake zinaelekeza tena kwenye candidate. Huhifadhi offset iliyogunduliwa, huficha process kwa kuunganisha upya `Flink`/`Blink` za neighbors zake, na huhifadhi state ili kuunganisha entry hiyo tena baadaye. Process huendelea kufanya kazi lakini hutoweka kwenye enumerators zinazotembea kwenye active-process list.<sup>[[1]](#references)</sup>

Hii ni **DKOM**, si termination. Detection inapaswa kulinganisha matokeo ya list na ushahidi huru kama pool/object scans, thread ownership, handle tables, scheduler artifacts, na kernel memory inspection. Process inayoonekana kwenye scan lakini haipo kwenye canonical list ina maana zaidi kuliko view yoyote kati ya hizo pekee.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Primitive inayolingana ya kuficha module hutafuta target entry katika `PsLoadedModuleList` na kurekebisha pointers za `Flink`/`Blink` zilizo karibu. Driver hubaki ikiwa imepakiwa na inaweza kutekelezwa, lakini module queries zinazotegemea list haziiingizi. Linganisha loader list na executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses, na dispatch pointers zinazoelekea nje ya image iliyoorodheshwa.<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

Rootkit inaweza kuunganisha callback frameworks zilizo documented na DKOM pamoja na hooks:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handlers za `PsProcessType` na `PsThreadType huondoa rights zinazotumiwa kwa termination, VM access, duplication, au thread manipulation wakati caller asiye trusted anafungua target iliyolindwa. Rekodi callback altitude na resolve kila callback address hadi module inayoimiliki.
- `PsSetCreateProcessNotifyRoutineEx` na `PsSetLoadImageNotifyRoutine` hudumisha hali ya protected/ignored/hidden process wakati processes na images zinapoonekana; process walk ya mara moja inaweza kujaza objects zilizokuwepo kabla ya registration.
- Filesystem minifilter inakataa access kwenye paths zilizosanidiwa. Implementation isiyo ya kawaida inaweza kuunda key yake ya `Instances`, kuchagua altitude dynamically, na kuongeza/retry wakati `FltRegisterFilter` inaporipoti collision.
- Routine ya `CmRegisterCallbackEx` inaweza kuficha protected names kutoka enumeration na kukataa direct open, rename, set, au delete operations huku ikiwaruhusu registered trusted processes.

Correlate `ObRegisterCallbacks` registrations, registry-callback altitudes, output ya `fltmc filters`, service `Instances` keys, na callback addresses. Ikiwa tools za kawaida zinafanyiwa filtering, kagua structures hizi kutoka offline memory image au trusted acquisition layer nyingine.<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment inaweza kulenga `\Driver\Nsiproxy`: pata driver object kwa `ObReferenceObjectByName`, hifadhi handler pointer, ibadilishe na wrapper, na uondoe IPv4 records zilizorejeshwa zinazolingana na C2 list inayodhibitiwa na IOCTL kabla user mode haijazipokea. Applications zinazotegemea filtered NSI data huenda zisionyeshe tena connection hata traffic ikiwa bado ipo.<sup>[[1]](#references)</sup>

Linganisha host connection views na packet capture, WFP/ETW telemetry, na kernel-memory network objects. Pia kagua `Nsiproxy` dispatch/handler pointers na uthibitishe kwamba kila moja ina-resolve ndani ya signed module inayotarajiwa; pointer inayoelekea kwenye mapping ambayo haijaorodheshwa inaweza kuunganisha network filtering na `PsLoadedModuleList` DKOM.<sup>[[1]](#references)</sup>

## Investigation checklist

Signal yenye nguvu zaidi ni kutokubaliana kati ya layers, si filename au hash moja. Correlate:<sup>[[1]](#references)</sup>

1. Uundaji wa kernel-service na signed driver ambaye umri wa certificate, publisher, au path yake haulingani na installed product.
2. Uundaji wa device, DOS links, na IOCTL traffic, ikijumuisha user-mode na kernel device names zisizolingana.
3. Request ya PID registration ikifuatiwa na failures kutoka processes nyingine za kufungua, kuenumerate, kurekebisha, au kufuta objects hizo hizo.
4. Object/registry/process/image callbacks, minifilter instances, na hooks ambazo addresses zake si za driver inayotajwa kwa kawaida.
5. Tofauti kati ya inventories za process, module, callback, na network zinazotegemea list na zile zinazotegemea scan.

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
