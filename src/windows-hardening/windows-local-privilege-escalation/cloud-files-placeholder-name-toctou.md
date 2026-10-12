# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Windows kernel driver husababisha double-fetch inapothibitisha data katika kurasa zinazotegemea caller na baadaye kupitisha pointer inayoelekeza kwenye kurasa hizo hizo kwa API nyeti kwa usalama. Kufunga na kumap kurasa hakufanyi yaliyomo yasiweze kubadilishwa. CVE-2025-55680 katika `cldflt.sys` inaonyesha muundo huu: driver ilithibitisha relative name ya Cloud Files placeholder, kisha ikaunda object huku ikiendelea kurejelea buffer inayoweza kubadilishwa na caller.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` huunda files au directories chini ya Cloud Files sync root iliyosajiliwa. Katika njia iliyo hatarini, kubadilisha jina baada ya uthibitishaji kungeweza kuelekeza uundaji wenye haki za juu nje ya root hiyo.<sup>[[1]](#references)[[2]](#references)</sup>

## Kwa nini kufunga kurasa hakukufunga data

Njia iliyo hatarini ya `HsmpOpCreatePlaceholders()` ilitenga MDL kwa payload ya caller, ikaita `ProbeForRead()` na `MmProbeAndLockPages()`, kisha ikamap kurasa hizo katika kernel virtual address space. MDL huelezea na kufunga kurasa halisi ili zibaki kwenye memory. **Haihifadhi nakala ya bytes zake.** Kwa hiyo user mode inaweza kurekebisha memory ileile halisi wakati driver inaisoma kupitia system mapping.<sup>[[1]](#references)[[3]](#references)</sup>

Njia husika ya request na matumizi ilikuwa:<sup>[[1]](#references)</sup>

1. `cldapi.dll` ilituma Cloud Files control code `0x903BC` yenye tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) na create-placeholder operation `0xC0000001`.
2. Kila payload record ilikuwa na jozi za offset/length za biti 16 kwa relative name na file identity. Sehemu nyingi za kudumu zilinakiliwa kwenye stack record, lakini name yenye urefu unaobadilika ilibaki katika kurasa za user zilizomapishwa.
3. Driver ilichanganua jina la UTF-16 na kukataa backslash au colon.
4. Kisha iliunda `UNICODE_STRING` ambayo `Buffer` yake bado ilielekeza kwenye payload iliyomapishwa na kuweka thamani hiyo kwa `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` ilisoma pointer hiyo tena. Kwa hiyo writer wa wakati mmoja angeweza kufanya uthibitishaji uone string moja na uundaji wa file uone nyingine.

Huu ni **double-fetch** hata kama usomaji wote wawili hutumia kernel virtual address: mpaka wa usalama hutegemea storage inayounga mkono data, si virtual mapping ambayo driver inatumia kuirejelea.<sup>[[1]](#references)</sup>

## Muundo wa race ya Cloud Files

Mkakati wa exploit uliofichuliwa ulitumia requests zinazorudiwa, mutator threads na junction kubadilisha double-fetch kuwa path redirection:<sup>[[1]](#references)</sup>

1. Sajili directory inayodhibitiwa na mshambulizi kwa `CfRegisterSyncRoot()` na uunde `JUSTASTRING` chini yake kama junction inayoelekeza kwenye protected destination.
2. Andaa placeholder record ya pamoja yenye jina halali la component moja, `JUSTASTRINGDnewfile.dll`.
3. Fanya mutator threads zibadilishe UTF-16 `D` code unit kati ya `D` na `\`. Umbo la pili ni `JUSTASTRING\newfile.dll`.
4. Sambamba na hilo, fanya worker threads zitume mara kwa mara create-placeholder requests zinazorejelea payload ileile, huku monitor ikikagua protected destination.
5. Iteration iliyofanikiwa huthibitisha umbo lisilo na separator, kisha hufuata junction wakati create inayofuata inapoona umbo lenye `\`.

Primitive hii huwezesha tu uundaji wa file au directory yenye ulinzi. Kuibadilisha kuwa code execution bado kunahitaji udhibiti wa yaliyomo kwenye file iliyoundwa na consumer mwenye haki za juu, kama vile lengo linalofaa la DLL side-loading. Uchambuzi wa awali ulitumia aina hii ya chain ya mwisho lakini haukuchapisha loader, payload au exploit kamili inayoweza kutumika kivyake.<sup>[[1]](#references)</sup>

Kwa mbinu za ziada zinazopanua kimakusudi races za Windows path-lookup, tazama [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU Privilege Escalation](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders function](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
