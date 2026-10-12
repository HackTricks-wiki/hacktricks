# Windows MDL-Gekarteerde Gebruikersbuffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

'n Windows-kerneldrywer veroorsaak 'n double-fetch wanneer dit data in bladsye wat deur die oproeper gesteun word, valideer en later 'n wyser na dieselfde bladsye aan 'n sekuriteitsensitiewe API deurgee. Deur die bladsye te sluit en te karteer, word hul inhoud nie onveranderlik nie. CVE-2025-55680 in `cldflt.sys` illustreer hierdie patroon: die drywer het 'n Cloud Files-plaasvervanger se relatiewe naam gevalideer en daarna die objek geskep terwyl dit steeds na die oproeper se veranderbare buffer verwys het.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` skep lêers of gidse onder 'n geregistreerde Cloud Files-sinkroniseringswortel. In die kwesbare kodepad kon 'n verandering aan die naam ná validering bevoorregte skepping buite daardie wortel herlei.<sup>[[1]](#references)[[2]](#references)</sup>

## Waarom die sluit van die bladsye nie die data gesluit het nie

Die kwesbare `HsmpOpCreatePlaceholders()`-kodepad het 'n MDL vir die oproeper se loonvrag toegewys, `ProbeForRead()` en `MmProbeAndLockPages()` geroep en daardie bladsye in die virtuele kernadresruimte gekarteer. 'n MDL beskryf en sluit die fisiese bladsye sodat hulle in die geheue bly. Dit neem **nie** 'n momentopname van hul grepe nie. Gebruikersmodus kan dus dieselfde fisiese geheue verander terwyl die drywer dit deur die stelselkartering lees.<sup>[[1]](#references)[[3]](#references)</sup>

Die betrokke versoek- en gebruikspad was:<sup>[[1]](#references)</sup>

1. `cldapi.dll` het Cloud Files-beheerkode `0x903BC` gestuur met merker `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) en die create-placeholder-bewerking `0xC0000001`.
2. Elke loonvragrekord het 16-bis-afset-/lengtepare vir die relatiewe naam en lêeridentiteit bevat. Die meeste vaste velde is na 'n stapelrekord gekopieer, maar die veranderlike-lengtenaam het in die gekarteerde gebruikersbladsye gebly.
3. Die drywer het die UTF-16-naam geskandeer en 'n terugskuinsstreep of dubbelpunt verwerp.
4. Daarna het dit 'n `UNICODE_STRING` opgebou waarvan `Buffer` steeds na die gekarteerde loonvrag gewys het, en dit aan `OBJECT_ATTRIBUTES.ObjectName` toegeken.
5. `FltCreateFileEx2()` het daardie wyser weer gelees. 'n Gelyktydige skrywer kon dus veroorsaak dat validering een string sien en lêerskepping 'n ander een.

Dit is 'n **double-fetch**, al gebruik albei leesaksies 'n virtuele kernadres: die sekuriteitsgrens hang van die rugliggende berging af, nie van watter virtuele kartering die drywer dereferensieer nie.<sup>[[1]](#references)</sup>

## Cloud Files-wedrenuitleg

Die bekendgemaakte uitbuitingstrategie het herhaalde versoeke, mutatordrade en 'n junction gebruik om die double-fetch in padherleiding te omskep:<sup>[[1]](#references)</sup>

1. Registreer 'n aanvallerbeheerde gids met `CfRegisterSyncRoot()` en skep `JUSTASTRING` daaronder as 'n junction na 'n beskermde bestemming.
2. Berei 'n gedeelde plaasvervangerrekord voor met die geldige enkelkomponentnaam `JUSTASTRINGDnewfile.dll`.
3. Laat mutatordrade die UTF-16-`D`-kode-eenheid tussen `D` en `\` wissel. Die tweede voorstelling is `JUSTASTRING\newfile.dll`.
4. Laat werkdrade terselfdertyd herhaaldelik create-placeholder-versoeke indien wat na dieselfde loonvrag verwys, terwyl 'n monitor die beskermde bestemming nagaan.
5. 'n Suksesvolle iterasie valideer die voorstelling sonder 'n skeidingsteken en volg dan die junction wanneer die latere skepaksie die voorstelling met `\` sien.

Die primitief maak slegs die skep van beskermde lêers of gidse moontlik. Om dit in kode-uitvoering om te skakel, is steeds beheer oor die geskepte lêer se inhoud en 'n bevoorregte verbruiker nodig, soos 'n geskikte DLL-side-loading-teiken. Die oorspronklike ontleding het hierdie laaste klas ketting gebruik, maar nie die laaier, loonvrag of 'n volledige selfstandige uitbuiting gepubliseer nie.<sup>[[1]](#references)</sup>

Vir aanvullende tegnieke wat Windows-padsoek-wedrenne doelbewus verleng, sien [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files-minifilter-TOCTOU-bevoorregte eskalasie](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders-funksie](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages-funksie](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
