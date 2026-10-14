# Omseilings van lêertoegangkontroles in Kernel-Mode

{{#include ../../banners/hacktricks-training.md}}

## Kwesbare driver-patroon

’n Driver behou nie bloot deur ’n oproeper na te boots daardie oproeper se sekuriteitsgrens nie. Kernel-mode-objectopenings omseil gewoonlik toegangskontroles. `OBJ_KERNEL_HANDLE` maak die resulterende handle slegs vanuit kernel mode toeganklik. Wanneer ’n driver ’n object namens user mode oopmaak of manipuleer, moet dit ook `OBJ_FORCE_ACCESS_CHECK` gebruik sodat die Object Manager die aangevraagde toegang teen die effektiewe token evalueer.<sup>[[3]](#references)[[4]](#references)</sup>

Ondersoek IOCTL’s vir lêerhantering en create-callbacks vir hierdie volgorde:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode verskaf ’n pad, bron-handle, verlangde toegang of bewerkingstipe.
2. Die driver boots die oproeper na, maar roep `IoCreateFileEx`, `ZwCreateFile` of ’n soortgelyke roetine aan sonder `OBJ_FORCE_ACCESS_CHECK`.
3. ’n Lêer- of gids-handle wat slegs vir kernel beskikbaar is, word in per-handle-toestand gestoor.
4. ’n Latere bewerking besluit of die oproeper nageboots moet word op grond van toestand wat deur die aanvaller beïnvloed kan word, soos die toegangsmasker wat tydens die eerste opening aangevra is.
5. Die bevoorregte tak voer ’n hernoeming of skakelbewerking uit met ’n `BypassAccessCheck`-inligtingklas.

Dit is ’n **confused-deputy file primitive**, nie noodwendig geheuekorrupsie nie. ’n Besonder gevaarlike omkering van die toestand is “skryf aangevra beteken boots na; geen skryf aangevra beteken bly bevoorreg.” In dié ontwerp kan die doelbewuste versoek om slegs leestoegang die kragtiger pad ontsluit.<sup>[[3]](#references)</sup>

## vSMB-voorbeeld: bevoorregte wortel plus bevoorregte hernoeming

`storvsp.sys` implementeer Virtual Server Message Block (vSMB). Wanneer die **Virtual Machine Platform**-funksie geaktiveer is, kan user mode `\Device\STORVSP` via `\\.\STORVSP` bereik. ’n vSMB-lêerstelselpad het die vorm `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 en CVE-2025-64673 het gewys hoe twee inkonsekwente toegangsbeheerbesluite hierdie koppelvlak in plaaslike voorregte-eskalasie kon verander.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Die bron se kartering van funksies na CVE’s kom uit reverse engineering van die reggemaakte binêre lêer, eerder as Microsoft se bronkode. Die navorsers waarsku dat die twee identifiseerders moontlik aan die teenoorgestelde funksies gekoppel is.<sup>[[3]](#references)</sup>

### 1. Skep ’n deelhulpbron met slegs leestoegang, gewortel in ’n beskermde gids

Die kwesbare create-pad het die aangevraagde regte in aanhoudende vlae soos `HasReadAccess`, `HasWriteAccess` en `HasAppendAccess` aangeteken. Daarna het dit die agterliggende pad met `OBJ_KERNEL_HANDLE`, maar sonder `OBJ_FORCE_ACCESS_CHECK`, oopgemaak. Die poging om die oproeper na te boots het dus nie verseker dat die lêeropening die oproeper se NTFS-toestemmings respekteer nie.<sup>[[3]](#references)[[4]](#references)</sup>

Versoek slegs `FILE_READ_DATA`. Dit laat `HasWriteAccess` ongestel, terwyl ’n deelhulpbron verkry word waarvan die interne wortel ’n beskermde gids is:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Die belangrike artefak is nie ’n user-mode System32-gids-handvatsel nie. Dit is ’n vSMB-toestelhandvatsel wat met driver-toestand geassosieer word en ’n bevoorregte kernel-wortelhandvatsel bevat.<sup>[[3]](#references)</sup>

### 2. Gebruik die toestandwanpassing om ’n beskermde lêer te vervang

IOCTL `0x240330` het ’n bronlêerhandvatsel, ’n inligtingsklas en ’n inligtingbuffer met veranderlike lengte aanvaar:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Die kwesbare handler het `FileRenameInformation`, `FileLinkInformation` en `FileRenameInformationEx` aanvaar. Vir ’n normale hernoempad het dit die ouerpad van die finale komponent geskei, en daarna die ouer relatief tot die gestoorde wortelhandle oopgemaak. Daardie opening het weer `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` gebruik sonder `OBJ_FORCE_ACCESS_CHECK`. ’n Nie-nul `RootDirectory` wat die aanvaller in die hernoemstruktuur verskaf het, is afgekeur, dus het die driver sy eie bevoorregte gids-handle verskaf.<sup>[[3]](#references)</sup>

Die uitbuitbare tak is gekies deur **nie** skryftoegang tydens stage 1 aan te vra nie:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersonate die gestoorde wortelsekuriteitskonteks.
- `HasWriteAccess == 0`: slaan impersonation oor en skakel `FileRenameInformation` of `FileRenameInformationEx` om na die ooreenstemmende `BypassAccessCheck`-variant.

Die handler het die bron-handle wat die aanvaller verskaf het na `PsInitialSystemProcess` gedupliseer, daarna as ’n file object verwys, die bevoorregte teikengids-handle in die hernoemstruktuur geïnstalleer en `ZwSetInformationFile` aangeroep. Met `ReplaceIfExists = TRUE` kon ’n lêer onder die aanvaller se beheer dus ’n bestaande lêer onder die beskermde wortel vervang.<sup>[[3]](#references)</sup>

Wanneer jy ’n soortgelyke handler hersien, volg **beide handle-herkoms en sekuriteitskonteks** deur elke tak. Invoervalidering, integer-overflow-kontroles, `IO_STOP_ON_SYMLINK` en die beperking van die aanvaarde information classes vergoed nie vir ’n bevoorregte wortel-handle saam met ’n access-check-bypass-operasie nie.<sup>[[3]](#references)</sup>

## Van beskermde skryftoegang tot SYSTEM-uitvoering

’n Primitief vir die vervanging van beskermde lêers lei tot code execution wanneer ’n bevoorregte proses later die vervangde module laai. In die gedemonstreerde ketting was die bestemming `C:\Windows\System32\wuapi.dll`. Deur die local-server COM-klas `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` vir koppelvlak `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` te aktiveer en `IWaaSRemediation::LaunchDetectionOnly()` aan te roep, is ’n SYSTEM-proses veroorsaak om daardie DLL te laai.<sup>[[3]](#references)</sup>

Hierdie COM-aanroep is ’n **aktiveringstrigger**, nie [COM registry hijacking](com-hijacking.md) nie. Die lêerprimitief verskaf die geplante module, en die bevoorregte loader verskaf die uitvoering. Vir ander kettings met beskermde skryftoegang, identifiseer die presiese image, DLL-pad, signature policy, bitness, exported functions en betroubare trigger voordat jy ’n teiken kies. Sien [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) vir die algemene loader-ontledingswerkvloei.<sup>[[3]](#references)</sup>

### ’n Session 0-token na die interaktiewe desktop verskuif

’n Payload wat deur ’n diens gelaai word, loop gewoonlik in Session 0. Om ’n interaktiewe proses te skep, kan dit die aktiewe console-session met `WTSGetActiveConsoleSessionId` verkry, die vereiste token privileges aktiveer, die huidige SYSTEM-token as ’n primary token dupliseer, en sy `TokenSessionId` op die aktiewe session stel. `CreateProcessAsUserW` gebruik dan daardie token met `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` is nodig om in hierdie scenario ’n token se sessie-ID in te stel. Die interaktiewe vensterstasie en werkskerm moet ook die token toegang verleen. Sien [token duplication from Session 0](sedebug-+-seimpersonate-copy-token.md) vir die breër token-copy-werkvloei.<sup>[[3]](#references)[[5]](#references)</sup>

## Patch- en hersieningsriglyne

Microsoft se opdaterings van Desember 2025 het die gedemonstreerde ketting reggestel. Omgekeerde ontleding het getoon dat die gelapte vSMB-create-pad onbetroubare aanroepe verwerp wat ’n share-root sonder `FILE_WRITE_DATA` versoek. Relevante bewerkings het ook gedwonge toegangstoetsing gekry. Dit keer die toestandinversie voordat ’n onbevoorregte aanroeper die bevoorregte root kan verkry.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Pas hierdie reëls toe vir driver-kode:<sup>[[3]](#references)[[4]](#references)</sup>

- Voeg `OBJ_FORCE_ACCESS_CHECK` by wanneer ’n objek namens ’n user-mode-versoek oopgemaak word. Moenie `OBJ_KERNEL_HANDLE` as ’n magtigingsbeheermaatreël beskou nie.<sup>[[4]](#references)</sup>
- Leg die versoekermodus en effektiewe onderwerp-konteks vas en valideer dit. Moenie toelaat dat die versoekte regte ’n meer bevoorregte uitvoeringsvertakking kies nie.
- Valideer user-handles met die korrekte objektipe, toegangsmasker en `UserMode`. Om ’n handle na die stelselproses te dupliseer, valideer nie die magtiging vir die versoekte bewerking nie.
- Hou teikenresolusie relatief tot ’n vertroude handle, maar verseker dat die vertroude handle self geopen is met die versoeker se afgedwonge toegangstoets.
- Vermy `File*BypassAccessCheck`-klasse vir gebruiker-gedrewe bewerkings. As interne kode dit werklik nodig het, beperk daardie pad met ’n magtigingsbesluit wat onafhanklik is van gebruiker-beheerde toegangsvlae.
- Patch die betrokke stelsels. Die kwesbare aanvalsvlak is relevant wanneer Virtual Machine Platform `storvsp.sys` laai.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Van Virtual Share tot Physical Shell: Benutting van Windows se inkonsekwente toegangsbeheer vir LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Objekhandvatsels](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW-funksie](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
