# Bypasses za Ukaguzi wa Ufikiaji wa Faili katika Kernel Mode

{{#include ../../banners/hacktricks-training.md}}

## Muundo wa driver ulio hatarini

Driver haihifadhi tu mpaka wa usalama wa caller kwa kuiga utambulisho wake. Kufungua object katika kernel mode kwa kawaida hupita ukaguzi wa ufikiaji. `OBJ_KERNEL_HANDLE` hufanya tu handle inayotokana ipatikane kutoka kernel mode. Driver inapofungua au kudhibiti object kwa niaba ya user mode, lazima pia itumie `OBJ_FORCE_ACCESS_CHECK` ili Object Manager itathmini ufikiaji ulioombwa kwa kutumia token inayotumika.<sup>[[3]](#references)[[4]](#references)</sup>

Kagua IOCTL za kushughulikia faili na create callbacks ili kuona mfuatano huu:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode hutoa path, source handle, ufikiaji unaotakiwa, au aina ya operesheni.
2. Driver inaiga utambulisho wa caller, lakini inaita `IoCreateFileEx`, `ZwCreateFile`, au routine inayofanana bila `OBJ_FORCE_ACCESS_CHECK`.
3. Handle ya faili au saraka inayopatikana kernel pekee inahifadhiwa katika hali ya per-handle.
4. Operesheni ya baadaye huamua iwapo itaiga utambulisho kwa kutumia hali inayoweza kuathiriwa na mshambulizi, kama vile access mask iliyoombwa wakati wa kufungua kwa mara ya kwanza.
5. Tawi lenye mapendeleo makubwa hufanya rename au link kwa kutumia information class ya `BypassAccessCheck`.

Hii ni **file primitive ya confused-deputy**, si lazima iwe memory corruption. Mabadiliko hatari hasa ya hali ni “write imeombwa, kwa hiyo iga utambulisho; write haijaombwa, kwa hiyo endelea na mapendeleo.” Katika muundo huo, kuomba read access pekee kimakusudi kunaweza kufungua njia yenye uwezo mkubwa zaidi.<sup>[[3]](#references)</sup>

## Mfano wa vSMB: root yenye mapendeleo pamoja na rename yenye mapendeleo

`storvsp.sys` hutekeleza Virtual Server Message Block (vSMB). Kipengele cha **Virtual Machine Platform** kikiwashwa, user mode inaweza kufikia `\Device\STORVSP` kupitia `\\.\STORVSP`. Path ya mfumo wa faili ya vSMB huwa na muundo `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 na CVE-2025-64673 zilionyesha jinsi maamuzi mawili yasiyolingana ya udhibiti wa ufikiaji yalivyoweza kugeuza kiolesura hiki kuwa local privilege escalation.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Ulinganisho wa source kati ya function na CVE unatokana na reverse engineering ya binary iliyofanyiwa patch, si source ya Microsoft. Watafiti wanaonya kuwa huenda vitambulisho hivyo viwili vinalingana na functions zilizo kinyume.<sup>[[3]](#references)</sup>

### 1. Unda share ya read-only yenye mizizi katika saraka iliyolindwa

Njia ya create ilirekodi haki zilizoombwa katika flags zinazoendelea kama `HasReadAccess`, `HasWriteAccess`, na `HasAppendAccess`. Kisha ilifungua backing path kwa kutumia `OBJ_KERNEL_HANDLE` lakini bila `OBJ_FORCE_ACCESS_CHECK`. Kwa hiyo, jaribio la kuiga utambulisho halikufanya ufunguzi wa faili uheshimu ruhusa za NTFS za caller.<sup>[[3]](#references)[[4]](#references)</sup>

Omba `FILE_READ_DATA` pekee. Hii huacha `HasWriteAccess` ikiwa haijawekwa, huku bado ikipata share ambayo internal root yake ni saraka iliyolindwa:<sup>[[3]](#references)</sup>

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

Artifact muhimu si handle ya directory ya System32 katika user mode. Ni device handle ya vSMB inayohusishwa na hali ya driver iliyo na handle ya root yenye upendeleo wa kernel.<sup>[[3]](#references)</sup>

### 2. Tumia kutolingana kwa hali ili kubadilisha faili iliyolindwa

IOCTL `0x240330` ilikubali handle ya faili chanzo, darasa la taarifa, na buffer ya taarifa yenye urefu unaobadilika:<sup>[[3]](#references)</sup>

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

Handler iliyo hatarini ilikubali `FileRenameInformation`, `FileLinkInformation`, na `FileRenameInformationEx`. Kwa njia ya kawaida ya kubadilisha jina, ilitenganisha njia ya parent kutoka kwenye kipengele cha mwisho, kisha ikafungua parent ikilinganishwa na root handle iliyohifadhiwa. Ufunguzi huo pia ulitumia `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` bila `OBJ_FORCE_ACCESS_CHECK`. `RootDirectory` isiyo sifuri iliyotolewa na mshambuliaji ndani ya muundo wa kubadilisha jina ilikataliwa, kwa hiyo driver ilitoa handle yake yenyewe ya directory yenye upendeleo.<sup>[[3]](#references)</sup>

Tawi lililoweza kutumiwa vibaya lilichaguliwa kwa **kutokuomba ufikiaji wa kuandika wakati wa stage 1**:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersonate muktadha wa usalama wa root uliohifadhiwa.
- `HasWriteAccess == 0`: ruka impersonation na badilisha `FileRenameInformation` au `FileRenameInformationEx` kuwa aina yake ya `BypassAccessCheck`.

Handler ilinakili handle ya chanzo iliyotolewa na mshambuliaji ndani ya `PsInitialSystemProcess`, ika-refer handle hiyo kama file object, ikaweka handle ya directory lengwa yenye upendeleo ndani ya muundo wa kubadilisha jina, kisha ikaita `ZwSetInformationFile`. Kwa `ReplaceIfExists = TRUE`, faili inayodhibitiwa na caller ingeweza kwa hiyo kuchukua nafasi ya faili iliyopo chini ya root iliyolindwa.<sup>[[3]](#references)</sup>

Unapokagua handler inayofanana, fuatilia **asili ya handle na muktadha wa usalama** katika kila tawi. Uthibitishaji wa ingizo, ukaguzi wa integer overflow, `IO_STOP_ON_SYMLINK`, na kuzuia madarasa ya taarifa yanayokubaliwa havizuii hatari inayotokana na handle ya root yenye upendeleo pamoja na operesheni inayoruka ukaguzi wa ufikiaji.<sup>[[3]](#references)</sup>

## Kutoka kwa uandishi uliolindwa hadi utekelezaji wa SYSTEM

Primitive ya kubadilisha faili iliyolindwa huwa code execution pale mchakato wenye upendeleo unapopakia baadaye module iliyobadilishwa. Katika chain iliyoonyeshwa, lengwa lilikuwa `C:\Windows\System32\wuapi.dll`. Kuwasha COM class ya local-server `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` kwa interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` na kuita `IWaaSRemediation::LaunchDetectionOnly()` kulisababisha mchakato wa SYSTEM kupakia DLL hiyo.<sup>[[3]](#references)</sup>

Wito huu wa COM ni **kichochezi cha activation**, si [COM registry hijacking](com-hijacking.md). Primitive ya faili hutoa module iliyopandikizwa, na loader yenye upendeleo huitekeleza. Kwa chain nyingine za uandishi uliolindwa, tambua image halisi, njia ya DLL, sera ya sahihi, bitness, functions zinazotolewa nje, na kichochezi cha kuaminika kabla ya kuchagua lengwa. Tazama [kuunganisha uandishi wa faili holela na DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) kwa mtiririko wa jumla wa uchanganuzi wa loader.<sup>[[3]](#references)</sup>

### Kuhamisha tokeni ya Session 0 hadi kwenye desktop shirikishi

Payload iliyopakiwa na service kwa kawaida hutekelezwa katika Session 0. Ili kuunda mchakato shirikishi, inaweza kupata session ya active console kwa kutumia `WTSGetActiveConsoleSessionId`, kuwasha token privileges zinazohitajika, kunakili tokeni ya sasa ya SYSTEM kama primary token, na kuweka `TokenSessionId` yake kuwa session inayotumika. Kisha `CreateProcessAsUserW` hutumia tokeni hiyo pamoja na `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

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

`SeTcbPrivilege` inahitajika ili kuweka session ID ya token katika hali hii. Interactive window station na desktop lazima pia ziruhusu token kufikia. Tazama [kunakili token kutoka Session 0](sedebug-+-seimpersonate-copy-token.md) kwa mtiririko mpana wa kunakili token.<sup>[[3]](#references)[[5]](#references)</sup>

## Mwongozo wa patch na ukaguzi

Updates za Microsoft za Desemba 2025 zilirekebisha mnyororo ulioonyeshwa. Reverse engineering ilibaini kuwa njia ya kuunda vSMB iliyorekebishwa hukataa wapigaji wasioaminika wanaoomba mzizi wa share bila `FILE_WRITE_DATA`. Operesheni husika pia ziliwekewa ukaguzi wa ufikiaji wa lazima. Hili huzuia ubadilishaji wa hali kabla mpigaji asiye na upendeleo hajapata mzizi wenye upendeleo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Kwa msimbo wa driver, tumia kanuni hizi:<sup>[[3]](#references)[[4]](#references)</sup>

- Ongeza `OBJ_FORCE_ACCESS_CHECK` kila mara object inapofunguliwa kwa niaba ya ombi la user-mode. Usichukulie `OBJ_KERNEL_HANDLE` kama udhibiti wa uidhinishaji.<sup>[[4]](#references)</sup>
- Nasa na uthibitishe hali ya mwombaji na muktadha wa subject unaotumika. Usiruhusu haki zilizoombwa kuchagua njia ya utekelezaji yenye upendeleo zaidi.
- Thibitisha user handles kwa kutumia aina sahihi ya object, access mask na `UserMode`. Kunakili handle kwenye mchakato wa system hakuthibitishi mamlaka ya operesheni iliyoombwa.
- Fanya utatuzi wa target ukiwa umehusishwa na handle inayoaminika, lakini hakikisha handle hiyo yenyewe ilifunguliwa kwa ukaguzi wa ufikiaji unaotekelezwa kwa mwombaji.
- Epuka madarasa ya `File*BypassAccessCheck` kwa operesheni zinazoendeshwa na mtumiaji. Ikiwa msimbo wa ndani unayahitaji kweli, zuia njia hiyo kwa uamuzi wa uidhinishaji usiotegemea flags za ufikiaji zinazodhibitiwa na mtumiaji.
- Weka mifumo iliyoathiriwa kwenye patch. Sehemu iliyo hatarini ni muhimu wakati Virtual Machine Platform inapopakia `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Kutoka Virtual Share hadi Physical Shell: Kutumia Udhibiti wa Ufikiaji Usio Sawia wa Windows kwa LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Handles za Object](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Function ya CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
