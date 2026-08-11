# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony service'i (TapiSrv, `tapisrv.dll`) **TAPI server** olarak yapılandırıldığında, kimliği doğrulanmış SMB client'larına **`\pipe\tapsrv` named pipe üzerinden `tapsrv` MSRPC interface'ini** sunar. Asynchronous event delivery'deki CVE-2026-20931, saldırganın varsayılan bir mailslot handle'ını, `NETWORK SERVICE` tarafından yazılabilir olan mevcut bir dosyaya **kontrollü 4-byte write** gerçekleştirecek şekilde kullanmasına olanak tanır. Yayımlanan chain, Telephony administrator listesinin üzerine yazar; ardından yalnızca administrator'ların erişebildiği bir DLL load işlemine ulaşır ve `NETWORK SERVICE` olarak çalışır.<sup>[[1]](#references)[[2]](#references)</sup>

## Attack Surface

- **Yalnızca etkinleştirildiğinde remote exposure**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing`, sharing'e izin vermelidir (veya `TapiMgmt.msc` / `tcmsetup /c <server>` üzerinden yapılandırılmalıdır). Varsayılan olarak `tapsrv` yalnızca local erişime açıktır.
- Interface: **SMB named pipe** üzerinden MS-TRP (`tapsrv`); bu nedenle saldırganın geçerli SMB auth bilgilerine ihtiyacı vardır.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)`, async event delivery'yi başlatır. Pull mode'da service şu işlemi gerçekleştirir:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser` değerinin bir mailslot path (`\\*\MAILSLOT\...`) olduğunu doğrulamaz. `NETWORK SERVICE` tarafından yazılabilir olan **mevcut herhangi bir filesystem path** kabul edilir.
- Her async event write, açılan handle'a tek bir **`DWORD` = `InitContext`** (sonraki `Initialize` request'inde saldırgan tarafından kontrol edilir) yazar ve bunun sonucunda **write-what/write-where (4 bytes)** elde edilir.<sup>[[1]](#references)</sup>

## Deterministic Writes Zorlama
1. **Target file'ı açın**: `pszDomainUser = <existing writable path>` ile `ClientAttach` çağrısı yapın (örneğin, `C:\Windows\TAPI\tsec.ini`).
2. Yazılacak her `DWORD` için `ClientRequest` karşısında şu RPC sequence'i çalıştırın:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` ve `pszModuleName = DIALER.EXE` (veya per-user priority list'teki başka bir üst entry) olarak ayarlayın.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (line app'i register eder ve en yüksek öncelikli recipient'ı yeniden hesaplar).
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` işlemini zorlayarak async event oluşturur.
- `GetAsyncEvents` (`Req_Func 0`): write işlemini dequeue eder/tamamlar.
- `LRegisterRequestRecipient` çağrısını `bEnable = 0` ile yeniden yapın (unregister).
- Line app'i sonlandırmak için `Shutdown` (`Req_Func 86`) çağrısı yapın.
- Priority control: “highest priority” recipient, `pszModuleName` ile `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` karşılaştırılarak seçilir (client impersonation yapılırken okunur). Gerekirse `LSetAppPriority` (`Req_Func 69`) ile module name'inizi ekleyin.
- `OPEN_EXISTING` kullanıldığı için dosya **önceden mevcut olmalıdır**. `NETWORK SERVICE` tarafından yazılabilir yaygın adaylar: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## DWORD Write'tan TapiSrv İçinde RCE'ye
1. **Kendinize Telephony “admin” yetkisi verin**: `C:\Windows\TAPI\tsec.ini` dosyasını hedefleyin ve yukarıdaki 4-byte write işlemleriyle `[TapiAdministrators]\r\n<DOMAIN\\user>=1` ekleyin. Service'in INI dosyasını yeniden okuması ve hesabınız için `ptClient->dwFlags |= 9` ayarlaması amacıyla **yeni bir session** (`ClientAttach`) başlatın.
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` ile `GetUIDllName` gönderin ve `dwProviderFilenameOffset` üzerinden bir path sağlayın. Admin'ler için service `LoadLibrary(path)` çağrısını yapar ve ardından `TSPI_providerUIIdentify` export'unu çağırır:
- Gerçek bir Windows SMB share'e ait UNC path'ler çalışır; bazı saldırgan SMB server'ları `ERROR_SMB_GUEST_LOGON_BLOCKED` ile başarısız olur.
- Alternative: aynı 4-byte write primitive'i kullanarak local bir DLL'i yavaşça bırakıp ardından yükleyin.
3. **Payload**: Export, `NETWORK SERVICE` altında çalışır. Minimal bir DLL `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` çalıştırabilir ve service'in DLL'i unload etmesi, dolayısıyla execution'ı doğrulaması için non-zero bir değer (örneğin `0x1337`) döndürebilir.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- CVE-2026-20931 için Microsoft security update'i yükleyin. Ayrıca gerekli değilse TAPI server mode'u disable edin ve `\pipe\tapsrv` remote access'ini block edin.
- Client tarafından sağlanan path'leri açmadan önce mailslot namespace validation (`\\*\MAILSLOT\`) uygulayın.
- `C:\Windows\TAPI\tsec.ini` ACL'lerini sıkılaştırın ve değişiklikleri monitor edin; default olmayan path'leri yükleyen `GetUIDllName` çağrılarını alert'leyin.<sup>[[1]](#references)</sup>

## References

- [1] [Kim hatta? Windows Telephony Service'te RCE Exploiting (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)
- [2] [Microsoft Security Response Center — CVE-2026-20931](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20931)
{{#include ../../banners/hacktricks-training.md}}
