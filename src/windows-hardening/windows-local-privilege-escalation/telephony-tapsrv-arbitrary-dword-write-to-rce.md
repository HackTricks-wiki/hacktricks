# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

Windows Telephony service'i (TapiSrv, `tapisrv.dll`) **TAPI server** olarak yapılandırıldığında, kimliği doğrulanmış SMB istemcilerine **`\pipe\tapsrv` named pipe** üzerinden **`tapsrv` MSRPC interface** sunar. Uzak istemciler için asynchronous event delivery işlemindeki bir tasarım hatası, saldırganın mailslot handle'ını **`NETWORK SERVICE` tarafından yazılabilir, önceden var olan herhangi bir dosyaya kontrollü 4-byte write** gerçekleştirecek şekilde kullanmasına olanak tanır. Bu primitive, Telephony admin list'ini overwrite etmek ve **admin-only arbitrary DLL load** özelliğini kötüye kullanarak `NETWORK SERVICE` olarak code execute etmek için chain edilebilir.<sup>[[1]](#references)</sup>

## Attack Surface

- **Yalnızca etkinleştirildiğinde uzaktan erişilebilir**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing`, sharing'e izin vermelidir (veya `TapiMgmt.msc` / `tcmsetup /c <server>` üzerinden yapılandırılmalıdır). Varsayılan olarak `tapsrv` yalnızca local'dir.
- Interface: **SMB named pipe** üzerinden MS-TRP (`tapsrv`); bu nedenle saldırganın geçerli SMB auth bilgilerine ihtiyacı vardır.
- Service account: `NETWORK SERVICE` (manual start, on-demand).<sup>[[1]](#references)</sup>

## Primitive: Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` async event delivery'yi başlatır. Pull mode'da service şu işlemi yapar:
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
`pszDomainUser` değerinin bir mailslot path (`\\*\MAILSLOT\...`) olduğunu doğrulamadan işlem yapar. `NETWORK SERVICE` tarafından yazılabilir herhangi bir **existing filesystem path** kabul edilir.
- Her async event write işlemi, açılan handle'a tek bir **`DWORD` = `InitContext`** kaydeder (`InitContext`, sonraki `Initialize` request'inde saldırgan tarafından kontrol edilir); böylece **write-what/write-where (4 bytes)** elde edilir.<sup>[[1]](#references)</sup>

## Deterministic Writes Zorlamak
1. **Target file'ı açın**: `pszDomainUser = <existing writable path>` ile `ClientAttach` çağırın (örneğin, `C:\Windows\TAPI\tsec.ini`).
2. Yazılacak her `DWORD` için `ClientRequest` karşısında şu RPC sequence'i çalıştırın:
- `Initialize` (`Req_Func 47`): `InitContext = <4-byte value>` ve `pszModuleName = DIALER.EXE` (veya per-user priority list'teki başka bir üst entry) olarak ayarlayın.
- `LRegisterRequestRecipient` (`Req_Func 61`): `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (line app'i register eder ve en yüksek priority recipient'ı yeniden hesaplar).
- `TRequestMakeCall` (`Req_Func 121`): `NotifyHighestPriorityRequestRecipient` işlemini zorlayarak async event oluşturur.
- `GetAsyncEvents` (`Req_Func 0`): write işlemini dequeue eder/tamamlar.
- `LRegisterRequestRecipient` işlemini `bEnable = 0` ile tekrar çağırın (unregister).
- `Shutdown` (`Req_Func 86`): line app'i teardown eder.
- Priority control: “highest priority” recipient, `pszModuleName` değerinin `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` ile karşılaştırılmasıyla seçilir (bu değer client impersonation yapılırken okunur). Gerekirse `LSetAppPriority` (`Req_Func 69`) ile module name'inizi ekleyin.
- File **zaten var olmalıdır**, çünkü `OPEN_EXISTING` kullanılır. `NETWORK SERVICE` tarafından yazılabilir yaygın adaylar: `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## DWORD Write'tan TapiSrv içinde RCE'ye
1. **Kendinize Telephony “admin” yetkisi verin**: `C:\Windows\TAPI\tsec.ini` dosyasını target olarak seçin ve yukarıdaki 4-byte writes ile `[TapiAdministrators]\r\n<DOMAIN\\user>=1` ekleyin. Yeni bir session (`ClientAttach`) başlatın; böylece service INI'yi yeniden okur ve hesabınız için `ptClient->dwFlags |= 9` ayarını yapar.
2. **Admin-only DLL load**: `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` ile `GetUIDllName` gönderin ve `dwProviderFilenameOffset` üzerinden bir path sağlayın. Admin'ler için service `LoadLibrary(path)` çağırır, ardından `TSPI_providerUIIdentify` export'unu çalıştırır:
- Gerçek bir Windows SMB share'e ait UNC path'lerle çalışır; bazı attacker SMB server'ları `ERROR_SMB_GUEST_LOGON_BLOCKED` hatasıyla başarısız olur.
- Alternative: aynı 4-byte write primitive'i kullanarak local bir DLL'i yavaşça drop edin, ardından load edin.
3. **Payload**: export `NETWORK SERVICE` altında execute edilir. Minimal bir DLL `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` çalıştırabilir ve execution'ı doğrulamak için non-zero bir değer (örneğin `0x1337`) döndürebilir; böylece service DLL'i unload eder.<sup>[[1]](#references)</sup>

## Hardening / Detection Notes
- Gerekli değilse TAPI server mode'u disable edin; `\pipe\tapsrv` için remote access'i block edin.
- Client tarafından sağlanan path'leri açmadan önce mailslot namespace validation (`\\*\MAILSLOT\`) uygulayın.
- `C:\Windows\TAPI\tsec.ini` ACL'lerini sıkılaştırın ve değişiklikleri monitor edin; default olmayan path'leri load eden `GetUIDllName` calls için alert oluşturun.<sup>[[1]](#references)</sup>

## References

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
