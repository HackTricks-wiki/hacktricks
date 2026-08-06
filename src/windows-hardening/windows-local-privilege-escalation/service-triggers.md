# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers, bir koşul gerçekleştiğinde (ör. bir IP adresi kullanılabilir olduğunda, bir named pipe bağlantısı denenğinde veya bir ETW event yayımlandığında) Service Control Manager'ın (SCM) bir service'i başlatmasını/durdurmasını sağlar. Hedef service üzerinde SERVICE_START haklarına sahip olmasanız bile trigger'ını tetikleyerek service'i başlatabilirsiniz.<sup>[[1]](#references)</sup>

Bu sayfa, saldırganlar için kullanışlı enumeration yöntemlerine ve yaygın trigger'ları etkinleştirmenin düşük zahmetli yollarına odaklanır.

> İpucu: Yetkili bir yerleşik service'i (ör. RemoteRegistry, WebClient/WebDAV, EFS) başlatmak, yeni RPC/named-pipe listener'larını açığa çıkarabilir ve daha ileri abuse zincirlerinin önünü açabilir.

## Service Triggers Enumeration

- sc.exe (local)
- Bir service'in trigger'larını listeleme: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger'lar şurada bulunur: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Recursive olarak dump etme: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_CONFIG_TRIGGER_INFO (8) ile SERVICE_TRIGGER_INFO bilgisini almak için QueryServiceConfig2 çağrılır.
- Docs: QueryServiceConfig2[W/A] ve SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- MS-SCMR üzerinden RPC (remote)
- SCM, MS-SCMR kullanılarak trigger bilgilerini almak üzere remote olarak sorgulanabilir. TrustedSec’in Titanis aracı bunu sunar: `Scm.exe qtriggers`.
- Impacket, msrpc MS-SCMR içindeki yapıları tanımlar; bunları kullanarak remote query uygulayabilirsiniz.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (bulk enumeration)
- `TriggerInfo` key'i sunan her service'i hızlıca listeleme:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw'ın `NtObjectManager` module'ü, `sc.exe` output'unu scrape etmeden trigger metadata'sını parse etmek için `Get-Win32ServiceTrigger` sunar.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Bunlar, bir client IPC endpoint ile iletişim kurmayı denediğinde bir service'i başlatır. SCM, client gerçekten bağlanabilmeden önce service'i otomatik olarak başlatacağından low-priv user'lar için kullanışlıdır.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Davranış: \\.\pipe\<PipeName> adresine yapılan bir client connection attempt, dinlemeye başlayabilmesi için SCM'nin service'i başlatmasına neden olur.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe trigger'ları, kayıtlı trigger pipe name'lerine yönelik open işlemlerini izleyen bir filesystem minifilter olan `npsvctrig.sys` tarafından desteklenir. Bu nedenle open attempt, service'in kendisi pipe'ı oluşturup dinlemeye başlamadan önce bile service'i başlatabilir.<sup>[[5]](#references)</sup>
- Ayrıca bkz.: Start sonrası abuse için Named Pipe Client Impersonation.

- RPC endpoint trigger (Endpoint Mapper)
- Davranış: Service ile ilişkilendirilmiş bir interface UUID'si için Endpoint Mapper'ın (EPM, TCP/135) sorgulanması, endpoint'ini register edebilmesi için SCM'nin service'i başlatmasına neden olur.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Bir service, bir ETW provider/event'e bağlı bir trigger register edebilir. Ek filter'lar (keyword/level/binary/string) yapılandırılmamışsa, bu provider'dan gelen herhangi bir event service'i başlatır.<sup>[[1]](#references)</sup>

- Örnek (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Trigger'ı listeleme: `sc.exe qtriggerinfo webclient`
- Provider'ın register edildiğini doğrulama: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Eşleşen event'leri emit etmek genellikle bu provider'a log yazan bir code gerektirir; filter yoksa herhangi bir event yeterlidir.
- Provider'ı fire etmek için minimal C shape (ek ETW filter'ları yapılandırılmadığında):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Alt türler: Machine/User. İlgili policy'nin bulunduğu domain-joined host'larda trigger boot sırasında çalışır. `gpupdate` tek başına değişiklik olmadan trigger'ı çalıştırmaz, ancak:<sup>[[1]](#references)</sup>

- Activation: `gpupdate /force`
- İlgili policy type mevcutsa bu işlem trigger'ın fire etmesini ve service'i başlatmasını güvenilir şekilde sağlar.

### IP Address Available

İlk IP alındığında (veya son IP kaybedildiğinde) fire olur. Genellikle boot sırasında trigger edilir.<sup>[[1]](#references)</sup>

- Activation: Örneğin bağlantıyı yeniden tetiklemek için connectivity'yi değiştirin:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Eşleşen bir device interface geldiğinde bir service'i başlatır. Herhangi bir data item belirtilmemişse, trigger subtype GUID'siyle eşleşen herhangi bir device trigger'ı fire eder. Boot sırasında ve hot-plug gerçekleştiğinde değerlendirilir.<sup>[[1]](#references)</sup>

- Activation: Trigger subtype tarafından belirtilen class/hardware ID ile eşleşen bir device'ı (physical veya virtual) bağlayın/takın.

### Domain Join State

Kafa karıştırıcı MSDN wording'ine rağmen bu, boot sırasında domain state'i değerlendirir:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → domain-joined ise service'i başlatır
- DOMAIN_LEAVE_GUID → yalnızca domain-joined DEĞİLSE service'i başlatır

### System State Change – WNF (undocumented)

Bazı service'ler undocumented WNF-based trigger'lar kullanır (SERVICE_TRIGGER_TYPE 0x7). Activation, ilgili WNF state'in publish edilmesini gerektirir; ayrıntılar state name'e bağlıdır. Araştırma arka planı: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Windows 11'de bazı service'lerde (ör. CDPSvc) gözlemlenir. Aggregated configuration şurada saklanır:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Bir service'in Trigger value'su bir GUID'dir; bu GUID'ye sahip subkey, aggregated event'i tanımlar. Constituent event'lerden herhangi birinin trigger edilmesi service'i başlatır.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Belirli bir port/protocol kapsamındaki bir trigger'ın yalnızca belirtilen portta değil, herhangi bir firewall rule değişikliğinde (disable/delete/add) başlatıldığı gözlemlenmiştir. Daha da kötüsü, protocol belirtilmeden bir port yapılandırmak reboot'lar boyunca BFE startup'ını bozabilir; bu da birçok service failure'ına ve firewall management'ın bozulmasına yol açar. Son derece dikkatli kullanın.<sup>[[1]](#references)</sup>

## Practical Workflow

1) İlgilenilen service'lerde trigger'ları enumerate edin (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Bir Network Endpoint trigger mevcutsa:
- Named pipe → \\.\pipe\<PipeName> adresine client open denemesi yapın
- RPC endpoint → interface UUID için bir Endpoint Mapper lookup gerçekleştirin

3) Bir ETW trigger mevcutsa:
- `sc.exe qtriggerinfo` ile provider ve filter'ları kontrol edin; filter yoksa bu provider'dan gelen herhangi bir event service'i başlatır

4) Group Policy/IP/Device/Domain trigger'ları için:
- Environmental lever'ları kullanın: `gpupdate /force`, NIC'leri toggle etme, device'ları hot-plug etme vb.

## Related

- Bir Named Pipe trigger üzerinden privileged bir service'i başlattıktan sonra onu impersonate edebilirsiniz:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Trigger'ları listeleme (local): `sc.exe qtriggerinfo <Service>`
- Registry görünümü: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Önce `sc.exe qc <Service>` ile service start type'ını kontrol edin. `DISABLED` ise trigger'ı fire etmek yeterli değildir; önce configuration'ı değiştirmenin bir yolunu bulmanız gerekir.
- Trigger-start service'ler idle hâle geldikten sonra tekrar stop olabilir. Follow-on action kısa ömürlü bir listener'a (RPC/named pipe/WebDAV) bağlıysa trigger'layın ve hemen consume edin.
- `sc.exe qtriggerinfo`, her undocumented trigger type'ını tam olarak anlayamaz. Daha yeni Windows build'lerindeki aggregate trigger'lar için backing GUID'yi ve constituent event'leri `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` içinde doğrulayın.

## Detection and Hardening Notes

- Service'ler genelinde TriggerInfo için baseline oluşturun ve audit gerçekleştirin. Ayrıca aggregate trigger'lar için HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents'i inceleyin.
- Privileged service UUID'leri için şüpheli EPM lookup'larını ve service start'larından önce gerçekleşen named-pipe connection attempt'lerini izleyin.
- Service trigger'larını kimin değiştirebileceğini kısıtlayın; trigger değişikliklerinden sonra meydana gelen beklenmedik BFE failure'larını şüpheli kabul edin.

## References
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
