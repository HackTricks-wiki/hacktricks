# Windows Service Triggers: Enumeration and Abuse

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers, Service Control Manager (SCM)’nin bir koşul gerçekleştiğinde bir service başlatmasına/durdurmasına izin verir (örn. bir IP address kullanılabilir hale gelir, bir named pipe connection girişimi yapılır, bir ETW event yayınlanır). Hedef service üzerinde SERVICE_START yetkiniz olmasa bile, trigger’ını tetikleyerek onu yine de başlatabilirsiniz.

Bu sayfa, saldırgan dostu enumeration ve yaygın trigger’ları etkinleştirmek için düşük sürtünmeli yöntemlere odaklanır.

> Tip: Privileged built-in bir service’i başlatmak (örn. RemoteRegistry, WebClient/WebDAV, EFS), yeni RPC/named-pipe listener’larını açığa çıkarabilir ve ek abuse chain’lerinin kilidini açabilir.

## Enumerating Service Triggers

- sc.exe (local)
- Bir service’in trigger’larını listele: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Trigger’lar şurada bulunur: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekürsif döküm: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_TRIGGER_INFO almak için SERVICE_CONFIG_TRIGGER_INFO (8) ile QueryServiceConfig2 çağır.
- Docs: QueryServiceConfig2[W/A] ve SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM, MS‑SCMR kullanılarak trigger info almak için uzaktan sorgulanabilir. TrustedSec’in Titanis aracı bunu sunar: `Scm.exe qtriggers`.
- Impacket, msrpc MS-SCMR içinde structure’ları tanımlar; bunları kullanarak remote query implemente edebilirsin.
- PowerShell (bulk enumeration)
- `TriggerInfo` key’si açığa çıkaran her service’i hızlıca listele:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- James Forshaw’un `NtObjectManager` module’ü, `sc.exe` output’unu parse etmeden trigger metadata’sını ayrıştırmak için `Get-Win32ServiceTrigger` sunar.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Bunlar, bir client IPC endpoint’i ile konuşmaya çalıştığında bir service’i başlatır. Low-priv kullanıcılar için kullanışlıdır; çünkü SCM, client’ın gerçekten bağlanabilmesinden önce service’i otomatik başlatır.

- Named pipe trigger
- Davranış: `\\.\pipe\<PipeName>` adresine yapılan client connection girişimi, SCM’nin service’i başlatmasına neden olur; böylece service dinlemeye başlayabilir.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- İç yapı notu: named-pipe trigger’ları, kayıtlı trigger pipe adlarına karşı open’ları izleyen bir filesystem minifilter olan `npsvctrig.sys` tarafından desteklenir. Bu yüzden open denemesi, service’in kendisi pipe’ı oluşturmadan/dinlemeden önce bile service’i başlatabilir.
- Ayrıca bak: Named Pipe Client Impersonation, start sonrası abuse için.

- RPC endpoint trigger (Endpoint Mapper)
- Davranış: Endpoint Mapper (EPM, TCP/135) üzerinde bir service ile ilişkili interface UUID’si sorgulamak, SCM’nin service’i başlatmasına neden olur; böylece endpoint’ini register edebilir.
- Activation (Impacket):
```bash
# Yerel EPM'i sorgular; UUID yerine service interface GUID'sini koy
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Bir service, bir ETW provider/event’e bağlı bir trigger register edebilir. Ek filtreler (keyword/level/binary/string) yapılandırılmamışsa, o provider’dan gelen herhangi bir event service’i başlatır.

- Örnek (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Trigger’ı listele: `sc.exe qtriggerinfo webclient`
- Provider’ın register edildiğini doğrula: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Eşleşen event’leri üretmek genellikle o provider’a log yazan code gerektirir; filtre yoksa herhangi bir event yeterlidir.
- Provider’ı tetiklemek için minimal C şekli (ek ETW filtreleri yoksa):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Alt türler: Machine/User. İlgili policy’nin mevcut olduğu domain-joined host’larda, trigger boot sırasında çalışır. `gpupdate` tek başına değişiklik olmadan trigger etmez, ancak:

- Activation: `gpupdate /force`
- İlgili policy type mevcutsa, bu güvenilir şekilde trigger’ı tetikler ve service’i başlatır.

### IP Address Available

İlk IP alındığında (veya son IP kaybedildiğinde) tetiklenir. Genellikle boot sırasında çalışır.

- Activation: Yeniden tetiklemek için connectivity’yi aç/kapat, örn.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Eşleşen bir device interface geldiğinde bir service’i başlatır. Eğer veri öğesi belirtilmemişse, trigger subtype GUID’si ile eşleşen herhangi bir device trigger’ı tetikler. Boot sırasında ve hot-plug anında değerlendirilir.

- Activation: Trigger subtype tarafından belirtilen class/hardware ID ile eşleşen bir device’ı bağla/tak (physical veya virtual).

### Domain Join State

MSDN’deki kafa karıştırıcı ifadeye rağmen, bu boot sırasında domain state’i değerlendirir:
- DOMAIN_JOIN_GUID → domain-joined ise service’i başlat
- DOMAIN_LEAVE_GUID → yalnızca domain-joined DEĞİLSE service’i başlat

### System State Change – WNF (undocumented)

Bazı service’ler undocumented WNF-based trigger’lar (SERVICE_TRIGGER_TYPE 0x7) kullanır. Activation, ilgili WNF state’inin yayınlanmasını gerektirir; ayrıntılar state name’e bağlıdır. Araştırma arka planı: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Windows 11’de bazı service’lerde (örn. CDPSvc) gözlemlenmiştir. Aggregate configuration şu yerde saklanır:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Bir service’in Trigger değeri bir GUID’dir; bu GUID’ye sahip subkey aggregated event’i tanımlar. Bileşen event’lerden herhangi birini tetiklemek service’i başlatır.

### Firewall Port Event (quirks and DoS risk)

Belirli bir port/protocol’e scoped bir trigger’ın, sadece belirtilen portta değil, herhangi bir firewall rule değişikliğinde (disable/delete/add) başladığı gözlemlenmiştir. Daha kötüsü, protocol olmadan bir port yapılandırmak, reboot’lar boyunca BFE startup’ını bozabilir; bu da çok sayıda service failure zincirine yol açar ve firewall management’i kırar. Son derece dikkatli olun.

## Practical Workflow

1) İlginç service’lerde trigger’ları enumerate et (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Eğer bir Network Endpoint trigger varsa:
- Named pipe → `\\.\pipe\<PipeName>` için bir client open dene
- RPC endpoint → interface UUID için bir Endpoint Mapper lookup yap

3) Eğer bir ETW trigger varsa:
- `sc.exe qtriggerinfo` ile provider ve filtreleri kontrol et; filtre yoksa o provider’dan gelen herhangi bir event service’i başlatır

4) Group Policy/IP/Device/Domain trigger’ları için:
- Çevresel araçları kullan: `gpupdate /force`, NIC’leri toggle et, hot-plug device’lar, vb.

## Related

- Named Pipe trigger aracılığıyla privileged bir service’i başlattıktan sonra, onu impersonate edebilirsin:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- Trigger’ları listele (local): `sc.exe qtriggerinfo <Service>`
- Registry görünümü: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Önce service start type’ını `sc.exe qc <Service>` ile kontrol et. Eğer `DISABLED` ise, trigger’ı tetiklemek yeterli değildir; önce configuration’ı değiştirecek bir yol bulmalısın.
- Trigger-start service’ler idle olduklarında tekrar durabilir. Sonraki aksiyonun kısa ömürlü bir listener’a (RPC/named pipe/WebDAV) bağlıysa, trigger et ve hemen consume et.
- `sc.exe qtriggerinfo`, her undocumented trigger type’ını tam olarak anlayamaz. Yeni Windows build’lerindeki aggregate trigger’lar için, backing GUID ve bileşen event’leri `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` içinde doğrula.

## Detection and Hardening Notes

- Tüm service’ler arasında TriggerInfo için baseline oluştur ve audit et. Ayrıca aggregate trigger’lar için HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents’i de incele.
- Privileged service UUID’leri için şüpheli EPM lookup’larını ve service start’tan önce gelen named-pipe connection girişimlerini izle.
- Service trigger’larını kimin değiştirebileceğini kısıtla; trigger değişikliklerinden sonra beklenmeyen BFE failure’larını şüpheli kabul et.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
