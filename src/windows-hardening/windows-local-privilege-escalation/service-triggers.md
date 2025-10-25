# Windows Service Triggers: Enumerasyon ve Kötüye Kullanım

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers, Service Control Manager (SCM)'ın bir koşul oluştuğunda bir servisi başlatmasına/durdurmasına izin verir (ör. bir IP adresi kullanıma girdiğinde, bir named pipe bağlantısı denendiğinde, bir ETW olayı yayınlandığında). Hedef serviste SERVICE_START haklarınız olmasa bile, tetikleyicisini harekete geçirerek servisi başlatabilmeniz mümkündür.

Bu sayfa, saldırgan-dostu enumerasyon ve yaygın tetikleyicileri aktive etmenin düşük sürtünmeli yollarına odaklanır.

> İpucu: Ayrıcalıklı bir yerleşik servisi (ör. RemoteRegistry, WebClient/WebDAV, EFS) başlatmak yeni RPC/named-pipe dinleyicilerini açığa çıkarabilir ve ek kötüye kullanım zincirlerini mümkün kılabilir.

## Servis Tetikleyicilerinin Enumerasyonu

- sc.exe (local)
- Bir servisin tetikleyicilerini listele: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Tetikleyiciler burada bulunur: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Rekürsif döküm: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- SERVICE_TRIGGER_INFO almak için QueryServiceConfig2'yi SERVICE_CONFIG_TRIGGER_INFO (8) ile çağırın.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM, tetikleyici bilgisini almak için uzaktan MS‑SCMR üzerinden sorgulanabilir. TrustedSec’in Titanis bunu sunar: `Scm.exe qtriggers`.
- Impacket msrpc MS-SCMR içindeki yapıları tanımlar; bunları kullanarak uzak bir sorgu uygulayabilirsiniz.

## Yüksek Değerli Tetik Türleri ve Nasıl Aktive Edilirler

### Network Endpoint Triggers

Bunlar, bir istemci bir IPC uç noktasına bağlanmaya çalıştığında bir servisi başlatır. Düşük ayrıcalıklı kullanıcılar için faydalıdır çünkü SCM, istemcinin gerçekten bağlanmasından önce servisi otomatik olarak başlatacaktır.

- Named pipe tetikleyicisi
- Davranış: \\.\pipe\<PipeName>'e yapılan bir istemci bağlantı denemesi, SCM'nin servisi başlatmasına ve dinlemeye başlamasına neden olur.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Ayrıca bakınız: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Davranış: Endpoint Mapper (EPM, TCP/135) için bir servisle ilişkili interface UUID'si sorgulandığında, SCM servisin kendi endpoint'ini kaydetmesi için servisi başlatır.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Bir servis, bir ETW sağlayıcısına/olayına bağlı bir tetikleyici kaydedebilir. Eğer ek filtreler (keyword/level/binary/string) yapılandırılmamışsa, o sağlayıcıdan gelen herhangi bir olay servisi başlatır.

- Örnek (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Tetikleyici listesi: `sc.exe qtriggerinfo webclient`
- Sağlayıcının kayıtlı olduğunu doğrulayın: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Eşleşen olaylar genellikle o sağlayıcıya log kaydı yapan kod gerektirir; filtre yoksa herhangi bir olay yeterlidir.

### Grup İlkesi Tetikleyicileri

Alt tipler: Machine/User. İlgili politika mevcutsa domain'e bağlı makinelerde tetikleyici boot sırasında çalışır. `gpupdate` tek başına değişiklik olmadan tetiklemeyebilir, ancak:

- Activation: `gpupdate /force`
- İlgili politika türü mevcutsa, bu güvenilir şekilde tetikleyiciyi ateşler ve servisi başlatır.

### IP Address Available

İlk IP elde edildiğinde (veya sonuncusu kaybolduğunda) ateşlenir. Genellikle boot sırasında tetikler.

- Aktivasyon: Yeniden tetiklemek için bağlantıyı kapatıp açın, örn:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Eşleşen bir device interface geldiğinde bir servisi başlatır. Eğer veri öğesi belirtilmemişse, tetikleyici alt tip GUID'siyle eşleşen herhangi bir cihaz tetikleyiciyi ateşler. Boot sırasında ve hot‑plug sırasında değerlendirilir.

- Aktivasyon: Tetikleyici alt tipi tarafından belirtilen class/hardware ID ile eşleşen bir cihazı (fiziksel veya sanal) takın/ekleyin.

### Domain Join State

MSDN’deki kafa karıştırıcı ifadeye rağmen, bu boot sırasında domain durumunu değerlendirir:
- DOMAIN_JOIN_GUID → domain'e bağlıysa servisi başlat
- DOMAIN_LEAVE_GUID → sadece domain'e bağlı DEĞİLSE servisi başlat

### System State Change – WNF (belgelendirilmemiş)

Bazı servisler belgelendirilmemiş WNF tabanlı tetikleyiciler (SERVICE_TRIGGER_TYPE 0x7) kullanır. Aktivasyon, ilgili WNF state'i publish etmeyi gerektirir; ayrıntılar state adlarına bağlıdır. Araştırma arka planı: Windows Notification Facility içyapıları.

### Aggregate Service Triggers (belgelendirilmemiş)

Windows 11'de bazı servislerde (ör. CDPSvc) gözlemlenmiştir. Toplu yapılandırma şurada depolanır:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

Bir servisin Trigger değeri bir GUID'dir; o GUID ile alt anahtar toplanmış olayı tanımlar. İç bileşen olaylardan herhangi biri tetiklendiğinde servis başlatılır.

### Firewall Port Event (tuhaflıklar ve DoS riski)

Belirli bir port/protokol ile sınırlı bir tetikleyicinin, yalnızca belirtilen port için değil herhangi bir firewall kuralı değişikliğinde (disable/delete/add) başladığı gözlemlenmiştir. Daha da kötüsü, bir porta protokol olmadan yapılandırma BFE başlangıcını reboottan sonra bozabilir, bu da birçok servisin başarısız olmasına ve firewall yönetiminin bozulmasına yol açabilir. Aşırı dikkatle ele alın.

## Pratik İş Akışı

1) İlginç servislerdeki tetikleyicileri enumerate edin (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Eğer bir Network Endpoint tetikleyicisi varsa:
- Named pipe → \\.\pipe\<PipeName> için istemci open denemesi yapın
- RPC endpoint → interface UUID için Endpoint Mapper sorgusu yapın

3) Eğer bir ETW tetikleyicisi varsa:
- Sağlayıcıyı ve filtreleri `sc.exe qtriggerinfo` ile kontrol edin; filtre yoksa o sağlayıcıdan gelen herhangi bir olay servisi başlatır

4) Grup İlkesi/IP/Cihaz/Domain tetikleyicileri için:
- Çevresel kaldıraçları kullanın: `gpupdate /force`, NIC'leri toggle edin, cihazları hot-plug yapın, vb.

## İlgili

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Hızlı komut özeti

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Tespit ve Sertleştirme Notları

- TriggerInfo'yu servisler genelinde temel alın ve denetleyin. Ayrıca toplu tetikleyiciler için HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents'i inceleyin.
- Ayrıcalıklı servis UUID'leri için şüpheli EPM sorgularını ve servis başlatılmasından önce yapılan named-pipe bağlantı denemelerini izleyin.
- Kimlerin servis tetikleyicilerini değiştirebileceğini kısıtlayın; tetikleyici değişikliklerinden sonra beklenmeyen BFE hatalarını şüpheli olarak ele alın.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
