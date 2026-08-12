# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalışır

Service Control Manager Remote Protocol (SCMR), uzak bir bilgisayardaki Windows servislerini yapılandırmak ve kontrol etmek için kullanılan RPC tabanlı bir protokoldür. Yeterli izinlere sahip bir operator, binary path alanında bir komut bulunan bir service oluşturabilir veya yeniden yapılandırabilir ve ardından komutu uzaktan çalıştırmak için bu service'i başlatabilir.<sup>[[1]](#references)</sup>

Herhangi bir service account belirtilmezse, `CreateService` kapsamlı yerel ayrıcalıklara sahip olan `LocalSystem` hesabını kullanır. Bu durum, başarılı SCM execution işleminin yüksek etkisini açıklar. Bu işlem doğası gereği UAC veya Microsoft Defender'ı devre dışı bırakmaz: çağıranın hâlâ uzak SCM izinlerine sahip olması gerekir ve endpoint kontrolleri service'i veya payload'ı inceleyebilir ya da engelleyebilir.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Araçlar

**SharpMove**, SCM ve diğer çeşitli Windows mekanizmaları üzerinden kimlik doğrulamalı uzak execution işlemini destekler. Aşağıdaki örnek SCM action'ını seçer, `WindowsDebug` adlı bir service oluşturur ve bu service'i uzak host üzerinde önceden mevcut olan bir payload'a yönlendirir.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol genel bakışı](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem hesabı](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService` işlevi](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
