# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalışır

Service Control Manager Remote Protocol (SCMR), uzak bir bilgisayardaki Windows services yapılandırmak ve kontrol etmek için kullanılan RPC tabanlı bir protokoldür. Yeterli izinlere sahip bir operator, binary path'i bir command içeren bir service oluşturabilir veya yeniden yapılandırabilir ve ardından command'i uzaktan execute etmek için bu service'i başlatabilir.<sup>[[1]](#references)</sup>

## Araçlar

**SharpMove**, SCM ve diğer birkaç Windows mekanizması üzerinden authenticated remote execution özelliğini destekler. Aşağıdaki örnek SCM action'ını seçer, `WindowsDebug` adlı bir service oluşturur ve bunu remote host'ta zaten bulunan bir payload'a yönlendirir.<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol genel bakışı](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
