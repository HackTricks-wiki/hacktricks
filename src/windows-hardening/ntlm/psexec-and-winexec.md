# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışırlar

Süreç, aşağıdaki adımlarda özetlenmiştir ve hizmet ikili dosyalarının nasıl manipüle edildiğini gösterir, böylece SMB üzerinden hedef makinede uzaktan yürütme sağlanır:

1. **Bir hizmet ikili dosyasının ADMIN$ paylaşımına SMB üzerinden kopyalanması** gerçekleştirilir.
2. **Uzaktaki makinede bir hizmetin oluşturulması**, ikili dosyaya işaret edilerek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'i Manuel Olarak Çalıştırma Süreci**

Antivirüs tespitinden kaçınmak için msfvenom ile oluşturulmuş ve Veil kullanılarak obfuscate edilmiş bir yürütülebilir yük olduğunu varsayalım, 'met8888.exe' adında, bir meterpreter reverse_http yükünü temsil eder, aşağıdaki adımlar izlenir:

- **İkili dosyanın kopyalanması**: Yürütülebilir dosya, bir komut istemcisinden ADMIN$ paylaşımına kopyalanır, ancak dosya sisteminde gizli kalmak için herhangi bir yere yerleştirilebilir.

- **Bir hizmetin oluşturulması**: Windows `sc` komutunu kullanarak, uzaktan Windows hizmetlerini sorgulama, oluşturma ve silme imkanı sağlayan, yüklenen ikili dosyaya işaret eden "meterpreter" adında bir hizmet oluşturulur.

- **Hizmetin başlatılması**: Son adım, hizmetin başlatılmasıdır; bu, ikili dosyanın gerçek bir hizmet ikili dosyası olmaması ve beklenen yanıt kodunu döndürmemesi nedeniyle muhtemelen bir "zaman aşımı" hatası ile sonuçlanacaktır. Bu hata önemsizdir çünkü asıl hedef ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin gözlemlenmesi, oturumun başarıyla başlatıldığını gösterecektir.

[sc komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals ikili dosyası PsExec.exe'yi de kullanabilirsiniz:**

![](<../../images/image (165).png>)

Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
