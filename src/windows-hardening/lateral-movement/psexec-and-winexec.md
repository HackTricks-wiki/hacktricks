# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

{% embed url="https://websec.nl/" %}

## Nasıl çalışırlar

Süreç, aşağıdaki adımlarda özetlenmiştir ve hizmet ikili dosyalarının, SMB üzerinden hedef makinede uzaktan yürütme sağlamak için nasıl manipüle edildiğini göstermektedir:

1. **Bir hizmet ikili dosyasının ADMIN$ paylaşımına SMB üzerinden kopyalanması** gerçekleştirilir.
2. **Uzaktaki makinede bir hizmetin oluşturulması**, ikili dosyaya işaret edilerek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'i Manuel Olarak Yürütme Süreci**

Antivirüs tespitinden kaçınmak için Veil kullanılarak obfuscate edilmiş, 'met8888.exe' adında bir yürütülebilir yük (msfvenom ile oluşturulmuş) olduğu varsayılarak, aşağıdaki adımlar izlenir:

- **İkili dosyanın kopyalanması**: Yürütülebilir dosya, komut istemcisinden ADMIN$ paylaşımına kopyalanır, ancak dosya sisteminde gizli kalmak için herhangi bir yere yerleştirilebilir.
- **Bir hizmetin oluşturulması**: Windows `sc` komutunu kullanarak, uzaktan Windows hizmetlerini sorgulama, oluşturma ve silme imkanı sağlayan bir hizmet "meterpreter" adıyla yüklenen ikili dosyaya işaret edecek şekilde oluşturulur.
- **Hizmetin başlatılması**: Son adım, hizmetin başlatılmasıdır; bu, ikili dosyanın gerçek bir hizmet ikili dosyası olmaması ve beklenen yanıt kodunu döndürmemesi nedeniyle muhtemelen bir "zaman aşımı" hatası ile sonuçlanacaktır. Bu hata önemsizdir çünkü asıl hedef ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin gözlemlenmesi, oturumun başarıyla başlatıldığını gösterecektir.

[sc komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals ikilisi PsExec.exe'yi de kullanabilirsiniz:**

![](<../../images/image (928).png>)

Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
