# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Nasıl çalışır

Hizmet ikili dosyalarının, SMB üzerinden hedef makinede uzaktan yürütme sağlamak için nasıl manipüle edildiğini gösteren adımlar aşağıda özetlenmiştir:

1. **ADMIN$ paylaşımına bir hizmet ikili dosyasının kopyalanması** gerçekleştirilir.
2. **Uzaktaki makinede bir hizmetin oluşturulması**, ikili dosyaya işaret edilerek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'i Manuel Olarak Çalıştırma Süreci**

Antivirüs tespitinden kaçınmak için Veil kullanılarak obfuscate edilmiş msfvenom ile oluşturulmuş bir yürütülebilir yük (payload) olan 'met8888.exe' adında bir dosya olduğu varsayılarak, aşağıdaki adımlar izlenir:

- **İkili dosyanın kopyalanması**: Yürütülebilir dosya, komut istemcisinden ADMIN$ paylaşımına kopyalanır, ancak dosya sistemi üzerinde gizli kalmak için herhangi bir yere yerleştirilebilir.

- **Bir hizmet oluşturma**: Windows `sc` komutunu kullanarak, uzaktan Windows hizmetlerini sorgulama, oluşturma ve silme imkanı sağlayan bir hizmet "meterpreter" adıyla yüklenen ikili dosyaya işaret edecek şekilde oluşturulur.

- **Hizmeti başlatma**: Son adım, hizmetin başlatılmasıdır; bu, ikili dosyanın gerçek bir hizmet ikili dosyası olmaması ve beklenen yanıt kodunu döndürmemesi nedeniyle muhtemelen bir "zaman aşımı" hatası ile sonuçlanacaktır. Bu hata önemsizdir çünkü asıl hedef ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin gözlemlenmesi, oturumun başarıyla başlatıldığını gösterecektir.

[`sc` komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals ikili dosyası PsExec.exe'yi de kullanabilirsiniz:**

![](<../../images/image (165).png>)

Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<figure><img src="/images/image (48).png" alt=""><figcaption></figcaption></figure>

Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{{#include ../../banners/hacktricks-training.md}}
