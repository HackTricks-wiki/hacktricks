# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve bulutunuz hakkında bir hacker perspektifi edinin**

**Gerçek iş etkisi olan kritik, istismar edilebilir güvenlik açıklarını bulun ve raporlayın.** Saldırı yüzeyini haritalamak, ayrıcalıkları artırmanıza izin veren güvenlik sorunlarını bulmak ve temel kanıtları toplamak için otomatik istismarları kullanmak için 20'den fazla özel aracımızı kullanın, böylece sıkı çalışmanızı ikna edici raporlara dönüştürün.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Nasıl Çalışır

**Smbexec**, Windows sistemlerinde uzaktan komut yürütmek için kullanılan bir araçtır, **Psexec**'e benzer, ancak hedef sistemde herhangi bir kötü amaçlı dosya bırakmaktan kaçınır.

### **SMBExec** Hakkında Ana Noktalar

- Hedef makinede komutları cmd.exe (%COMSPEC%) aracılığıyla yürütmek için geçici bir hizmet (örneğin, "BTOBTO") oluşturarak çalışır, herhangi bir ikili dosya bırakmaz.
- Gizli yaklaşımına rağmen, yürütülen her komut için olay günlükleri oluşturur ve etkileşimsiz bir "shell" biçimi sunar.
- **Smbexec** kullanarak bağlanmak için komut şu şekildedir:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Binariesiz Komut Çalıştırma

- **Smbexec**, hedefte fiziksel binary'lere ihtiyaç duymadan, hizmet binPath'leri aracılığıyla doğrudan komut yürütmeyi sağlar.
- Bu yöntem, bir Windows hedefinde tek seferlik komutlar yürütmek için faydalıdır. Örneğin, Metasploit'in `web_delivery` modülü ile birleştirildiğinde, PowerShell hedefli ters Meterpreter yükünün yürütülmesini sağlar.
- Saldırganın makinesinde binPath'i cmd.exe aracılığıyla sağlanan komutu çalıştıracak şekilde ayarlayarak uzaktan bir hizmet oluşturmak, yükü başarıyla yürütmek, geri çağırma ve yük yürütme sağlamak mümkündür; bu, hizmet yanıt hataları olsa bile Metasploit dinleyicisi ile gerçekleşir.

### Komut Örneği

Hizmeti oluşturmak ve başlatmak aşağıdaki komutlarla gerçekleştirilebilir:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Daha fazla bilgi için [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referanslar

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve bulutunuz hakkında bir hacker perspektifi edinin**

**Gerçek iş etkisi olan kritik, istismar edilebilir güvenlik açıklarını bulun ve raporlayın.** Saldırı yüzeyini haritalamak, ayrıcalıkları artırmanıza izin veren güvenlik sorunlarını bulmak ve temel kanıtları toplamak için otomatik istismarları kullanmak için 20'den fazla özel aracımızı kullanın, böylece sıkı çalışmanızı ikna edici raporlara dönüştürebilirsiniz.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
