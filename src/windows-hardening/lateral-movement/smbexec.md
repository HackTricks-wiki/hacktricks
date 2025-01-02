# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalışır

**Smbexec**, Windows sistemlerinde uzaktan komut yürütmek için kullanılan bir araçtır, **Psexec**'e benzer, ancak hedef sistemde herhangi bir zararlı dosya bırakmaktan kaçınır.

### **SMBExec** Hakkında Ana Noktalar

- Hedef makinede cmd.exe (%COMSPEC%) aracılığıyla komutları yürütmek için geçici bir hizmet (örneğin, "BTOBTO") oluşturarak çalışır, herhangi bir ikili dosya bırakmaz.
- Gizli yaklaşımına rağmen, yürütülen her komut için olay günlükleri oluşturur ve etkileşimsiz bir "shell" biçimi sunar.
- **Smbexec** kullanarak bağlanma komutu şu şekildedir:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Binariesiz Komut Çalıştırma

- **Smbexec**, hedefte fiziksel ikili dosyalar olmaksızın hizmet binPath'leri aracılığıyla doğrudan komut yürütmeyi sağlar.
- Bu yöntem, bir Windows hedefinde tek seferlik komutlar yürütmek için faydalıdır. Örneğin, Metasploit'in `web_delivery` modülü ile birleştirildiğinde, PowerShell hedefli ters Meterpreter yükünün yürütülmesini sağlar.
- Saldırganın makinesinde binPath'i cmd.exe aracılığıyla sağlanan komutu çalıştıracak şekilde ayarlayarak uzaktan bir hizmet oluşturmak, yükün başarılı bir şekilde yürütülmesini sağlamakta ve Metasploit dinleyicisi ile geri çağırma ve yük yürütme elde etmekte mümkündür; hizmet yanıt hataları olsa bile.

### Komutlar Örneği

Hizmeti oluşturmak ve başlatmak aşağıdaki komutlarla gerçekleştirilebilir:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Daha fazla detay için [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Referanslar

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


{{#include ../../banners/hacktricks-training.md}}
