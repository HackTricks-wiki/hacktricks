# macOS Ağ Hizmetleri ve Protokoller

{{#include ../../banners/hacktricks-training.md}}

## Uzaktan Erişim Hizmetleri

Bunlar, uzaktan erişim için yaygın macOS hizmetleridir.\
Bu hizmetleri `Sistem Ayarları` --> `Paylaşım` bölümünden etkinleştirebilir/devre dışı bırakabilirsiniz.

- **VNC**, “Ekran Paylaşımı” olarak bilinir (tcp:5900)
- **SSH**, “Uzaktan Giriş” olarak adlandırılır (tcp:22)
- **Apple Remote Desktop** (ARD), veya “Uzaktan Yönetim” (tcp:3283, tcp:5900)
- **AppleEvent**, “Uzaktan Apple Olayı” olarak bilinir (tcp:3031)

Herhangi birinin etkin olup olmadığını kontrol etmek için:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD), macOS için özel olarak tasarlanmış, ek özellikler sunan [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) 'nin geliştirilmiş bir versiyonudur. ARD'deki dikkat çekici bir zafiyet, kontrol ekranı şifresi için kullanılan kimlik doğrulama yöntemidir; bu yöntem yalnızca şifrenin ilk 8 karakterini kullanır, bu da onu [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) gibi Hydra veya [GoRedShell](https://github.com/ahhh/GoRedShell/) gibi araçlarla saldırılara karşı savunmasız hale getirir, çünkü varsayılan hız sınırlamaları yoktur.

Zayıf noktaları olan örnekler, **nmap**'in `vnc-info` betiği kullanılarak tespit edilebilir. `VNC Authentication (2)`'yi destekleyen hizmetler, 8 karakterli şifre kısaltması nedeniyle brute force saldırılarına özellikle açıktır.

ARD'yi ayrıcalık yükseltme, GUI erişimi veya kullanıcı izleme gibi çeşitli yönetim görevleri için etkinleştirmek için aşağıdaki komutu kullanın:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD, gözlem, paylaşılan kontrol ve tam kontrol dahil olmak üzere çok yönlü kontrol seviyeleri sağlar ve oturumlar kullanıcı şifre değişikliklerinden sonra bile devam eder. Unix komutlarını doğrudan göndermeye ve bunları yönetici kullanıcılar için root olarak çalıştırmaya olanak tanır. Görev zamanlama ve Uzaktan Spotlight arama, birden fazla makine arasında hassas dosyalar için uzaktan, düşük etkili aramalar yapmayı kolaylaştıran dikkate değer özelliklerdir.

## Bonjour Protokolü

Apple tarafından tasarlanan Bonjour, **aynı ağdaki cihazların birbirlerinin sunduğu hizmetleri tespit etmesine olanak tanır**. Rendezvous, **Zero Configuration** veya Zeroconf olarak da bilinen bu teknoloji, bir cihazın TCP/IP ağına katılmasını, **otomatik olarak bir IP adresi seçmesini** ve hizmetlerini diğer ağ cihazlarına yayınlamasını sağlar.

Bonjour tarafından sağlanan Zero Configuration Networking, cihazların:

- **Otomatik olarak bir IP Adresi almasını** sağlar, DHCP sunucusu yoksa bile.
- **isimden-adrese çeviri** yapmasını, DNS sunucusu gerektirmeden gerçekleştirir.
- Ağda mevcut olan **hizmetleri keşfetmesini** sağlar.

Bonjour kullanan cihazlar, kendilerine **169.254/16 aralığından bir IP adresi atar** ve ağdaki benzersizliğini doğrular. Mac'ler, bu alt ağ için bir yönlendirme tablosu girişi tutar, bu giriş `netstat -rn | grep 169` ile doğrulanabilir.

DNS için Bonjour, **Multicast DNS (mDNS) protokolünü** kullanır. mDNS, **port 5353/UDP** üzerinden çalışır ve **standart DNS sorgularını** kullanarak **multicast adresi 224.0.0.251**'yi hedef alır. Bu yaklaşım, ağdaki tüm dinleyen cihazların sorguları almasını ve yanıt vermesini sağlar, böylece kayıtlarını güncelleyebilirler.

Ağa katıldığında, her cihaz kendine bir isim seçer, genellikle **.local** ile biter ve bu isim, ana bilgisayar adından türetilmiş veya rastgele oluşturulmuş olabilir.

Ağ içindeki hizmet keşfi, **DNS Hizmet Keşfi (DNS-SD)** ile kolaylaştırılır. DNS SRV kayıtlarının formatını kullanan DNS-SD, birden fazla hizmetin listelenmesini sağlamak için **DNS PTR kayıtlarını** kullanır. Belirli bir hizmet arayan bir istemci, `<Service>.<Domain>` için bir PTR kaydı talep eder ve eğer hizmet birden fazla ana bilgisayardan mevcutsa, `<Instance>.<Service>.<Domain>` formatında bir dizi PTR kaydı alır.

`dns-sd` aracı, **ağ hizmetlerini keşfetmek ve tanıtmak için** kullanılabilir. İşte kullanımına dair bazı örnekler:

### SSH Hizmetlerini Arama

Ağda SSH hizmetlerini aramak için aşağıdaki komut kullanılır:
```bash
dns-sd -B _ssh._tcp
```
Bu komut, \_ssh.\_tcp hizmetleri için tarama başlatır ve zaman damgası, bayraklar, arayüz, alan, hizmet türü ve örnek adı gibi ayrıntıları çıktılar. 

### HTTP Hizmetini Duyurma

Bir HTTP hizmetini duyurmak için şunu kullanabilirsiniz:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Bu komut, `/index.html` yolu ile port 80'de "Index" adında bir HTTP hizmeti kaydeder.

Daha sonra ağda HTTP hizmetlerini aramak için:
```bash
dns-sd -B _http._tcp
```
Bir hizmet başladığında, varlığını alt ağdaki tüm cihazlara çoklu yayın yaparak duyurur. Bu hizmetlerle ilgilenen cihazların istek göndermesine gerek yoktur, sadece bu duyuruları dinlemeleri yeterlidir.

Daha kullanıcı dostu bir arayüz için, Apple App Store'da bulunan **Discovery - DNS-SD Browser** uygulaması, yerel ağınızdaki sunulan hizmetleri görselleştirebilir.

Alternatif olarak, `python-zeroconf` kütüphanesini kullanarak hizmetleri taramak ve keşfetmek için özel betikler yazılabilir. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) betiği, `_http._tcp.local.` hizmetleri için bir hizmet tarayıcısı oluşturmayı gösterir ve eklenen veya kaldırılan hizmetleri yazdırır:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Bonjour'u Devre Dışı Bırakma

Eğer güvenlik endişeleri veya Bonjour'u devre dışı bırakmak için başka nedenler varsa, aşağıdaki komut kullanılarak kapatılabilir:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referanslar

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
