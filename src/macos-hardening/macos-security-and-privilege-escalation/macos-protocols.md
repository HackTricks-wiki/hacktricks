# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Bunlar, uzaktan erişmek için kullanılan yaygın macOS servisleridir.\
Bu servisleri `System Settings` --> `Sharing` içinde etkinleştirebilir/devre dışı bırakabilirsiniz

- **VNC**, “Screen Sharing” olarak bilinir (tcp:5900)
- **SSH**, “Remote Login” olarak adlandırılır (tcp:22)
- **Apple Remote Desktop** (ARD), veya “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, “Remote Apple Event” olarak bilinir (tcp:3031)

Herhangi birinin etkin olup olmadığını kontrol etmek için çalıştırın:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Yerel olarak paylaşım yapılandırmasını numaralandırma

Mac üzerinde zaten local code execution elde ettiğinizde, yalnızca listening sockets’e bakmayın, **yapılandırılmış durumu kontrol edin**. `systemsetup` ve `launchctl` genellikle servisin yönetimsel olarak etkin olup olmadığını söylerken, `kickstart` ve `system_profiler` etkin ARD/Sharing yapılandırmasını doğrulamaya yardımcı olur:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD), macOS için uyarlanmış, ek özellikler sunan [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) gelişmiş bir sürümüdür. ARD’deki dikkat çekici bir zafiyet, kontrol ekranı parolası için kullandığı kimlik doğrulama yöntemidir; bu yöntem parolanın yalnızca ilk 8 karakterini kullanır ve bu da onu Hydra veya [GoRedShell](https://github.com/ahhh/GoRedShell/) gibi araçlarla [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) karşı savunmasız hale getirir, çünkü varsayılan hız sınırları yoktur.

Zafiyetli örnekler, **nmap**'in `vnc-info` script'i ile tespit edilebilir. `VNC Authentication (2)` destekleyen servisler, 8 karakterlik parola kısaltması nedeniyle özellikle brute force attacks’a açıktır.

Privilege escalation, GUI erişimi veya kullanıcı izleme gibi çeşitli yönetim görevleri için ARD'yi etkinleştirmek amacıyla aşağıdaki komutu kullanın:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD, oturumlar kullanıcı parola değişikliklerinden sonra bile devam ederek gözlem, paylaşılan kontrol ve tam kontrol dahil olmak üzere çok yönlü kontrol seviyeleri sağlar. Unix komutlarını doğrudan göndermeye izin verir ve bunları yönetici kullanıcılar için root olarak çalıştırır. Görev zamanlama ve Remote Spotlight araması dikkat çeken özelliklerdir; bunlar birden fazla makinede hassas dosyalar için uzaktan, düşük etkili aramaları kolaylaştırır.

Bir operatör bakış açısından, **Monterey 12.1+ yönetilen filolarda remote-enablement iş akışlarını değiştirdi**. Eğer kurbanın MDM'sini zaten kontrol ediyorsanız, Apple'ın `EnableRemoteDesktop` komutu yeni sistemlerde remote desktop işlevini etkinleştirmenin çoğu zaman en temiz yoludur. Eğer host üzerinde zaten bir foothold'a sahipseniz, `kickstart` komut satırından ARD ayrıcalıklarını incelemek veya yeniden yapılandırmak için hâlâ kullanışlıdır.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple bu özelliğe modern System Settings içinde **Remote Application Scripting** der. İçeride, **Apple Event Manager**'ı uzaktan **EPPC** üzerinden **TCP/3031** üzerinde `com.apple.AEServer` servisi aracılığıyla sunar. Palo Alto Unit 42 bunu yeniden, geçerli kimlik bilgileri ve etkin bir RAE servisi bir operatörün uzak bir Mac üzerindeki scriptable uygulamaları kontrol etmesine izin verdiği için pratik bir **macOS lateral movement** primiitif olarak vurguladı.

Faydalı kontroller:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Hedefte zaten admin/root yetkiniz varsa ve bunu etkinleştirmek istiyorsanız:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Başka bir Mac’ten temel bağlantı testi:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Uygulamada, abuse case yalnızca Finder ile sınırlı değildir. Gerekli Apple events’i kabul eden herhangi bir **scriptable application**, bir remote attack surface haline gelir; bu da credential theft sonrası internal macOS networks üzerinde RAE’yi özellikle ilginç kılar.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* *Screen Sharing*/*Remote Management* gerekmedikçe devre dışı bırakın.
* macOS’i tamamen güncel tutun (Apple genellikle son üç büyük sürüm için security fixes yayınlar).
* Bir **Strong Password** kullanın ve mümkünse *“VNC viewers may control screen with password”* seçeneğinin **disabled** olduğundan emin olun.
* Servisi Internet’e açmak yerine bir VPN arkasına koyun; TCP 5900/3283 portlarını doğrudan expose etmeyin.
* `ARDAgent`’i local subnet ile sınırlamak için bir Application Firewall kuralı ekleyin:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple tarafından tasarlanan bir teknoloji olan Bonjour, **aynı ağdaki cihazların birbirlerinin sunduğu hizmetleri tespit etmesine** izin verir. Rendezvous, **Zero Configuration** veya Zeroconf olarak da bilinir; bir cihazın TCP/IP network’e katılmasını, **otomatik olarak bir IP address seçmesini** ve hizmetlerini diğer network cihazlarına yayınlamasını sağlar.

Bonjour tarafından sağlanan Zero Configuration Networking, cihazların şunları yapabilmesini sağlar:

- DHCP server olmasa bile **otomatik olarak bir IP Address almasını**.
- DNS server gerektirmeden **isimden adrese çeviri** yapmasını.
- Ağda bulunan **services**’leri keşfetmesini.

Bonjour kullanan cihazlar kendilerine **169.254/16 aralığından bir IP address** atar ve ağ üzerindeki benzersizliğini doğrular. Mac’ler bu subnet için bir routing table girdisi tutar; bunu `netstat -rn | grep 169` ile doğrulayabilirsiniz.

DNS için Bonjour, **Multicast DNS (mDNS) protocol**’ünü kullanır. mDNS, **port 5353/UDP** üzerinden çalışır, **standard DNS queries** kullanır ancak bunları **multicast address 224.0.0.251** hedefine gönderir. Bu yaklaşım, ağdaki dinleyen tüm cihazların sorguları alıp yanıtlayabilmesini sağlar ve kayıtlarının güncellenmesini kolaylaştırır.

Ağa katıldıktan sonra her cihaz kendi adını seçer; bu ad genellikle **.local** ile biter ve hostname’den türetilebilir veya rastgele oluşturulabilir.

Ağ içindeki service discovery, **DNS Service Discovery (DNS-SD)** ile sağlanır. DNS SRV record formatından yararlanan DNS-SD, birden fazla service’i listelemek için **DNS PTR records** kullanır. Belirli bir service arayan bir client, `<Service>.<Domain>` için bir PTR record ister; service birden fazla host üzerinden sunuluyorsa karşılık olarak `<Instance>.<Service>.<Domain>` biçiminde bir PTR records listesi alır.

`dns-sd` utility, **network services keşfetmek ve duyurmak** için kullanılabilir. Kullanımına dair bazı örnekler:

### Searching for SSH Services

Ağdaki SSH services’i aramak için şu command kullanılır:
```bash
dns-sd -B _ssh._tcp
```
Bu komut, \_ssh.\_tcp servisleri için taramayı başlatır ve zaman damgası, bayraklar, arayüz, domain, servis türü ve instance adı gibi ayrıntıları çıktı olarak verir.

### Bir HTTP Servisini Advertising Etme

Bir HTTP servisini advertising etmek için şunu kullanabilirsiniz:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Bu komut, 80 numaralı portta `/index.html` yoluyla "Index" adlı bir HTTP servisini kaydeder.

Ardından ağ üzerindeki HTTP servislerini aramak için:
```bash
dns-sd -B _http._tcp
```
Bir servis başladığında, alt ağdaki tüm cihazlara çoklama yaparak (multicasting) kendi varlığını duyurur. Bu servislerle ilgilenen cihazların istek göndermesine gerek yoktur; sadece bu duyuruları dinlerler.

Daha kullanıcı dostu bir arayüz için, Apple App Store’da bulunan **Discovery - DNS-SD Browser** uygulaması yerel ağınızdaki sunulan servisleri görselleştirebilir.

Alternatif olarak, `python-zeroconf` kütüphanesini kullanarak servisleri taramak ve keşfetmek için özel scriptler yazılabilir. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) scripti, `_http._tcp.local.` servisleri için bir service browser oluşturmayı ve eklenen veya kaldırılan servisleri yazdırmayı gösterir:
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
### macOS'a özgü Bonjour hunting

macOS ağlarında, Bonjour çoğu zaman hedefe doğrudan dokunmadan **remote administration surfaces** bulmanın en kolay yoludur. Apple Remote Desktop'in kendisi de istemcileri Bonjour üzerinden keşfedebilir; bu nedenle aynı keşif verisi bir saldırgan için de faydalıdır.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Daha geniş **mDNS spoofing, impersonation, ve cross-subnet discovery** teknikleri için özel sayfaya bakın:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Ağ üzerinde Bonjour envanterini çıkarma

* **Nmap NSE** – tek bir host tarafından duyurulan servisleri keşfeder:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script'i `_services._dns-sd._udp.local` sorgusu gönderir ve ardından duyurulan her servis türünü listeler.

* **mdns_recon** – *misconfigured* mDNS responder'ları arayan ve tüm aralıkları tarayan Python aracı; unicast sorgulara yanıt verenleri bulur (subnet'ler/WAN üzerinden erişilebilen cihazları bulmak için yararlıdır):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Bu, yerel bağlantı dışında Bonjour üzerinden SSH açığa çıkaran host'ları döndürür.

### Güvenlik hususları ve son zafiyetler (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* içindeki bir logic error, hazırlanmış bir packet'in **denial-of-service** tetiklemesine izin veriyordu|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* içindeki bir correctness issue, **local privilege escalation** için kötüye kullanılabiliyordu|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Azaltma önerileri**

1. UDP 5353'ü *link-local* kapsamıyla sınırlandırın – wireless controller'larda, router'larda ve host-based firewall'larda bloklayın veya rate-limit uygulayın.
2. Service discovery gerektirmeyen sistemlerde Bonjour'u tamamen devre dışı bırakın:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour'un dahili olarak gerekli olduğu ancak network sınırlarını asla geçmemesi gereken ortamlarda, *AirPlay Receiver* profile kısıtlamalarını (MDM) veya bir mDNS proxy kullanın.
4. **System Integrity Protection (SIP)**'i etkinleştirin ve macOS'i güncel tutun – yukarıdaki iki zafiyet hızla yamalandı, ancak tam koruma için SIP'nin etkin olmasına dayanıyordu.

### Bonjour'u devre dışı bırakma

Güvenlik veya başka nedenlerle Bonjour'u devre dışı bırakma konusunda endişeler varsa, aşağıdaki komutla kapatılabilir:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - macOS üzerinde Yan Hareket: Benzersiz ve Popüler Teknikler ve Gerçek Dünyadan Örnekler**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - macOS Sonoma 14.7.2’nin güvenlik içeriği hakkında**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
