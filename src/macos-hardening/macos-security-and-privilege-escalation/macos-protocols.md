# macOS Ağ Hizmetleri ve Protokolleri

{{#include ../../banners/hacktricks-training.md}}

## Uzaktan Erişim Hizmetleri

Bunlar macOS'a uzaktan erişmek için kullanılan yaygın hizmetlerdir.\
Bu hizmetleri `System Settings` --> `Sharing` bölümünden etkinleştirebilir/devre dışı bırakabilirsiniz.

- **VNC**, “Screen Sharing” olarak bilinir (tcp:5900)
- **SSH**, “Remote Login” olarak adlandırılır (tcp:22)
- **Apple Remote Desktop** (ARD) veya “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, “Remote Apple Event” olarak bilinir (tcp:3031)

Aşağıdakini çalıştırarak herhangi birinin etkin olup olmadığını kontrol edin:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Yerel olarak sharing yapılandırmasını numaralandırma

Bir Mac üzerinde zaten yerel code execution elde ettiğinizde, yalnızca listening socket'leri değil, **yapılandırılmış durumu** da kontrol edin. `systemsetup` ve `launchctl` genellikle servisin yönetimsel olarak etkin olup olmadığını gösterirken, `kickstart` ve `system_profiler` etkin ARD/Sharing yapılandırmasını doğrulamaya yardımcı olur:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD), macOS için uyarlanmış ve ek özellikler sunan [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) sürümüdür. ARD'deki dikkate değer bir vulnerability, kontrol ekranı parolası için kullanılan authentication yöntemidir. Bu yöntem parolanın yalnızca ilk 8 karakterini kullanır ve varsayılan rate limit'ler bulunmadığından Hydra veya [GoRedShell](https://github.com/ahhh/GoRedShell/) gibi araçlarla [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) saldırılarına açıktır.<sup>[[3]](#references)</sup>

Vulnerable instance'lar **nmap**'in `vnc-info` script'i kullanılarak tespit edilebilir. `VNC Authentication (2)` destekleyen servisler, 8 karakterlik parola truncation nedeniyle özellikle brute force attacks saldırılarına açıktır.

Privilege escalation, GUI erişimi veya user monitoring gibi çeşitli administrative task'ler için ARD'yi etkinleştirmek üzere aşağıdaki command'i kullanın:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD; gözlem, paylaşımlı kontrol ve tam kontrol dahil olmak üzere çok yönlü kontrol düzeyleri sunar ve kullanıcı parolaları değiştirilse bile oturumlar devam eder. Unix komutlarının doğrudan gönderilmesine ve bunların yönetici kullanıcılar için root olarak çalıştırılmasına olanak tanır. Görev zamanlama ve Remote Spotlight search, birden fazla makinede hassas dosyalar için uzaktan ve düşük etkili aramaları kolaylaştıran dikkat çekici özelliklerdir.

Operatör açısından, **Monterey 12.1+ yönetilen filolarda remote-enablement iş akışlarını değiştirdi**. Kurbanın MDM'sini zaten kontrol ediyorsanız, Apple'ın `EnableRemoteDesktop` komutu daha yeni sistemlerde remote desktop işlevini etkinleştirmenin çoğu zaman en temiz yoludur. Ana bilgisayarda zaten bir foothold'unuz varsa, `kickstart` komutu ARD ayrıcalıklarını komut satırından incelemek veya yeniden yapılandırmak için hâlâ kullanışlıdır.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Yakın zamanda yapılan `screensharingd` araştırması, Apple Screen Sharing'in her zaman yalnızca klasik VNC auth kullanmadığını gösterdi: daha yeni build'ler **RFB `003.889`** konuşur ve burada önce **SRP** ile authentication yapılır; **ChaCha20-Poly1305** ise yalnızca `ccsrp_server_verify_session` başarılı olduktan sonra etkinleştirilir. Public write-up, bug'ın **macOS Tahoe 26.6** sürümünde (**27 Temmuz 2026**) düzeltildiğini bildiriyor.<sup>[[8]](#references)[[9]](#references)</sup>

Hatırlanması gereken yararlı bir pattern, **stale-status parser bypass**'tır: başarılı bir 4-byte length read işleminden sonra, her oversized/error branch yeni bir error döndürmelidir. Etkilenen build'lerde, big-endian SRP frame length **`>= 32768`** olduğunda rejection path önceki `NetBufferRead` başarısını (`0`) yeniden kullanır; böylece caller, herhangi bir password proof çalıştırılmamış ve hiçbir transport crypto kurulmamış olsa bile session'ı authenticated olarak ayarlar. Okunmamış byte'lar paylaşılan socket buffer'da kaldığından attacker, **malformed SRP data ile post-auth RFB message'larını aynı TCP burst içinde pipeline'layabilir** ve bunların **cleartext authenticated traffic** olarak parse edilmesini sağlayabilir.<sup>[[8]](#references)</sup>

Bypass sonrasında, Apple'ın özel **file-copy** mesajı **`0x22`**, `screensharingd` root olarak çalıştığı için bir **root file read/write primitive** hâline gelir:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: arbitrary file read
- `kind=2` / `StartFileReceive`: arbitrary file write
- Farklı `sid` değerleri, tek bir bağlantıda birden fazla transaction'ı pipeline yapmanıza olanak tanır
- `kind=101` (`NewItem`) içinde, normal bir dosya için byte `14` / `arg[0]` değerini `0x01` olarak ayarlayın; payload offset `+42` değerini **sıfır olmayan** big-endian dosya boyutuna ve payload offset `+0x5a` değerini istenen Unix mode değerine (`crontab` hedefleniyorsa `0600`) ayarlayın

Writable path'ler üzerindeki ilginç post-write pivot'lar arasında **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** ve **`/var/root/.ssh/authorized_keys`** bulunur. **SIP, auth bypass'ı veya root file read işlemini engellemez**, ancak **`/var/at`** gibi bazı write target'larını engeller; bu nedenle cron tabanlı execution yalnızca SIP devre dışıyken çalışır. Varsayılan SIP-enabled host'larda, doğrudan code execution yerine **"privileged auto-consumed files içine root file write"** yaklaşımını düşünün.<sup>[[8]](#references)</sup>

Aynı araştırmadan bir başka SRP pitfall'ı: sunucular yalnızca `A > 0` değerini değil, (RFC 5054 uyarınca) **`A mod N != 0`** değerini de doğrulamalıdır. **`A = N`** değerinin kabul edilmesi, shared secret'ı sıfıra zorlayabilir ve password verification sürecini zayıflatabilir.<sup>[[8]](#references)[[10]](#references)</sup>

**Detection fikirleri**

- İlk SRP frame uzunluğu **`>= 32768`** olan Security type `36` session'ları
- Başarılı bir SRP proof / cipher install gerçekleşmeden önce cleartext **`0x22`** file-copy traffic'ini işlemeye başlayan session'lar
- **TCP/5900** üzerine tekrarlanan kısa ömürlü retry'lar ve tek bir burst içinde birden fazla file-copy `sid` değeri
- Screen Sharing exposure sonrasında beklenmedik şekilde oluşturulan **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** veya **`/var/root/.ssh/authorized_keys`**

### Pentesting Remote Apple Events (RAE / EPPC)

Apple, modern System Settings içinde bu özelliği **Remote Application Scripting** olarak adlandırır. Arka planda bu özellik, `com.apple.AEServer` service aracılığıyla **TCP/3031** üzerinde **EPPC** üzerinden **Apple Event Manager**'ı remote olarak açığa çıkarır. Palo Alto Unit 42, valid credentials ve enabled bir RAE service'in bir operator'ın remote bir Mac üzerindeki scriptable application'ları yönetmesine olanak tanıması nedeniyle bu özelliği pratik bir **macOS lateral movement** primitive'i olarak yeniden vurguladı.<sup>[[6]](#references)</sup>

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Hedefte zaten admin/root yetkiniz varsa ve bunu etkinleştirmek istiyorsanız:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Başka bir Mac'ten temel bağlantı testi:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Pratikte abuse case yalnızca Finder ile sınırlı değildir. Gerekli Apple events'leri kabul eden herhangi bir **scriptable application**, remote attack surface hâline gelir; bu da RAE'yi internal macOS network'lerinde credential theft sonrasında özellikle ilgi çekici kılar.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Hatalı session rendering, *yanlış* desktop veya window'un iletilmesine ve bunun sonucunda sensitive information leak'ine neden olabilirdi|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Screen sharing access'ine sahip bir user, state-management issue nedeniyle **başka bir user'ın screen'ini** görüntüleyebilir|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* *Screen Sharing*/*Remote Management*'ı kesinlikle gerekli olmadığında disable edin.
* macOS'u tamamen patch'li tutun (Apple genellikle son üç major release için security fix'leri yayınlar).
* Bir **Strong Password** kullanın ve mümkün olduğunda *“VNC viewers may control screen with password”* seçeneğini **disable** olarak enforce edin.
* TCP 5900/3283'ü Internet'e expose etmek yerine service'i bir VPN arkasına koyun.
* `ARDAgent`'ı local subnet ile sınırlamak için bir Application Firewall rule ekleyin:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Apple tarafından tasarlanan bir technology olan Bonjour, **aynı network üzerindeki device'ların birbirleri tarafından sunulan service'leri tespit etmesini** sağlar. Rendezvous, **Zero Configuration** veya Zeroconf olarak da bilinen bu technology, bir device'ın TCP/IP network'e katılmasını, **otomatik olarak bir IP address seçmesini** ve service'lerini diğer network device'larına broadcast etmesini sağlar.

Bonjour tarafından sağlanan Zero Configuration Networking, device'ların şunları yapmasını sağlar:

- **DHCP server olmasa bile otomatik olarak bir IP Address edinme.**
- DNS server gerektirmeden **name-to-address translation** gerçekleştirme.
- Network'te mevcut **service'leri keşfetme**.

Bonjour kullanan device'lar kendilerine **169.254/16 range'inden bir IP address** atar ve network'te bu address'in benzersiz olduğunu doğrular. Mac'ler bu subnet için bir routing table entry tutar; bu entry `netstat -rn | grep 169` ile doğrulanabilir.

DNS için Bonjour, **Multicast DNS (mDNS) protocol**'ünü kullanır. mDNS, **port 5353/UDP** üzerinden çalışır; **standard DNS query'lerini** kullanır ancak bunları **multicast address 224.0.0.251**'e yönlendirir. Bu yaklaşım, network'te dinleyen tüm device'ların query'leri alıp yanıtlayabilmesini ve böylece record'larının güncellenmesini sağlar.

Network'e katıldığında her device kendisi için bir name seçer. Bu name genellikle **.local** ile biter ve hostname'den türetilebilir veya rastgele oluşturulabilir.

Network içindeki service discovery, **DNS Service Discovery (DNS-SD)** ile gerçekleştirilir. DNS SRV record'larının formatından yararlanan DNS-SD, birden fazla service'in listelenmesini sağlamak için **DNS PTR record'larını** kullanır. Belirli bir service'i arayan client, `<Service>.<Domain>` için bir PTR record ister; service birden fazla host tarafından sunuluyorsa karşılığında `<Instance>.<Service>.<Domain>` formatında bir PTR record listesi alır.

`dns-sd` utility'si **network service'lerini keşfetmek ve advertise etmek** için kullanılabilir. Kullanımına ilişkin bazı örnekler:

### SSH Service'lerini arama

Network'teki SSH service'lerini aramak için aşağıdaki command kullanılır:
```bash
dns-sd -B _ssh._tcp
```
Bu komut, \_ssh.\_tcp hizmetleri için browsing işlemini başlatır ve zaman damgası, bayraklar, arayüz, domain, hizmet türü ve örnek adı gibi ayrıntıları görüntüler.

### HTTP Service Advertising

Bir HTTP hizmetini advertise etmek için şunu kullanabilirsiniz:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Bu komut, 80 numaralı portta `/index.html` yoluna sahip "Index" adlı bir HTTP service kaydeder.

Ardından ağdaki HTTP service'lerini aramak için:
```bash
dns-sd -B _http._tcp
```
Bir servis başlatıldığında, varlığını multicast ile duyurarak subnet üzerindeki tüm cihazlara kullanılabilirliğini bildirir. Bu servislerle ilgilenen cihazların istek göndermesine gerek yoktur; yalnızca bu duyuruları dinlemeleri yeterlidir.

Daha kullanıcı dostu bir arayüz için Apple App Store'da bulunan **Discovery - DNS-SD Browser** uygulaması, yerel ağınızda sunulan servisleri görselleştirebilir.

Alternatif olarak, `python-zeroconf` kütüphanesini kullanarak servisleri taramak ve keşfetmek için özel script'ler yazılabilir. [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script'i, `_http._tcp.local.` servisleri için bir servis tarayıcısı oluşturmayı ve eklenen veya kaldırılan servisleri yazdırmayı gösterir:
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
### macOS-specific Bonjour hunting

macOS ağlarında Bonjour, hedefe doğrudan dokunmadan **remote administration surfaces** bulmanın çoğu zaman en kolay yoludur. Apple Remote Desktop, istemcileri Bonjour üzerinden keşfedebilir; dolayısıyla aynı keşif verileri bir saldırgan için de faydalıdır.
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
Daha kapsamlı **mDNS spoofing, impersonation ve cross-subnet discovery** teknikleri için özel sayfaya bakın:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Ağ üzerinden Bonjour Enumeration

* **Nmap NSE** – tek bir host tarafından duyurulan servisleri keşfedin:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script'i bir `_services._dns-sd._udp.local` sorgusu gönderir ve ardından duyurulan her servis türünü enumerate eder.

* **mdns_recon** – unicast sorgularını yanıtlayan *misconfigured* mDNS responder'larını aramak için tüm aralıkları tarayan Python tool'u (subnet/WAN üzerinden erişilebilen cihazları bulmak için kullanışlıdır):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Bu komut, local link dışında Bonjour üzerinden SSH sunan host'ları döndürür.

### Security considerations ve güncel vulnerabilities (2024-2025)

| Yıl | CVE | Severity | Sorun | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* içindeki bir logic error, hazırlanmış bir packet'ın **denial-of-service** tetiklemesine izin verdi|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Eylül 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* içindeki bir correctness issue, **local privilege escalation** için abuse edilebilirdi|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Mayıs 2025) |

**Mitigation guidance**

1. UDP 5353'ü *link-local* scope ile sınırlandırın – wireless controller'larda, router'larda ve host-based firewall'larda engelleyin veya rate-limit uygulayın.
2. Service discovery gerektirmeyen sistemlerde Bonjour'u tamamen disable edin:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Bonjour'un dahili olarak gerekli olduğu ancak network boundary'lerini kesinlikle aşmaması gereken ortamlarda *AirPlay Receiver* profile restriction'larını (MDM) veya bir mDNS proxy kullanın.
4. **System Integrity Protection (SIP)** özelliğini enable edin ve macOS'u güncel tutun – yukarıdaki iki vulnerability hızlıca patched edildi, ancak full protection için SIP'in enable olması gerekiyordu.

### Bonjour'u Disable Etme

Security concerns veya diğer nedenlerle Bonjour'un disable edilmesi gerekiyorsa, aşağıdaki command kullanılarak kapatılabilir:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referanslar

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - macOS'ta Lateral Movement: Benzersiz ve Popüler Teknikler ve Gerçek Dünyadan Örnekler](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - macOS Sonoma 14.7.2 güvenlik içeriği hakkında](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - macOS Tahoe 26.6 güvenlik içeriği hakkında](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - TLS Kimlik Doğrulaması için Secure Remote Password (SRP) Protocol Kullanımı](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
