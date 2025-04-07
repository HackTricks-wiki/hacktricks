# Mythic

## Mythic Nedir?

Mythic, red teaming için tasarlanmış açık kaynaklı, modüler bir komut ve kontrol (C2) çerçevesidir. Güvenlik profesyonellerinin Windows, Linux ve macOS dahil olmak üzere farklı işletim sistemlerinde çeşitli ajanları (payloads) yönetmesine ve dağıtmasına olanak tanır. Mythic, ajanları yönetmek, komutları yürütmek ve sonuçları toplamak için kullanıcı dostu bir web arayüzü sağlar, bu da onu kontrollü bir ortamda gerçek dünya saldırılarını simüle etmek için güçlü bir araç haline getirir.

### Kurulum

Mythic'i kurmak için resmi **[Mythic repo](https://github.com/its-a-feature/Mythic)** üzerindeki talimatları izleyin.

### Ajanlar

Mythic, **ele geçirilmiş sistemlerde görevleri yerine getiren payloads** olan birden fazla ajanı destekler. Her ajan, belirli ihtiyaçlara göre özelleştirilebilir ve farklı işletim sistemlerinde çalışabilir.

Varsayılan olarak Mythic'te herhangi bir ajan yüklü değildir. Ancak, [**https://github.com/MythicAgents**](https://github.com/MythicAgents) adresinde bazı açık kaynak ajanlar sunmaktadır.

O repo'dan bir ajan yüklemek için sadece şunu çalıştırmanız yeterlidir:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Yeni ajanlar, Mythic zaten çalışıyorsa bile önceki komutla eklenebilir.

### C2 Profilleri

Mythic'teki C2 profilleri, **ajanların Mythic sunucusuyla nasıl iletişim kurduğunu** tanımlar. İletişim protokolünü, şifreleme yöntemlerini ve diğer ayarları belirtir. C2 profillerini Mythic web arayüzü aracılığıyla oluşturabilir ve yönetebilirsiniz.

Varsayılan olarak, Mythic hiçbir profil ile kurulmuştur, ancak bazı profilleri repodan [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) indirmeniz mümkündür:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo, SpecterOps eğitim tekliflerinde kullanılmak üzere tasarlanmış, 4.0 .NET Framework kullanarak C# ile yazılmış bir Windows ajanıdır.

Bunu şu şekilde kurun:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Bu ajan, bazı ek özelliklerle birlikte Cobalt Strike'ın Beacon'una çok benzeyen birçok komuta sahiptir. Bunlar arasında şunlar desteklenmektedir:

### Yaygın eylemler

- `cat`: Bir dosyanın içeriğini yazdır
- `cd`: Geçerli çalışma dizinini değiştir
- `cp`: Bir dosyayı bir yerden başka bir yere kopyala
- `ls`: Geçerli dizindeki veya belirtilen yoldaki dosyaları ve dizinleri listele
- `pwd`: Geçerli çalışma dizinini yazdır
- `ps`: Hedef sistemdeki çalışan süreçleri listele (ek bilgi ile)
- `download`: Hedef sistemden yerel makineye bir dosya indir
- `upload`: Yerel makineden hedef sisteme bir dosya yükle
- `reg_query`: Hedef sistemdeki kayıt defteri anahtarlarını ve değerlerini sorgula
- `reg_write_value`: Belirtilen kayıt defteri anahtarına yeni bir değer yaz
- `sleep`: Ajanın uyku aralığını değiştir, bu da Mythic sunucusuyla ne sıklıkla kontrol yapacağını belirler
- Ve daha fazlası, mevcut komutların tam listesini görmek için `help` kullanın.

### Yetki yükseltme

- `getprivs`: Geçerli iş parçacığı belirtecinde mümkün olan en fazla yetkiyi etkinleştir
- `getsystem`: Winlogon'a bir tanıtıcı aç ve belirteci kopyala, böylece yetkileri SYSTEM seviyesine yükselt
- `make_token`: Yeni bir oturum aç ve bunu ajana uygula, başka bir kullanıcıyı taklit etmeye olanak tanır
- `steal_token`: Başka bir süreçten birincil belirteci çal, böylece ajan o sürecin kullanıcısını taklit edebilir
- `pth`: Pass-the-Hash saldırısı, ajanın NTLM hash'ini kullanarak bir kullanıcı olarak kimlik doğrulamasına olanak tanır, düz metin parolasına ihtiyaç duymadan
- `mimikatz`: Kimlik bilgilerini, hash'leri ve diğer hassas bilgileri bellekten veya SAM veritabanından çıkarmak için Mimikatz komutlarını çalıştır
- `rev2self`: Ajanın belirtecini birincil belirtecine geri döndür, böylece yetkileri orijinal seviyeye düşür
- `ppid`: Post-exploitation işleri için yeni bir ana süreç kimliği belirterek ana süreci değiştir, iş yürütme bağlamı üzerinde daha iyi kontrol sağlar
- `printspoofer`: Yazıcı spooler güvenlik önlemlerini aşmak için PrintSpoofer komutlarını çalıştır, böylece yetki yükseltme veya kod yürütme sağlar
- `dcsync`: Bir kullanıcının Kerberos anahtarlarını yerel makineye senkronize et, çevrimdışı parola kırma veya daha fazla saldırı için olanak tanır
- `ticket_cache_add`: Mevcut oturum açma oturumuna veya belirtilen birine bir Kerberos bileti ekle, böylece bilet yeniden kullanımı veya taklitine olanak tanır

### Süreç yürütme

- `assembly_inject`: Uzak bir sürece .NET assembly yükleyici enjekte etmeye olanak tanır
- `execute_assembly`: Ajanın bağlamında bir .NET assembly çalıştırır
- `execute_coff`: Bellekte bir COFF dosyasını çalıştırır, derlenmiş kodun bellekte yürütülmesine olanak tanır
- `execute_pe`: Yönetilmeyen bir yürütülebilir dosyayı (PE) çalıştırır
- `inline_assembly`: Ajanın ana sürecini etkilemeden geçici kod yürütülmesine olanak tanıyan bir .NET assembly'yi geçici bir AppDomain'de çalıştırır
- `run`: Hedef sistemde bir ikili dosyayı çalıştırır, yürütülebilir dosyayı bulmak için sistemin PATH'ini kullanır
- `shinject`: Uzak bir sürece shellcode enjekte eder, böylece rastgele kodun bellekte yürütülmesine olanak tanır
- `inject`: Ajan shellcode'unu uzak bir sürece enjekte eder, böylece ajanın kodunun bellekte yürütülmesine olanak tanır
- `spawn`: Belirtilen yürütülebilir dosyada yeni bir ajan oturumu başlatır, böylece yeni bir süreçte shellcode'un yürütülmesine olanak tanır
- `spawnto_x64` ve `spawnto_x86`: Post-exploitation işlerinde kullanılan varsayılan ikili dosyayı, çok gürültülü olan `rundll32.exe` parametreleri olmadan kullanmak yerine belirtilen bir yola değiştirir.

### Mithic Forge

Bu, hedef sistemde yürütülebilecek önceden derlenmiş yükler ve araçlar deposu olan Mythic Forge'dan **COFF/BOF** dosyalarını yüklemeye olanak tanır. Yüklenebilecek tüm komutlarla, bunları mevcut ajan sürecinde BOF olarak yürütmek mümkün olacaktır (genellikle daha gizli).

Yüklemeye başlamak için:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Sonra, `forge_collections` kullanarak Mythic Forge'dan bir COFF/BOF modülünü gösterin, böylece bunları seçip ajan belleğine yükleyebilirsiniz. Varsayılan olarak, Apollo'da aşağıdaki 2 koleksiyon eklenmiştir:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Bir modül yüklendikten sonra, `forge_bof_sa-whoami` veya `forge_bof_sa-netuser` gibi başka bir komut olarak listede görünecektir.

### Powershell & scripting execution

- `powershell_import`: Yeni bir PowerShell betiğini (.ps1) ajan önbelleğine ithal eder ve daha sonra çalıştırmak için hazırlar.
- `powershell`: Ajan bağlamında bir PowerShell komutunu çalıştırır, gelişmiş betik yazma ve otomasyon sağlar.
- `powerpick`: Bir PowerShell yükleyici derlemesini fedakâr bir süreçte enjekte eder ve bir PowerShell komutunu çalıştırır (powershell kaydı olmadan).
- `psinject`: Belirtilen bir süreçte PowerShell'i çalıştırır, başka bir süreç bağlamında betiklerin hedefli olarak çalıştırılmasına olanak tanır.
- `shell`: Ajan bağlamında bir shell komutunu çalıştırır, cmd.exe'de bir komut çalıştırmaya benzer.

### Lateral Movement

- `jump_psexec`: PsExec tekniğini kullanarak Apollo ajan yürütülebilir dosyasını (apollo.exe) kopyalayarak yeni bir ana bilgisayara yan hareket eder ve çalıştırır.
- `jump_wmi`: WMI tekniğini kullanarak Apollo ajan yürütülebilir dosyasını (apollo.exe) kopyalayarak yeni bir ana bilgisayara yan hareket eder ve çalıştırır.
- `wmiexecute`: WMI kullanarak yerel veya belirtilen uzak sistemde bir komut çalıştırır, taklit için isteğe bağlı kimlik bilgileri ile.
- `net_dclist`: Belirtilen alan için etki alanı denetleyicilerinin bir listesini alır, yan hareket için potansiyel hedefleri belirlemek için yararlıdır.
- `net_localgroup`: Belirtilen bilgisayardaki yerel grupları listeler, bilgisayar belirtilmezse varsayılan olarak localhost'a döner.
- `net_localgroup_member`: Yerel veya uzak bilgisayardaki belirtilen bir grup için yerel grup üyeliğini alır, belirli gruplardaki kullanıcıların sayımına olanak tanır.
- `net_shares`: Belirtilen bilgisayardaki uzak payları ve erişilebilirliklerini listeler, yan hareket için potansiyel hedefleri belirlemek için yararlıdır.
- `socks`: Hedef ağda SOCKS 5 uyumlu bir proxy'yi etkinleştirir, böylece trafiği ele geçirilmiş ana bilgisayar üzerinden tünelleme sağlar. proxychains gibi araçlarla uyumludur.
- `rpfwd`: Hedef ana bilgisayarda belirtilen bir portta dinlemeye başlar ve trafiği Mythic üzerinden uzak bir IP ve porta yönlendirir, böylece hedef ağdaki hizmetlere uzaktan erişim sağlar.
- `listpipes`: Yerel sistemdeki tüm adlandırılmış boruları listeler, bu da IPC mekanizmalarıyla etkileşim yoluyla yan hareket veya ayrıcalık yükseltme için yararlı olabilir.

### Miscellaneous Commands
- `help`: Belirli komutlar hakkında ayrıntılı bilgi veya ajandaki tüm mevcut komutlar hakkında genel bilgi görüntüler.
- `clear`: Görevleri 'temizlendi' olarak işaretler, böylece ajanlar tarafından alınamazlar. Tüm görevleri temizlemek için `all` belirtebilir veya belirli bir görevi temizlemek için `task Num` belirtebilirsiniz.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon, **Linux ve macOS** yürütülebilir dosyalarına derlenen bir Golang ajanıdır.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
### Yaygın eylemler

- `cat`: Bir dosyanın içeriğini yazdır
- `cd`: Geçerli çalışma dizinini değiştir
- `chmod`: Bir dosyanın izinlerini değiştir
- `config`: Mevcut yapılandırmayı ve ana bilgisayar bilgilerini görüntüle
- `cp`: Bir dosyayı bir yerden başka bir yere kopyala
- `curl`: İsteğe bağlı başlıklar ve yöntem ile tek bir web isteği gerçekleştir
- `upload`: Hedefe bir dosya yükle
- `download`: Hedef sistemden yerel makineye bir dosya indir
- Ve daha fazlası

### Hassas Bilgileri Ara

- `triagedirectory`: Bir ana bilgisayardaki bir dizin içinde ilginç dosyaları, hassas dosyalar veya kimlik bilgileri gibi bul.
- `getenv`: Tüm mevcut ortam değişkenlerini al.

### Yanal Hareket Et

- `ssh`: Belirlenen kimlik bilgilerini kullanarak ana bilgisayara SSH ile bağlan ve ssh başlatmadan bir PTY aç.
- `sshauth`: Belirtilen ana bilgisayara(lar)a belirlenen kimlik bilgilerini kullanarak SSH ile bağlan. Ayrıca, bu komutu uzak ana bilgisayarlarda belirli bir komutu çalıştırmak için veya dosyaları SCP ile kullanmak için de kullanabilirsiniz.
- `link_tcp`: TCP üzerinden başka bir ajana bağlan, ajanslar arasında doğrudan iletişime izin verir.
- `link_webshell`: Webshell P2P profili kullanarak bir ajana bağlan, ajanın web arayüzüne uzaktan erişim sağlar.
- `rpfwd`: Hedef ağdaki hizmetlere uzaktan erişim sağlamak için Ters Port İleri Sarma'yı başlat veya durdur.
- `socks`: Hedef ağda bir SOCKS5 proxy başlat veya durdur, ele geçirilmiş ana bilgisayar üzerinden trafiği tünelleme imkanı sağlar. proxychains gibi araçlarla uyumludur.
- `portscan`: Açık portlar için ana bilgisayar(lar)ı tarar, yanal hareket veya daha fazla saldırı için potansiyel hedefleri belirlemek için yararlıdır.

### Süreç yürütme

- `shell`: /bin/sh üzerinden tek bir shell komutunu çalıştır, hedef sistemde komutların doğrudan yürütülmesine izin verir.
- `run`: Diskten argümanlarla bir komut çalıştır, hedef sistemde ikili dosyaların veya betiklerin yürütülmesine izin verir.
- `pty`: Hedef sistemde shell ile doğrudan etkileşim sağlamak için etkileşimli bir PTY aç.
