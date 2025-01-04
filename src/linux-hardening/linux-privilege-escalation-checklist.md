# Kontrol Listesi - Linux Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgisi](privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** al
- [ ] [**PATH**](privilege-escalation/index.html#path) kontrol et, herhangi bir **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](privilege-escalation/index.html#env-info) kontrol et, herhangi bir hassas detay var mı?
- [ ] [**kernel exploit'lerini**](privilege-escalation/index.html#kernel-exploits) **script kullanarak** ara (DirtyCow?)
- [ ] [**sudo versiyonunun**](privilege-escalation/index.html#sudo-version) **güvenli olup olmadığını** kontrol et
- [ ] [**Dmesg** imza doğrulaması başarısız](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Daha fazla sistem enum ([tarih, sistem istatistikleri, cpu bilgisi, yazıcılar](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla savunmayı enumle](privilege-escalation/index.html#enumerate-possible-defenses)

### [Sürücüler](privilege-escalation/index.html#drives)

- [ ] **Bağlı** sürücüleri listele
- [ ] **Herhangi bir bağlı olmayan sürücü var mı?**
- [ ] **fstab'da herhangi bir kimlik bilgisi var mı?**

### [**Yüklenmiş Yazılımlar**](privilege-escalation/index.html#installed-software)

- [ ] **Yüklenmiş** [**yararlı yazılımları**](privilege-escalation/index.html#useful-software) kontrol et
- [ ] **Yüklenmiş** [**güvenlik açığı olan yazılımları**](privilege-escalation/index.html#vulnerable-software-installed) kontrol et

### [Süreçler](privilege-escalation/index.html#processes)

- [ ] Herhangi bir **bilinmeyen yazılım çalışıyor mu**?
- [ ] Herhangi bir yazılım **gerektiğinden daha fazla yetkiyle** mi çalışıyor?
- [ ] **Çalışan süreçlerin exploit'lerini** ara (özellikle çalışan versiyonu).
- [ ] Herhangi bir çalışan sürecin **ikili dosyasını** **değiştirebilir misin**?
- [ ] **Süreçleri izle** ve ilginç bir sürecin sıkça çalışıp çalışmadığını kontrol et.
- [ ] Bazı ilginç **süreç belleğini** (şifrelerin kaydedilebileceği yer) **okuyabilir misin**?

### [Planlı/Cron görevleri?](privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/index.html#cron-path) bazı cron tarafından **değiştiriliyor mu** ve sen **yazabilir misin**?
- [ ] Bir cron görevinde herhangi bir [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) var mı?
- [ ] **Çalıştırılan** veya **değiştirilebilir klasörde** bulunan bazı [**değiştirilebilir scriptler**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) var mı?
- [ ] Bazı **scriptlerin** [**çok sık**](privilege-escalation/index.html#frequent-cron-jobs) [**çalıştırıldığını**](privilege-escalation/index.html#frequent-cron-jobs) tespit ettin mi? (her 1, 2 veya 5 dakikada bir)

### [Hizmetler](privilege-escalation/index.html#services)

- [ ] Herhangi bir **yazılabilir .service** dosyası var mı?
- [ ] Herhangi bir **hizmet tarafından yürütülen yazılabilir ikili** var mı?
- [ ] **systemd PATH** içinde herhangi bir **yazılabilir klasör** var mı?

### [Zamanlayıcılar](privilege-escalation/index.html#timers)

- [ ] Herhangi bir **yazılabilir zamanlayıcı** var mı?

### [Socket'ler](privilege-escalation/index.html#sockets)

- [ ] Herhangi bir **yazılabilir .socket** dosyası var mı?
- [ ] Herhangi bir socket ile **iletişim kurabilir misin**?
- [ ] **İlginç bilgiler içeren HTTP socket'leri** var mı?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misin**?

### [Ağ](privilege-escalation/index.html#network)

- [ ] Nerede olduğunu bilmek için ağı enumle
- [ ] **Makine içinde bir shell alana kadar erişemediğin açık portlar var mı?**
- [ ] `tcpdump` kullanarak **trafik dinleyebilir misin**?

### [Kullanıcılar](privilege-escalation/index.html#users)

- [ ] Genel kullanıcılar/gruplar **enumlemesi**
- [ ] **Çok büyük bir UID**'ye sahip misin? **Makine** **güvenli mi**?
- [ ] **Ait olduğun bir grup sayesinde yetki yükseltebilir misin**? [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/)
- [ ] **Pano** verileri?
- [ ] Şifre Politikası?
- [ ] Daha önce keşfettiğin her **bilinen şifreyi** kullanarak **her bir kullanıcıyla** giriş yapmayı dene. Şifre olmadan da giriş yapmayı dene.

### [Yazılabilir PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Eğer **PATH içindeki bir klasörde yazma yetkin varsa** yetki yükseltebilirsin

### [SUDO ve SUID komutları](privilege-escalation/index.html#sudo-and-suid)

- [ ] **Herhangi bir komutu sudo ile çalıştırabilir misin**? Root olarak herhangi bir şeyi OKUMAK, YAZMAK veya ÇALIŞTIRMAK için kullanabilir misin? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Herhangi bir **istismar edilebilir SUID ikilisi** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** komutları **path** ile **sınırlı mı**? kısıtlamaları **bypass** edebilir misin](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Path belirtilmeden Sudo/SUID ikilisi**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Komut yolu belirten SUID ikilisi**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD açığı**](privilege-escalation/index.html#ld_preload)
- [ ] Yazılabilir bir klasörden [**SUID ikilisinde .so kütüphanesinin eksikliği**](privilege-escalation/index.html#suid-binary-so-injection)?
- [ ] [**SUDO token'leri mevcut**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Bir SUDO token'i oluşturabilir misin**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misin**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/**'yi değiştirebilir misin](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) komutu

### [Yetenekler](privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir ikilinin herhangi bir **beklenmedik yeteneği** var mı?

### [ACL'ler](privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyanın herhangi bir **beklenmedik ACL'si** var mı?

### [Açık Shell oturumları](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH İlginç yapılandırma değerleri**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [İlginç Dosyalar](privilege-escalation/index.html#interesting-files)

- [ ] **Profil dosyaları** - Hassas verileri oku? Privesc için yaz?
- [ ] **passwd/shadow dosyaları** - Hassas verileri oku? Privesc için yaz?
- [ ] Hassas veriler için **yaygın ilginç klasörleri** kontrol et
- [ ] **Garip Konum/Sahip dosyalar,** erişimin olabileceği veya yürütülebilir dosyaları değiştirebileceğin dosyalar
- [ ] Son dakikalarda **değiştirilen**
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki Script/İkili dosyalar**
- [ ] **Web dosyaları** (şifreler?)
- [ ] **Yedekler**?
- [ ] **Şifreleri içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullan
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](privilege-escalation/index.html#writable-files)

- [ ] **Rasgele komutlar çalıştırmak için python kütüphanesini** değiştirebilir misin?
- [ ] **Log dosyalarını değiştirebilir misin**? **Logtotten** açığı
- [ ] **/etc/sysconfig/network-scripts/**'i değiştirebilir misin? Centos/Redhat açığı
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misin**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Diğer numaralar**](privilege-escalation/index.html#other-tricks)

- [ ] [**NFS'i yetki yükseltmek için kötüye kullanabilir misin**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**kısıtlayıcı bir shell'den kaçmak için**](privilege-escalation/index.html#escaping-from-restricted-shells) ihtiyacın var mı?

{{#include ../banners/hacktricks-training.md}}
