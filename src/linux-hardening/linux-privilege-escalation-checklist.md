# Kontrol Listesi - Linux Yetki Yükseltme

{{#include ../banners/hacktricks-training.md}}

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgisi](privilege-escalation/#system-information)

- [ ] **OS bilgilerini** al
- [ ] [**PATH**](privilege-escalation/#path)'i kontrol et, herhangi bir **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](privilege-escalation/#env-info) kontrol et, herhangi bir hassas detay var mı?
- [ ] [**kernel exploit'lerini**](privilege-escalation/#kernel-exploits) **script kullanarak** ara (DirtyCow?)
- [ ] [**sudo versiyonunun**](privilege-escalation/#sudo-version) **güvenli olup olmadığını** kontrol et
- [ ] [**Dmesg** imza doğrulaması başarısız](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Daha fazla sistem enum ([tarih, sistem istatistikleri, cpu bilgisi, yazıcılar](privilege-escalation/#more-system-enumeration))
- [ ] [Daha fazla savunmayı enumle](privilege-escalation/#enumerate-possible-defenses)

### [Sürücüler](privilege-escalation/#drives)

- [ ] **Bağlı** sürücüleri listele
- [ ] **Herhangi bir bağlı olmayan sürücü var mı?**
- [ ] **fstab'da herhangi bir kimlik bilgisi var mı?**

### [**Yüklenmiş Yazılımlar**](privilege-escalation/#installed-software)

- [ ] **Yüklenmiş** [**yararlı yazılımlar**](privilege-escalation/#useful-software) için kontrol et
- [ ] **Yüklenmiş** [**güvenlik açığı olan yazılımlar**](privilege-escalation/#vulnerable-software-installed) için kontrol et

### [Süreçler](privilege-escalation/#processes)

- [ ] Herhangi bir **bilinmeyen yazılım çalışıyor mu**?
- [ ] Herhangi bir yazılım **olması gerektiğinden daha fazla yetkiyle** mi çalışıyor?
- [ ] **Çalışan süreçlerin exploit'lerini** ara (özellikle çalışan versiyonu).
- [ ] Herhangi bir çalışan sürecin **ikili dosyasını** **değiştirebilir misin**?
- [ ] **Süreçleri izle** ve ilginç bir sürecin sıkça çalışıp çalışmadığını kontrol et.
- [ ] Bazı ilginç **süreç belleğini** (şifrelerin kaydedilebileceği yer) **okuyabilir misin**?

### [Planlı/Cron görevleri?](privilege-escalation/#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/#cron-path) bazı cron tarafından **değiştiriliyor mu** ve sen **yazabilir misin**?
- [ ] Bir cron görevinde herhangi bir [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) var mı?
- [ ] **Değiştirilebilir bir script** ([**cron script'inin üzerine yazma ve symlink**](privilege-escalation/#cron-script-overwriting-and-symlink)) **çalıştırılıyor mu** veya **değiştirilebilir klasör** içinde mi?
- [ ] Bazı **script'lerin** [**çok sık**](privilege-escalation/#frequent-cron-jobs) **çalıştırıldığını** tespit ettin mi? (her 1, 2 veya 5 dakikada bir)

### [Hizmetler](privilege-escalation/#services)

- [ ] Herhangi bir **yazılabilir .service** dosyası var mı?
- [ ] Herhangi bir **hizmet tarafından yürütülen yazılabilir ikili** var mı?
- [ ] **systemd PATH** içinde herhangi bir **yazılabilir klasör** var mı?

### [Zamanlayıcılar](privilege-escalation/#timers)

- [ ] Herhangi bir **yazılabilir zamanlayıcı** var mı?

### [Socket'ler](privilege-escalation/#sockets)

- [ ] Herhangi bir **yazılabilir .socket** dosyası var mı?
- [ ] Herhangi bir socket ile **iletişim kurabilir misin**?
- [ ] **İlginç bilgiler içeren HTTP socket'leri** var mı?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misin**?

### [Ağ](privilege-escalation/#network)

- [ ] Nerede olduğunu bilmek için ağı enumle
- [ ] **Makine içinde bir shell alana kadar erişemediğin açık portlar var mı?**
- [ ] `tcpdump` kullanarak **trafik dinleyebilir misin**?

### [Kullanıcılar](privilege-escalation/#users)

- [ ] Genel kullanıcılar/gruplar **enumlemesi**
- [ ] **Çok büyük bir UID**'ye sahip misin? **Makine** **güvenlik açığı** taşıyor mu?
- [ ] **Ait olduğun bir grup sayesinde** [**yetki yükseltebilir misin**](privilege-escalation/interesting-groups-linux-pe/)?
- [ ] **Pano** verileri?
- [ ] Şifre Politikası?
- [ ] Daha önce keşfettiğin her **bilinen şifreyi** kullanarak **her bir** olası **kullanıcıyla** giriş yapmayı dene. Şifre olmadan da giriş yapmayı dene.

### [Yazılabilir PATH](privilege-escalation/#writable-path-abuses)

- [ ] Eğer **PATH'teki bir klasörde yazma yetkin varsa** yetki yükseltebilirsin

### [SUDO ve SUID komutları](privilege-escalation/#sudo-and-suid)

- [ ] **Herhangi bir komutu sudo ile çalıştırabilir misin**? Root olarak herhangi bir şeyi OKUMAK, YAZMAK veya ÇALIŞTIRMAK için kullanabilir misin? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Herhangi bir **istismar edilebilir SUID ikilisi** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** komutları **path** ile **sınırlı mı**? kısıtlamaları **aşabilir misin**](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Path belirtilmeden Sudo/SUID ikilisi**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**Path belirten SUID ikilisi**](privilege-escalation/#suid-binary-with-command-path)? Aşma
- [ ] [**LD_PRELOAD açığı**](privilege-escalation/#ld_preload)
- [ ] Yazılabilir bir klasörden gelen [**SUID ikilisinde .so kütüphanesi eksikliği**](privilege-escalation/#suid-binary-so-injection)?
- [ ] [**SUDO token'leri mevcut**](privilege-escalation/#reusing-sudo-tokens)? [**Bir SUDO token'i oluşturabilir misin**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misin**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/**'yi değiştirebilir misin](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) komutu

### [Yetenekler](privilege-escalation/#capabilities)

- [ ] Herhangi bir ikilinin herhangi bir **beklenmedik yeteneği** var mı?

### [ACL'ler](privilege-escalation/#acls)

- [ ] Herhangi bir dosyanın herhangi bir **beklenmedik ACL'si** var mı?

### [Açık Shell oturumları](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Tahmin Edilebilir PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH İlginç yapılandırma değerleri**](privilege-escalation/#ssh-interesting-configuration-values)

### [İlginç Dosyalar](privilege-escalation/#interesting-files)

- [ ] **Profil dosyaları** - Hassas verileri oku? Privesc için yaz?
- [ ] **passwd/shadow dosyaları** - Hassas verileri oku? Privesc için yaz?
- [ ] Hassas veriler için **yaygın ilginç klasörleri** kontrol et
- [ ] **Garip Konum/Sahip dosyalar,** erişimin olabileceği veya yürütülebilir dosyaları değiştirebileceğin dosyalar
- [ ] **Son dakikalarda** **değiştirilen**
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH'teki Script/İkili dosyalar**
- [ ] **Web dosyaları** (şifreler?)
- [ ] **Yedekler**?
- [ ] **Şifreleri içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullan
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](privilege-escalation/#writable-files)

- [ ] **Rasgele komutlar çalıştırmak için python kütüphanesini** değiştirebilir misin?
- [ ] **Log dosyalarını değiştirebilir misin**? **Logtotten** açığı
- [ ] **/etc/sysconfig/network-scripts/**'i değiştirebilir misin? Centos/Redhat açığı
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misin**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Diğer numaralar**](privilege-escalation/#other-tricks)

- [ ] [**NFS'i kullanarak yetki yükseltebilir misin**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] [**Kısıtlayıcı bir shell'den kaçmak**](privilege-escalation/#escaping-from-restricted-shells) için bir ihtiyacın var mı?

{{#include ../banners/hacktricks-training.md}}
