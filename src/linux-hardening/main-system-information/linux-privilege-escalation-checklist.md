# Linux Yetki Yükseltme Kontrol Listesi

{{#include ../../banners/hacktricks-training.md}}

# Kontrol Listesi - Linux Yetki Yükseltme



### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **İşletim sistemi bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) değerini kontrol edin; **yazılabilir klasör** var mı?
- [ ] [**Ortam değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol edin; hassas bir bilgi var mı?
- [ ] **Script kullanarak** [**kernel exploitlerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) arayın (DirtyCow?)
- [ ] Kernel PoC çalıştırmadan önce yalnızca `uname -r` çıktısını değil, **gerçek ön koşulları** da doğrulayın: mimari, gerekli `CONFIG_*` seçenekleri/modülleri, namespace oluşturma ve etkin azaltımlar. Örneğin, `unshare -Urn true` ile user/network namespace kullanılabilirliğini test edin; modern netfilter exploitleri `CONFIG_USER_NS`, ayrıcalıksız user namespace'ler ve `CONFIG_NF_TABLES` gerektirebilir.<sup>[[3]](#references)</sup>
- [ ] [**sudo sürümünün** savunmasız olup olmadığını](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **kontrol edin**
- [ ] [**Dmesg** imza doğrulaması başarısız oldu mu?](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**Kernel modülü ve modül yükleme yanlış yapılandırmalarını**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) inceleyin: `insmod`, `modinfo`, `lsmod`, `dmesg`, imza zorunluluğu ve `modules_disabled`.
- [ ] Yardımcı program yolu değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path kötüye kullanım yollarını**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol edin.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata'sı dahil, [**yazılabilir /lib/modules yollarını**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol edin.
- [ ] Daha fazla sistem enum'u ([tarih, sistem istatistikleri, CPU bilgisi, yazıcılar](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla savunmayı sıralayın](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Sürücüler](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Bağlı** sürücüleri listeleyin
- [ ] **Bağlı olmayan sürücü var mı?**
- [ ] **fstab içinde kimlik bilgileri var mı?**

### [**Yüklü Yazılımlar**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Yararlı yazılımların** yüklü olup olmadığını [**kontrol edin**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Savunmasız yazılımların** yüklü olup olmadığını [**kontrol edin**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Debian/Ubuntu'da **needrestart interpreter scanning** özelliğinin yüklü/etkin olup olmadığını kontrol edin: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Savunmasız sürümlerde, APT veya `unattended-upgrades` needrestart'i root olarak çalıştırdığında saldırgan denetimindeki `PYTHONPATH`/`RUBYLIB` değerlerinin yeniden kullanılması, `/proc/<pid>/exe` için yarış durumu oluşturulması veya saldırgan denetimindeki Perl yollarının taranması ayrıcalık sınırının aşılmasına neden oluyordu.<sup>[[4]](#references)</sup>

### [İşlemler](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **Bilinmeyen bir yazılım** çalışıyor mu?
- [ ] Herhangi bir yazılım **olması gerekenden daha fazla ayrıcalıkla** mı çalışıyor?
- [ ] **Çalışan işlemlerin exploitlerini** arayın (özellikle çalışan sürüm için).
- [ ] Çalışan bir işlemin **binary dosyasını değiştirebilir** misiniz?
- [ ] **İşlemleri izleyin** ve ilginç bir işlem sık sık çalışıyor mu kontrol edin.
- [ ] Parolaların kaydedilmiş olabileceği ilginç **işlem belleğini** **okuyabilir** misiniz?

### [Zamanlanmış/Cron işleri?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Bazı cron işleri [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)değerini değiştiriyor ve bu dizine **yazabiliyor** musunuz?
- [ ] Bir cron işinde [**joker karakter** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] **Değiştirilebilir bir script** [**çalıştırılıyor** mu](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) veya **değiştirilebilir bir klasörde** mi?
- [ ] Bir **scriptin** [**çok sık**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) (her 1, 2 veya 5 dakikada bir) **çalıştırılabileceğini** ya da çalıştırıldığını tespit ettiniz mi?

### [Servisler](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **Yazılabilir bir .service** dosyası var mı?
- [ ] Bir **servis** tarafından çalıştırılan **yazılabilir bir binary** var mı?
- [ ] Bir root unit tarafından belirtilen yazılabilir **yardımcı program, yapılandırma veya ortam dosyası** var mı (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Birleştirilmiş unit'i `systemctl cat <unit>` ile inceleyin ve [service/socket dosyalarının kötüye kullanımını](../interesting-files-permissions/write-to-root.md) gözden geçirin.
- [ ] İsteğe bağlı, ayrıcalıklı bir iş akışı daha düşük ayrıcalıklı ve yazılabilir bir dizinin altındaki yardımcı programı çalıştırıyor mu? Hem yardımcı programı hem de üst dizinini [kullanıcı tarafından değiştirilebilir yolların root tarafından çalıştırılması](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries) açısından kontrol edin; kısa süreli yardımcı programlar yalnızca iş akışı çalışırken görünebilir.
- [ ] **systemd PATH içinde yazılabilir bir klasör** var mı?
- [ ] `ExecStart`/`User` değerlerini geçersiz kılabilen, `/etc/systemd/system/<unit>.d/*.conf` altında **yazılabilir bir systemd unit drop-in** var mı?<sup>[[2]](#references)</sup>

### [Zamanlayıcılar](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **Yazılabilir bir timer** var mı?

### [Socket'ler](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **Yazılabilir bir .socket** dosyası var mı?
- [ ] Herhangi bir **socket ile iletişim kurabilir** misiniz?
- [ ] İlginç bilgiler içeren **HTTP socket'leri** var mı?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` veya bir kubelet endpoint'i gibi bir [**container-runtime veya node-agent API'sine**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) erişebilir misiniz? Alışılmış CLI aracı olmasa bile ham HTTP/gRPC API'sini test edin.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir** misiniz?

### [Ağ](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu anlamak için ağı sıralayın
- [ ] Makine içinde shell aldıktan sonra daha önce erişemediğiniz **açık portlar** var mı?
- [ ] `tcpdump` kullanarak **trafiği sniff edebilir** misiniz?

### [Kullanıcılar](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel kullanıcı/grup **sıralaması**
- [ ] **Çok büyük bir UID** değeriniz var mı? **Makine** **savunmasız** mı?
- [ ] Üyesi olduğunuz bir [**grup sayesinde ayrıcalıklarınızı yükseltebilir**](../user-information/interesting-groups-linux-pe/index.html) misiniz?
- [ ] **Pano** verileri?
- [ ] Parola politikası?
- [ ] Daha önce keşfettiğiniz **bilinen her parolayı** mümkün olan **her kullanıcıyla** giriş yapmak için **kullanmayı** deneyin. Parola olmadan da giriş yapmayı deneyin.

### [Yazılabilir PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH içindeki bir klasör üzerinde yazma ayrıcalığınız** varsa ayrıcalıklarınızı yükseltebilirsiniz

### [SUDO ve SUID komutları](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir komut çalıştırabilir** misiniz? Root olarak bir şeyi OKUMAK, YAZMAK veya ÇALIŞTIRMAK için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` çıktısı `sudoedit` kullanımına izin veriyorsa, savunmasız sürümlerde (`sudo -V` < 1.9.12p2) `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argüman enjeksiyonunu** (CVE-2023-22809) kontrol edin. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] **Exploit edilebilir bir SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** komutları **yol ile** sınırlandırılmış mı? Kısıtlamaları **aşabilir** misiniz](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Yolu belirtilmemiş Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Yolu belirtilmiş SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Aşın
- [ ] [**LD_PRELOAD açığı**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasördeki SUID binary'de [**.so kütüphanesi eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir kütüphane yolu**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**Kullanılabilir SUDO token'ları**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) var mı? [**Bir SUDO token'ı oluşturabilir**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) misiniz?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) misiniz?
- [ ] [**/etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) dizinini **değiştirebilir** misiniz?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) komutu

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary'de **beklenmeyen bir capability** var mı?

### [ACL'ler](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada **beklenmeyen bir ACL** var mı?

### [Açık shell oturumları](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Öngörülebilir OpenSSL PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**İlginç SSH yapılandırma değerleri**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [İlginç Dosyalar](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile dosyaları** - Hassas verileri okuyabilir misiniz? Yetki yükseltmek için dosyaya yazabilir misiniz?
- [ ] **passwd/shadow dosyaları** - Hassas verileri okuyabilir misiniz? Yetki yükseltmek için dosyaya yazabilir misiniz?
- [ ] Hassas veriler için **genellikle ilginç olan klasörleri kontrol edin**
- [ ] **Tuhaf konumlardaki/sahipli dosyalar**; erişebileceğiniz veya değiştirebileceğiniz çalıştırılabilir dosyalar olabilir
- [ ] Son dakikalarda **değiştirilmiş**
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki script/binary dosyaları**
- [ ] **Web dosyaları** (parolalar?)
- [ ] **Yedekler**?
- [ ] **Parola içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Keyfi komutlar çalıştırmak için **Python kütüphanesini değiştirebilir** misiniz?
- [ ] **Log dosyalarını değiştirebilir** misiniz? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** dizinini **değiştirebilir** misiniz? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) misiniz?

### [**Diğer yöntemler**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Ayrıcalık yükseltmek için NFS'yi kötüye kullanabilir**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) misiniz?
- [ ] [**Kısıtlayıcı bir shell'den kaçmanız**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) gerekiyor mu?



## References

- [1] [Sudo duyurusu: sudoedit ile rastgele dosya düzenleme](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux belgeleri: systemd drop-in yapılandırması](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit gereksinimleri ve araştırması](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Güvenlik Duyurusu: needrestart'te LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
