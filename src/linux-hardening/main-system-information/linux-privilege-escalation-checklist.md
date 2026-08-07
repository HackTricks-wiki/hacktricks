# Linux Yetki Yükseltme Kontrol Listesi

{{#include ../../banners/hacktricks-training.md}}

# Kontrol Listesi - Linux Yetki Yükseltme



### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) kontrolü, **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol edin, hassas bir detay var mı?
- [ ] **script kullanarak** [**kernel exploit'lerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) arayın (DirtyCow?)
- [ ] [**sudo sürümünün** vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version) olup olmadığını **kontrol edin**
- [ ] [**Dmesg** imza doğrulaması başarısız](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module ve module-loading yanlış yapılandırmalarını**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) inceleyin: `insmod`, `modinfo`, `lsmod`, `dmesg`, imza zorlaması ve `modules_disabled`.
- [ ] Yardımcı path değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse path'lerini**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol edin.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata'sı dahil olmak üzere [**yazılabilir /lib/modules path'lerini**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol edin.
- [ ] Daha fazla sistem enum'u ([tarih, sistem istatistikleri, CPU bilgisi, yazıcılar](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enum'u yapın](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drive'lar](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mount edilmiş** drive'ları listeleyin
- [ ] **Mount edilmemiş bir drive var mı?**
- [ ] **fstab içinde credential var mı?**

### [**Yüklü Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Yüklü** [**faydalı software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **var mı kontrol edin**
- [ ] **Yüklü** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **var mı kontrol edin**

### [Process'ler](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Bilinmeyen bir **software çalışıyor mu**?
- [ ] Herhangi bir software **olması gerekenden daha fazla privilege ile çalışıyor mu**?
- [ ] **Çalışan process'ler için exploit** arayın (özellikle çalışan sürüm için).
- [ ] Çalışan herhangi bir process'in **binary'sini değiştirebilir misiniz**?
- [ ] **Process'leri monitor edin** ve ilginç bir process'in sık çalışıp çalışmadığını kontrol edin.
- [ ] İlginç bir **process memory'sini okuyabilir misiniz** (password'ların kaydedilmiş olabileceği yer)?

### [Zamanlanmış/Cron job'ları?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)bir cron tarafından değiştiriliyor ve içine **write** edebiliyor musunuz?
- [ ] Bir cron job'ında [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Bazı [**değiştirilebilir script'ler** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**execute** ediliyor veya **değiştirilebilir bir klasörün** içinde mi?
- [ ] Bir **script'in** [**çok sık execute edildiğini**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) tespit ettiniz mi veya edilebilir mi? (her 1, 2 veya 5 dakikada)

### [Servis'ler](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Yazılabilir bir **.service** dosyası var mı?
- [ ] Bir **servis tarafından** execute edilen yazılabilir bir **binary** var mı?
- [ ] **systemd PATH içinde** yazılabilir bir klasör var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilecek yazılabilir bir **systemd unit drop-in** var mı?<sup>[[2]](#references)</sup>

### [Timer'lar](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Yazılabilir bir **timer** var mı?

### [Socket'ler](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Yazılabilir bir **.socket** dosyası var mı?
- [ ] Herhangi bir **socket ile iletişim kurabilir misiniz**?
- [ ] İlginç bilgiler içeren **HTTP socket'leri** var mı?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu anlamak için network'ü enum edin
- [ ] Makinenin içine shell aldıktan sonra daha önce erişemediğiniz **açık port'lar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff edebilir misiniz**?

### [Kullanıcılar](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel kullanıcı/grup **enum'u**
- [ ] **Çok büyük bir UID'ye** mi sahipsiniz? **Makine** **vulnerable** mı?
- [ ] Üyesi olduğunuz bir [**grup sayesinde privilege escalate edebilir misiniz**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard** verisi var mı?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğiniz **bilinen her password'ü**, mümkün olan **her kullanıcıyla** login olmak için **kullanmaya** çalışın. Password olmadan da login olmayı deneyin.

### [Yazılabilir PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH içindeki bir klasör üzerinde write privilege'ınız** varsa privilege escalate edebilirsiniz

### [SUDO ve SUID command'leri](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir command execute edebilir misiniz**? Bunu root olarak herhangi bir şeyi READ, WRITE veya EXECUTE etmek için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` `sudoedit` kullanımına izin veriyorsa, vulnerable sürümlerde (`sudo -V` < 1.9.12p2) herhangi bir dosyayı düzenlemek için `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrolü yapın. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Exploit edilebilir bir **SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** command'leri **path ile** sınırlandırılmış mı? Kısıtlamaları **bypass edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Path belirtilmemiş Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirten SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) var mı? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasörden gelen [**SUID binary içinde .so library eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**Kullanılabilir SUDO token'ları**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) var mı? [**SUDO token oluşturabilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/ değiştirebilir misiniz**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command'i

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary'de **beklenmeyen capability** var mı?

### [ACL'ler](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada **beklenmeyen ACL** var mı?

### [Açık Shell session'ları](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [İlginç Dosyalar](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile dosyaları** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] **passwd/shadow dosyaları** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] Hassas veriler için **genellikle ilginç klasörleri kontrol edin**
- [ ] Erişebileceğiniz veya executable dosyaları değiştirebileceğiniz **tuhaf konumlu/sahipli dosyalar**
- [ ] Son dakikalarda **değiştirilmiş** dosyalar
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web dosyaları** (password'lar?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary command execute etmek için **Python library'sini değiştirebilir misiniz**?
- [ ] **Log dosyalarını değiştirebilir misiniz**? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** değiştirebilir misiniz? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına write edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Diğer trick'ler**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalate etmek için NFS'yi abuse edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**Restrictive shell'den escape etmeniz gerekiyor mu**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## Referanslar

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
