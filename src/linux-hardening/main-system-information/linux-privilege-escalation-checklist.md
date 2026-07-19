# Kontrol Listesi - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Linux yerel privilege escalation vektörlerini bulmak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) kontrol edin, herhangi bir **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol edin, hassas bir detay var mı?
- [ ] **Scriptler kullanarak** [**kernel exploitlerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) arayın (DirtyCow?)
- [ ] [**sudo sürümünün** güvenlik açığı içerip içermediğini](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **kontrol edin**
- [ ] [**Dmesg** imza doğrulaması başarısız](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**Kernel module ve module-loading yanlış yapılandırmalarını**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) inceleyin: `insmod`, `modinfo`, `lsmod`, `dmesg`, imza zorlaması ve `modules_disabled`.
- [ ] Yardımcı path değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse path'lerini**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol edin.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata'sı dahil olmak üzere [**yazılabilir /lib/modules path'lerini**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol edin.
- [ ] Daha fazla system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enumerate edin](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mount edilmiş** drive'ları listeleyin
- [ ] **Mount edilmemiş bir drive var mı?**
- [ ] **fstab içinde credential var mı?**

### [**Kurulu Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kurulu** [ **faydalı software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **var mı kontrol edin**
- [ ] **Kurulu** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **var mı kontrol edin**

### [Process'ler](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Herhangi bir **bilinmeyen software çalışıyor mu**?
- [ ] Herhangi bir software **sahip olması gerekenden daha fazla privilege ile mi çalışıyor**?
- [ ] **Çalışan process'ler için exploitleri** arayın (özellikle çalışan sürümü).
- [ ] Çalışan herhangi bir process'in **binary'sini değiştirebilir misiniz**?
- [ ] **Process'leri monitor edin** ve ilgi çekici bir process'in sık çalışıp çalışmadığını kontrol edin.
- [ ] İlgi çekici herhangi bir **process memory'sini okuyabilir misiniz** (password'lerin kaydedilmiş olabileceği yer)?

### [Zamanlanmış/Cron job'ları?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)bir cron tarafından değiştiriliyor mu ve buraya **yazabiliyor musunuz**?
- [ ] Bir cron job'ında [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Bazı [**değiştirilebilir script'ler** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**çalıştırılıyor** veya **değiştirilebilir bir klasörün** içinde mi?
- [ ] Bir **script'in** [**çok **sık** çalıştırılabildiğini** veya çalıştırıldığını](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) tespit ettiniz mi? (her 1, 2 veya 5 dakikada bir)

### [Servisler](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Yazılabilir bir **.service** dosyası var mı?
- [ ] Bir **service** tarafından çalıştırılan yazılabilir bir **binary** var mı?
- [ ] systemd PATH içinde yazılabilir bir **klasör** var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilecek yazılabilir bir **systemd unit drop-in** var mı?

### [Timer'lar](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Yazılabilir bir **timer** var mı?

### [Socket'ler](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Yazılabilir bir **.socket** dosyası var mı?
- [ ] Herhangi bir **socket ile iletişim kurabilir misiniz**?
- [ ] İlgi çekici bilgiler içeren **HTTP socket'leri** var mı?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu öğrenmek için network'ü enumerate edin
- [ ] Makinenin içinde bir shell elde etmeden önce erişemediğiniz **açık portlar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff edebilir misiniz**?

### [Kullanıcılar](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel kullanıcı/group **enumeration**
- [ ] **Çok büyük bir UID'niz** mi var? **Makine** **vulnerable** mı?
- [ ] Üyesi olduğunuz bir **group sayesinde privilege escalate edebilir misiniz**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard** verileri var mı?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğiniz **bilinen her password'ü**, mümkün olan **her kullanıcıyla** login olmak için **kullanmaya çalışın**. Ayrıca password olmadan da login olmayı deneyin.

### [Yazılabilir PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir klasör üzerinde **yazma privilege'ınız** varsa privilege escalate edebilirsiniz

### [SUDO ve SUID command'leri](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir command çalıştırabilir misiniz**? Bunu root olarak herhangi bir şeyi READ, WRITE veya EXECUTE etmek için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` `sudoedit` kullanımına izin veriyorsa, vulnerable sürümlerde (`sudo -V` < 1.9.12p2) rastgele dosyaları düzenlemek için `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrol edin. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Exploit edilebilir bir **SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** command'leri **path** ile sınırlandırılmış mı? Kısıtlamaları](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) **bypass edebilir misiniz**?
- [ ] [**Path belirtilmeden sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirten SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) var mı? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasörde bulunan [**SUID binary'de .so library eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir library path'i**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**SUDO token'ları mevcut mu**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Bir SUDO token oluşturabilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/** dosyasını değiştirebilir misiniz](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command'i

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary'de **beklenmeyen capability** var mı?

### [ACL'ler](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada **beklenmeyen ACL** var mı?

### [Açık Shell Oturumları](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Öngörülebilir OpenSSL PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH ilgi çekici configuration değerleri**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [İlgi Çekici Dosyalar](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile dosyaları** - Hassas veri okuyabilir misiniz? Privilege escalation için yazabilir misiniz?
- [ ] **passwd/shadow dosyaları** - Hassas veri okuyabilir misiniz? Privilege escalation için yazabilir misiniz?
- [ ] Hassas veri için **genellikle ilgi çekici klasörleri kontrol edin**
- [ ] **Tuhaf konumdaki/Sahibi olduğunuz dosyalar,** erişebileceğiniz veya değiştirebileceğiniz executable dosyalar olabilir
- [ ] Son dakikalarda **değiştirilmiş** dosyalar
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web dosyaları** (password'ler?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Rastgele command'ler çalıştırmak için **python library'sini değiştirebilir misiniz**?
- [ ] **Log dosyalarını değiştirebilir misiniz**? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** dizinini değiştirebilir misiniz? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Diğer trick'ler**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalate etmek için NFS'yi abuse edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**Restrictive shell'den escape etmeniz gerekiyor mu**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referanslar

- [Sudo advisory: sudoedit ile rastgele dosya düzenleme](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
