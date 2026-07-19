# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Linux yerel privilege escalation vector'lerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) kontrolü yapın, **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol edin, hassas bir detay var mı?
- [ ] [**kernel exploit'lerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **script'ler kullanarak** arayın (DirtyCow?)
- [ ] [**sudo sürümünün** güvenlik açığı içerip içermediğini](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **kontrol edin**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module ve module-loading yanlış yapılandırmalarını**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) inceleyin: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement ve `modules_disabled`.
- [ ] Yardımcı yol değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse yollarını**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol edin.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata'sı dahil olmak üzere [**yazılabilir /lib/modules yollarını**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol edin.
- [ ] Daha fazla system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enumerate edin](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mount edilmiş** drive'ları listeleyin
- [ ] **Mount edilmemiş bir drive var mı?**
- [ ] fstab içinde **credential var mı?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Yüklü**[ **faydalı software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **var mı kontrol edin**
- [ ] **Yüklü** [**güvenlik açığı içeren software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **var mı kontrol edin**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Bilinmeyen bir **software çalışıyor mu**?
- [ ] Herhangi bir software sahip olması gerekenden **daha fazla privilege ile çalışıyor mu**?
- [ ] **Çalışan process'lerin exploit'lerini** arayın (özellikle çalışan sürümü).
- [ ] Çalışan herhangi bir process'in **binary'sini değiştirebilir misiniz**?
- [ ] **Process'leri monitor edin** ve ilginç bir process'in sık çalışıp çalışmadığını kontrol edin.
- [ ] İlginç bir **process memory'sini okuyabilir misiniz** (password'lerin kaydedilmiş olabileceği yer)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)herhangi bir cron tarafından değiştiriliyor mu ve bu konuma **write** edebiliyor musunuz?
- [ ] Bir cron job içinde [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Bazı [**değiştirilebilir script'ler** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **çalıştırılıyor** veya **değiştirilebilir bir klasörün** içinde mi?
- [ ] Bir **script'in** [**çok **sık** çalıştırılabileceğini](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) veya çalıştırıldığını tespit ettiniz mi? (her 1, 2 ya da 5 dakikada bir)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Yazılabilir bir **.service** dosyası var mı?
- [ ] Bir **service** tarafından çalıştırılan yazılabilir bir **binary** var mı?
- [ ] systemd PATH içinde yazılabilir bir klasör var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilecek yazılabilir bir **systemd unit drop-in** var mı?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Yazılabilir bir **timer** var mı?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Herhangi bir **socket ile iletişim kurabilir misiniz**?
- [ ] İlginç bilgiler içeren **HTTP socket'leri** var mı?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu öğrenmek için network'ü enumerate edin
- [ ] Makinenin içinde shell elde etmeden önce erişemediğiniz **açık port'lar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff edebilir misiniz**?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel user/group **enumeration**
- [ ] **Çok büyük bir UID'niz** mi var? **Machine** **vulnerable** mı?
- [ ] Ait olduğunuz bir group sayesinde [**privilege escalation yapabilir misiniz**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard** verisi var mı?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğiniz her **known password'ü**, mümkün olan **her user ile** login olmak için **kullanmaya** çalışın. Ayrıca password olmadan da login olmayı deneyin.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir klasör üzerinde **write privilege'larınız** varsa privilege escalation yapabilirsiniz

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir command çalıştırabilir misiniz**? Herhangi bir şeyi root olarak READ, WRITE veya EXECUTE etmek için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l`, `sudoedit` kullanımına izin veriyorsa, vulnerable sürümlerde (`sudo -V` < 1.9.12p2) arbitrary dosyaları düzenlemek için `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrolü yapın. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Exploit edilebilir bir **SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** command'ları **path** ile sınırlı mı? Kısıtlamaları [**bypass edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Path belirtilmeden kullanılan Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirten SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) var mı? Bypass edin
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasörde [**SUID binary'de .so library eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**SUDO token'ları mevcut mu**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**SUDO token oluşturabilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/ dosyasını değiştirebilir misiniz**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary'de **beklenmeyen bir capability** var mı?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada **beklenmeyen bir ACL** var mı?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] **passwd/shadow files** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] Hassas veriler için **genellikle ilginç olan klasörleri kontrol edin**
- [ ] Erişebileceğiniz veya executable dosyaları değiştirebileceğiniz **tuhaf konumlu/sahipli dosyalar**
- [ ] Son dakikalarda **değiştirilmiş** dosyalar
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web files** (password'ler?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary command'ler çalıştırmak için **python library'sini değiştirebilir misiniz**?
- [ ] **Log dosyalarını değiştirebilir misiniz**? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** dosyasını değiştirebilir misiniz? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına write edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalation yapmak için NFS'yi abuse edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**Restrictive shell'den escape etmeniz gerekiyor mu**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
