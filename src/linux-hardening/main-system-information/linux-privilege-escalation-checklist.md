# Linux Privilege Escalation Checklist

# Checklist - Linux Privilege Escalation



### **Linux local privilege escalation vector'lerini aramak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** al
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) değerini kontrol et, **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol et, hassas bir ayrıntı var mı?
- [ ] [**kernel exploit'lerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **script'ler kullanarak** ara (DirtyCow?)
- [ ] Bir kernel PoC çalıştırmadan önce yalnızca `uname -r` değerini değil, **gerçek ön koşullarını** doğrula: mimari, gerekli `CONFIG_*` seçenekleri/modülleri, namespace oluşturma ve etkin mitigations. Örneğin, `unshare -Urn true` ile user/network namespace kullanılabilirliğini test et; modern netfilter exploit'leri `CONFIG_USER_NS`, unprivileged user namespace'leri ve `CONFIG_NF_TABLES` gerektirebilir.<sup>[[3]](#references)</sup>
- [ ] [**sudo sürümünün** güvenlik açığı içerip içermediğini](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **kontrol et**
- [ ] [**Dmesg** signature verification başarısız](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module ve module-loading yanlış yapılandırmalarını**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) incele: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement ve `modules_disabled`.
- [ ] Yardımcı path değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse path'lerini**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol et.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata dahil olmak üzere [**yazılabilir /lib/modules path'lerini**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol et.
- [ ] Daha fazla system enum ([tarih, system istatistikleri, CPU bilgileri, yazıcılar](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enumerate et](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Sürücüler](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mount edilmiş** sürücüleri listele
- [ ] **Mount edilmemiş bir sürücü var mı?**
- [ ] fstab içinde **credential var mı?**

### [**Yüklü Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Yüklü** [**kullanışlı software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **var mı kontrol et**
- [ ] **Yüklü** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **var mı kontrol et**
- [ ] Debian/Ubuntu'da **needrestart interpreter scanning** kurulu/etkin mi kontrol et: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Vulnerable build'ler, APT veya `unattended-upgrades` needrestart'i root olarak çağırdığında attacker-controlled `PYTHONPATH`/`RUBYLIB` değerlerini yeniden kullanarak, `/proc/<pid>/exe` üzerinde race yaparak veya attacker-controlled Perl path'lerini tarayarak privilege boundary'yi aştı.<sup>[[4]](#references)</sup>

### [Process'ler](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **Bilinmeyen bir software çalışıyor mu?**
- [ ] Herhangi bir software olması gerekenden **daha fazla privilege ile mi çalışıyor**?
- [ ] **Çalışan process'lerin exploit'lerini** ara (özellikle çalışan sürümü).
- [ ] Çalışan herhangi bir process'in **binary'sini değiştirebilir** misin?
- [ ] **Process'leri monitor et** ve ilginç bir process'in sık çalışıp çalışmadığını kontrol et.
- [ ] Bazı ilginç **process memory'sini** okuyabilir misin (password'lerin kaydedilmiş olabileceği yer)?

### [Zamanlanmış/Cron job'ları?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Bazı cron tarafından [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)değiştiriliyor ve bu path'e **write** edebiliyor musun?
- [ ] Bir cron job'ında [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Bazı [**değiştirilebilir script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**execute** ediliyor mu veya **değiştirilebilir klasör** içinde mi?
- [ ] Bir **script'in** [**çok sık execute edildiğini**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) tespit ettin mi veya böyle bir ihtimal var mı? (her 1, 2 veya 5 dakikada bir)

### [Servisler](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Yazılabilir bir **.service** dosyası var mı?
- [ ] Bir **service** tarafından execute edilen **yazılabilir bir binary** var mı?
- [ ] Bir root unit tarafından referans verilen yazılabilir **helper, config veya environment dosyası** var mı (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Birleştirilmiş unit'i `systemctl cat <unit>` ile incele ve [service/socket file abuse](../interesting-files-permissions/write-to-root.md)'ı gözden geçir.
- [ ] systemd PATH içinde **yazılabilir bir klasör** var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilen **yazılabilir bir systemd unit drop-in** var mı?<sup>[[2]](#references)</sup>

### [Timer'lar](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Yazılabilir bir **timer** var mı?

### [Socket'ler](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Yazılabilir bir **.socket** dosyası var mı?
- [ ] Herhangi bir **socket ile iletişim kurabilir** misin?
- [ ] İlginç bilgiler içeren **HTTP socket'leri** var mı?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` veya bir kubelet endpoint'i gibi bir [**container-runtime veya node-agent API'sine**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) erişebilir misin? Her zamanki CLI mevcut olmasa bile raw HTTP/gRPC API'yi test et.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir** misin?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunu anlamak için network'ü enumerate et
- [ ] Makinenin içinde shell aldıktan sonra daha önce erişemediğin **açık port'lar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff** edebilir misin?

### [Kullanıcılar](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel user/group **enumeration**
- [ ] **Çok büyük bir UID'ye** mi sahipsin? **Makine** **vulnerable** mı?
- [ ] Ait olduğun bir [**group sayesinde privilege escalate**](../user-information/interesting-groups-linux-pe/index.html) edebilir misin?
- [ ] **Clipboard** verileri?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğin her **known password'ü**, mümkün olan **her user ile** login olmak için **kullanmayı** dene. Password olmadan da login olmayı dene.

### [Yazılabilir PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir klasör üzerinde **write privilege'in** varsa privilege escalate edebilirsin

### [SUDO ve SUID command'leri](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir command execute** edebilir misin? Root olarak herhangi bir şeyi READ, WRITE veya EXECUTE etmek için kullanabilir misin? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` `sudoedit` kullanımına izin veriyorsa vulnerable sürümlerde (`sudo -V` < 1.9.12p2) rastgele dosyaları düzenlemek için `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrolü yap. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Herhangi bir **exploitable SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** command'leri **path** ile **sınırlandırılmış** mı? Kısıtlamaları](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) **bypass edebilir** misin?
- [ ] [**Path belirtilmeden kullanılan Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirten SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasörde [**SUID binary'de eksik .so library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**SUDO token'ları mevcut mu**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Bir SUDO token'ı oluşturabilir**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) misin?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) misin?
- [ ] [**/etc/ld.so.conf.d/** dosyasını değiştirebilir](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) misin?
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

- [ ] **Profile dosyaları** - Hassas veri oku? Privesc için yaz?
- [ ] **passwd/shadow dosyaları** - Hassas veri oku? Privesc için yaz?
- [ ] Hassas veri için **genellikle ilginç klasörleri kontrol et**
- [ ] Erişebileceğin veya executable dosyaları değiştirebileceğin **garip konumda/sahipli dosyalar**
- [ ] Son birkaç dakika içinde **değiştirilmiş** dosyalar
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web dosyaları** (password'ler?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullan
- [ ] **Genel arama**

### [**Yazılabilir Dosyalar**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Rastgele command'ler execute etmek için **Python library'sini değiştirebilir** misin?
- [ ] **Log dosyalarını değiştirebilir** misin? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** klasörünü değiştirebilir misin? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına yazabilir**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) misin?

### [**Diğer trick'ler**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalate etmek için NFS'yi abuse**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) edebilir misin?
- [ ] [**Restrictive shell'den escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) etmen gerekiyor mu?



## References

- [1] [Sudo advisory: sudoedit rastgele dosya düzenleme](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in yapılandırması](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit gereksinimleri ve araştırması](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart içindeki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
