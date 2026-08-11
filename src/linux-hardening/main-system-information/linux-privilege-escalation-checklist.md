# Linux Privilege Escalation Kontrol Listesi

{{#include ../../banners/hacktricks-training.md}}

# Kontrol Listesi - Linux Privilege Escalation



### **Linux local privilege escalation vektörlerini aramak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) kontrol edin, **yazılabilir klasör** var mı?
- [ ] [**env değişkenlerini**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrol edin, hassas bir ayrıntı var mı?
- [ ] [**kernel exploitlerini**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **scriptler kullanarak** arayın (DirtyCow?)
- [ ] Bir kernel PoC çalıştırmadan önce yalnızca `uname -r` değerini değil, **gerçek ön koşullarını** doğrulayın: mimari, gerekli `CONFIG_*` seçenekleri/modülleri, namespace oluşturma ve etkin mitigations. Örneğin `unshare -Urn true` ile user/network namespace kullanılabilirliğini test edin; modern netfilter exploitleri `CONFIG_USER_NS`, unprivileged user namespaces ve `CONFIG_NF_TABLES` gerektirebilir.<sup>[[3]](#references)</sup>
- [ ] [**sudo sürümünün** vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version) olup olmadığını **kontrol edin**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module ve module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) inceleyin: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement ve `modules_disabled`.
- [ ] Helper path değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrol edin.
- [ ] Yazılabilir `.ko*` dosyaları ve `modules.*` metadata dahil olmak üzere [**yazılabilir /lib/modules pathlerini**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrol edin.
- [ ] Daha fazla system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enumerate edin](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mount edilmiş** drive'ları listeleyin
- [ ] **Mount edilmemiş bir drive var mı?**
- [ ] fstab içinde **credential var mı?**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kurulu** [**yararlı software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **var mı kontrol edin**
- [ ] **Kurulu** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **var mı kontrol edin**
- [ ] Debian/Ubuntu üzerinde **needrestart interpreter scanning** kurulu/etkin mi kontrol edin: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Vulnerable build'ler, APT veya `unattended-upgrades` needrestart'ı root olarak çağırdığında attacker-controlled `PYTHONPATH`/`RUBYLIB` değerlerini yeniden kullanarak, `/proc/<pid>/exe` üzerinde race condition oluşturarak veya attacker-controlled Perl pathlerini tarayarak privilege boundary'yi aştı.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Bilinmeyen bir **software çalışıyor mu?**
- [ ] Herhangi bir software sahip olması gerekenden **daha fazla privilege ile mi çalışıyor**?
- [ ] **Çalışan processlerin exploitlerini** arayın (özellikle çalışan sürümünü).
- [ ] Çalışan herhangi bir processin **binary'sini değiştirebilir misiniz**?
- [ ] **Processleri monitor edin** ve ilginç bir processin sık çalışıp çalışmadığını kontrol edin.
- [ ] İlginç bir **process memory'sini okuyabilir misiniz** (password'ların kaydedilmiş olabileceği yer)?

### [Scheduled/Cron işleri?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)herhangi bir cron tarafından değiştiriliyor ve bu path'e **write** edebiliyor musunuz?
- [ ] Bir cron job içinde [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Bir [**değiştirilebilir script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**çalıştırılıyor** veya **değiştirilebilir klasör** içinde mi?
- [ ] Bir **scriptin** [**çok sık çalıştırılabildiğini** veya çalıştırıldığını](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) tespit ettiniz mi? (her 1, 2 veya 5 dakikada bir)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **Yazılabilir bir .service** dosyası var mı?
- [ ] Bir **service** tarafından çalıştırılan **yazılabilir bir binary** var mı?
- [ ] Bir root unit tarafından referans verilen yazılabilir bir **helper, config veya environment dosyası** var mı (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Birleştirilmiş unit'i `systemctl cat <unit>` ile inceleyin ve [service/socket file abuse](../interesting-files-permissions/write-to-root.md) konusunu gözden geçirin.
- [ ] systemd PATH içinde **yazılabilir bir klasör** var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilecek **yazılabilir bir systemd unit drop-in** var mı?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **Yazılabilir bir timer** var mı?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **Yazılabilir bir .socket** dosyası var mı?
- [ ] Herhangi bir **socket ile iletişim kurabilir misiniz**?
- [ ] İlginç bilgiler içeren **HTTP socketleri** var mı?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` veya bir kubelet endpoint'i gibi bir [**container-runtime veya node-agent API'sine**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) erişebilir misiniz? Her zamanki CLI mevcut olmasa bile raw HTTP/gRPC API'yi test edin.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile iletişim kurabilir misiniz**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu öğrenmek için network'ü enumerate edin
- [ ] Makinenin içinde shell aldıktan sonra daha önce erişemediğiniz **açık portlar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff edebilir misiniz**?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel user/group **enumeration**
- [ ] **Çok büyük bir UID'niz** var mı? **Machine** vulnerable mı?
- [ ] Ait olduğunuz bir [**group sayesinde privilege escalation yapabilir misiniz**](../user-information/interesting-groups-linux-pe/index.html)?
- [ ] **Clipboard** verileri var mı?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğiniz her **known password'u**, olası **her user** ile login olmak için **kullanmayı** deneyin. Password olmadan da login olmayı deneyin.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir klasör üzerinde **write privilege'larınız** varsa privilege escalation yapabilirsiniz

### [SUDO ve SUID command'leri](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir command çalıştırabilir misiniz**? Bunu root olarak herhangi bir şeyi READ, WRITE veya EXECUTE etmek için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` `sudoedit` kullanımına izin veriyorsa, vulnerable sürümlerde (`sudo -V` < 1.9.12p2) `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrolü yapın. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Exploit edilebilir bir **SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** command'leri **path** ile **sınırlandırılmış** mı? Kısıtlamaları **bypass edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Path belirtilmeden sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirtilen SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Yazılabilir bir klasörde [**SUID binary içinde .so library eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya yazılabilir library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**SUDO token'ları mevcut mu**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Bir SUDO token oluşturabilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/ değiştirebilir misiniz**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
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

- [ ] **Profile dosyaları** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] **passwd/shadow dosyaları** - Hassas verileri okuyabilir misiniz? Privesc için write edebilir misiniz?
- [ ] Hassas veriler için **genellikle ilginç klasörleri kontrol edin**
- [ ] Erişebileceğiniz veya executable dosyaları değiştirebileceğiniz **garip konumlu/sahipli dosyalar**
- [ ] Son dakikalarda **değiştirilmiş** dosyalar
- [ ] **Sqlite DB dosyaları**
- [ ] **Gizli dosyalar**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web dosyaları** (password'lar?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Genel arama**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary command'ler çalıştırmak için **python library'sini değiştirebilir misiniz**?
- [ ] **Log dosyalarını değiştirebilir misiniz**? **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/** değiştirebilir misiniz? Centos/Redhat exploit
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına write edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalation yapmak için NFS'yi abuse edebilir misiniz**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**Restrictive shell'den escape etmeniz**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) gerekiyor mu?



## References

- [1] [Sudo advisory: sudoedit ile arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit gereksinimleri ve araştırması](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart içindeki LPE'ler](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
