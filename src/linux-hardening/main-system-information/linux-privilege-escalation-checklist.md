# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Linux yerel privilege escalation vector'larını aramak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Sistem Bilgileri](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS bilgilerini** alın
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) kontrolü yapın, herhangi bir **writable folder** var mı?
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) kontrolü yapın, herhangi bir hassas detay var mı?
- [ ] [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) için **script'leri kullanarak** arama yapın (DirtyCow?)
- [ ] Bir kernel PoC çalıştırmadan önce yalnızca `uname -r` bilgisine değil, **gerçek gereksinimlerine** de bakarak doğrulama yapın: architecture, gerekli `CONFIG_*` seçenekleri/modülleri, namespace oluşturma ve aktif mitigations. Örneğin, `unshare -Urn true` ile user/network namespace kullanılabilirliğini test edin; modern netfilter exploit'leri `CONFIG_USER_NS`, unprivileged user namespace'ler ve `CONFIG_NF_TABLES` gerektirebilir.<sup>[[3]](#references)</sup>
- [ ] [**sudo version**](../linux-basics/linux-privilege-escalation/index.html#sudo-version) açığının olup olmadığını **kontrol edin**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module ve module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) incelemesi yapın: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement ve `modules_disabled`.
- [ ] Helper path değiştirilebiliyor veya tetiklenebiliyorsa [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) kontrolü yapın.
- [ ] Writable `.ko*` dosyaları ve `modules.*` metadata dahil olmak üzere [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) kontrolü yapın.
- [ ] Daha fazla system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Daha fazla defense enumerate edin](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Mounted** drive'ları listeleyin
- [ ] **Unmounted drive** var mı?
- [ ] fstab içinde **credentials** var mı?

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kurulu** [**useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) var mı kontrol edin
- [ ] **Kurulu** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) var mı kontrol edin
- [ ] Debian/Ubuntu'da **needrestart interpreter scanning** kurulu/etkin mi kontrol edin: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Vulnerable build'ler, APT veya `unattended-upgrades` needrestart'ı root olarak çağırdığında attacker-controlled `PYTHONPATH`/`RUBYLIB` değerlerini yeniden kullanarak, `/proc/<pid>/exe` üzerinde race yaparak veya attacker-controlled Perl path'lerini tarayarak privilege boundary'yi aştı.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Herhangi bir **unknown software** çalışıyor mu?
- [ ] Herhangi bir software sahip olması gerekenden **daha fazla privilege** ile mi çalışıyor?
- [ ] **Çalışan process'ler için exploit** arayın (özellikle çalışan version için).
- [ ] Çalışan process'lerden herhangi birinin **binary'sini değiştirebilir** misiniz?
- [ ] **Process'leri monitor edin** ve herhangi bir ilginç process'in sık çalışıp çalışmadığını kontrol edin.
- [ ] İlginç herhangi bir **process memory'sini okuyabilir** misiniz (password'lerin kaydedilmiş olabileceği yer)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)bir cron tarafından değiştiriliyor ve bu path'e **write** edebiliyor musunuz?
- [ ] Bir cron job içinde [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)var mı?
- [ ] Herhangi bir [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)**execute** ediliyor mu veya **modifiable folder** içinde mi?
- [ ] Herhangi bir **script'in** [çok **sık**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **execute** edilebileceğini veya edildiğini tespit ettiniz mi? (her 1, 2 veya 5 dakikada)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Herhangi bir **writable .service** dosyası var mı?
- [ ] Bir **service** tarafından execute edilen **writable binary** var mı?
- [ ] Bir root unit tarafından referans verilen writable **helper, config veya environment file** var mı (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? `systemctl cat <unit>` ile merged unit'i inceleyin ve [service/socket file abuse](../interesting-files-permissions/write-to-root.md) konusunu gözden geçirin.
- [ ] systemd PATH içinde herhangi bir **writable folder** var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User` değerlerini override edebilecek **writable systemd unit drop-in** var mı?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Herhangi bir **writable timer** var mı?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Herhangi bir **writable .socket** dosyası var mı?
- [ ] Herhangi bir **socket ile communicate** edebilir misiniz?
- [ ] İlginç bilgiler içeren **HTTP sockets** var mı?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` veya bir kubelet endpoint'i gibi bir [**container-runtime veya node-agent API'sine**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) erişebiliyor musunuz? Her zamanki CLI mevcut olmasa bile raw HTTP/gRPC API'yi test edin.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir **D-Bus ile communicate** edebilir misiniz?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Nerede olduğunuzu öğrenmek için network'ü enumerate edin
- [ ] Makinenin içine shell aldıktan sonra daha önce erişemediğiniz **open port'lar** var mı?
- [ ] `tcpdump` kullanarak **traffic sniff** edebilir misiniz?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Genel user/group **enumeration**
- [ ] **Çok büyük bir UID**'niz var mı? **Machine** **vulnerable** mı?
- [ ] Üyesi olduğunuz bir group sayesinde [**privilege escalation yapabilir**](../user-information/interesting-groups-linux-pe/index.html) misiniz?
- [ ] **Clipboard** verileri var mı?
- [ ] Password Policy?
- [ ] Daha önce keşfettiğiniz her **known password'ı**, mümkün olan **her user ile** login olmak için **kullanmayı** deneyin. Password olmadan da login olmayı deneyin.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir folder üzerinde **write privilege'ınız** varsa privilege escalation yapabilirsiniz

### [SUDO ve SUID komutları](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo ile herhangi bir komut execute** edebilir misiniz? Bunu root olarak herhangi bir şeyi READ, WRITE veya EXECUTE etmek için kullanabilir misiniz? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l`, `sudoedit` kullanımına izin veriyorsa, vulnerable version'larda (`sudo -V` < 1.9.12p2) arbitrary file'ları düzenlemek için `SUDO_EDITOR`/`VISUAL`/`EDITOR` üzerinden **sudoedit argument injection** (CVE-2023-22809) kontrolü yapın. Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Herhangi bir **exploitable SUID binary** var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** komutları **path** ile **sınırlandırılmış** mı? Kısıtlamaları](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) **bypass** edebilir misiniz?
- [ ] [**Path belirtilmeden kullanılan Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) var mı?
- [ ] [**Path belirten SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Writable folder'dan gelen [**SUID binary'sinde .so library eksikliği**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) var mı?
- [ ] [**SUID RPATH/RUNPATH veya writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) var mı?
- [ ] [**SUDO token'ları mevcut**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) mı? [**SUDO token oluşturabilir**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) misiniz?
- [ ] [**sudoers dosyalarını okuyabilir veya değiştirebilir**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) misiniz?
- [ ] [**/etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) konumunu **değiştirebilir** misiniz?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) komutu

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary'de **beklenmeyen capability** var mı?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada **beklenmeyen ACL** var mı?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Hassas verileri okuyabilir misiniz? privesc için write edebilir misiniz?
- [ ] **passwd/shadow files** - Hassas verileri okuyabilir misiniz? privesc için write edebilir misiniz?
- [ ] Hassas veriler için **genellikle ilginç olan folder'ları kontrol edin**
- [ ] Erişebileceğiniz veya executable dosyaları değiştirebileceğiniz **garip konumdaki/sahipli dosyalar**
- [ ] Son dakikalarda **modified** edilmiş dosyalar
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH içindeki script/binary'ler**
- [ ] **Web files** (password'ler?)
- [ ] **Backup'lar**?
- [ ] **Password içeren bilinen dosyalar**: **Linpeas** ve **LaZagne** kullanın
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Arbitrary komutları execute etmek için **python library'yi modify** edebilir misiniz?
- [ ] **Log files'ı modify** edebilir misiniz? **Logtotten** exploit'i
- [ ] **/etc/sysconfig/network-scripts/** konumunu **modify** edebilir misiniz? Centos/Redhat exploit'i
- [ ] [**ini, int.d, systemd veya rc.d dosyalarına write**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) edebilir misiniz?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**Privilege escalation yapmak için NFS'i abuse**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) edebilir misiniz?
- [ ] [**Restrictive shell'den escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) etmeniz gerekiyor mu?



## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
