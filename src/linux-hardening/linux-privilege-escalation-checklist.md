# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Linux local privilege escalation vectors**'ını aramak için en iyi araç: [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] OS bilgilerini al
- [ ] [**PATH**](privilege-escalation/index.html#path)'i kontrol et, yazılabilir bir klasör var mı?
- [ ] [**env variables**](privilege-escalation/index.html#env-info)'i kontrol et, hassas bir bilgi var mı?
- [ ] [**kernel exploits**](privilege-escalation/index.html#kernel-exploits)'i scriptler kullanarak ara (DirtyCow?)
- [ ] [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)'u kontrol et
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Daha fazla sistem enumerasyonu ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] Bağlı sürücüleri listele
- [ ] Herhangi bağlanmamış sürücü var mı?
- [ ] fstab içinde herhangi bir kimlik bilgisi var mı?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] Yüklü [**useful software**](privilege-escalation/index.html#useful-software) var mı, kontrol et
- [ ] Yüklü [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) var mı, kontrol et

### [Processes](privilege-escalation/index.html#processes)

- [ ] Bilinmeyen bir yazılım çalışıyor mu?
- [ ] Herhangi bir yazılım olması gerekenden daha fazla ayrıcalıkla mı çalışıyor?
- [ ] Çalışan süreçlerin exploitlerini ara (özellikle çalıştırılan versiyona dikkat et).
- [ ] Herhangi bir çalışan sürecin binary'sini değiştirebilir misin?
- [ ] Süreçleri izle ve ilginç bir sürecin sık çalışıp çalışmadığını kontrol et.
- [ ] Bazı ilginç süreçlerin belleğini okuyabilir misin (parolalar burada saklanmış olabilir)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/index.html#cron-path) cron tarafından değiştiriliyor mu ve burada yazma iznin var mı?
- [ ] Cron işinde herhangi bir [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) var mı?
- [ ] Herhangi bir [**modifiable script**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) çalıştırılıyor mu veya yazılabilir bir klasörün içinde mi?
- [ ] Bazı scriptlerin çok sık çalıştırılıyor olabileceğini tespit ettin mi? (her 1, 2 veya 5 dakikada)

### [Services](privilege-escalation/index.html#services)

- [ ] Yazılabilir bir .service dosyası var mı?
- [ ] Bir service tarafından çalıştırılan yazılabilir bir binary var mı?
- [ ] systemd PATH içinde yazılabilir bir klasör var mı?
- [ ] `/etc/systemd/system/<unit>.d/*.conf` içinde `ExecStart`/`User`'ı override edebilecek yazılabilir systemd unit drop-in var mı?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Yazılabilir bir timer var mı?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Yazılabilir bir .socket dosyası var mı?
- [ ] Herhangi bir socket ile iletişim kurabilir misin?
- [ ] İlginç bilgi içeren HTTP socket'leri var mı?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Herhangi bir D-Bus ile iletişim kurabilir misin?

### [Network](privilege-escalation/index.html#network)

- [ ] Ağda keşif yaparak nerede olduğunu belirle
- [ ] Shell aldıktan sonra önceden erişemediğin açık portlar var mı?
- [ ] `tcpdump` kullanarak trafiği dinleyebilir misin?

### [Users](privilege-escalation/index.html#users)

- [ ] Genel kullanıcı/grup enumerasyonu yap
- [ ] Çok büyük bir UID'in var mı? Bu makine için bir zayıflık olabilir mi?
- [ ] Üyesi olduğun bir grupla [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) yapabilir misin?
- [ ] Panodaki veriler var mı?
- [ ] Parola politikası?
- [ ] Daha önce keşfettiğin tüm bilinen parolaları her olası kullanıcı ile giriş yapmak için dene. Ayrıca parola olmadan da giriş yapmayı dene.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH içindeki bir klasöre yazma iznin varsa ayrıcalıkları yükseltebilirsin

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] `sudo` ile herhangi bir komut çalıştırabiliyor musun? Bunu root olarak herhangi bir şeyi OKU, YAZ veya ÇALIŞTIRmak için kullanabilir misin? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Eğer `sudo -l` `sudoedit`'e izin veriyorsa, **sudoedit argument injection** (CVE-2023-22809) için `SUDO_EDITOR`/`VISUAL`/`EDITOR` yoluyla, etkilenebilir sürümlerde rastgele dosyaları düzenleme imkanı olup olmadığını kontrol et (`sudo -V` < 1.9.12p2). Örnek: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Herhangi bir exploitable SUID binary var mı? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** komutları path ile mi sınırlandırılmış? bu kısıtlamaları atlatabilir misin](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) writable bir klasörden mi?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**Read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) yapabilir misin?
- [ ] [**Modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d) yapabilir misin?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) komutu

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Herhangi bir binary beklenmeyen bir capability'e sahip mi?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Herhangi bir dosyada beklenmeyen bir ACL var mı?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] screen
- [ ] tmux

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Hassas veri okunuyor mu? privesc için yazılabiliyor mu?
- [ ] **passwd/shadow files** - Hassas veri okunuyor mu? privesc için yazılabiliyor mu?
- [ ] Hassas veri için yaygın ilginç klasörleri kontrol et
- [ ] **Weird Location/Owned files**, executable dosyalara erişimin veya değişiklik yapma imkanın olabilir
- [ ] Son birkaç dakika içinde **değiştirilmiş**
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (parolalar?)
- [ ] **Backups**?
- [ ] Parola içeren bilinen dosyalar: **Linpeas** ve **LaZagne** kullan
- [ ] Genel arama

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] Python kütüphanesini değiştirerek rastgele komut çalıştırabilir misin?
- [ ] Log dosyalarını değiştirebilir misin? **Logtotten** exploit
- [ ] `/etc/sysconfig/network-scripts/` dizinine yazabilir misin? Centos/Redhat exploit
- [ ] ini, init.d, systemd veya rc.d dosyalarına yazabilir misin? (init/init.d/systemd/rc.d) 

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation) yapabilir misin?
- [ ] Kısıtlı bir shell'den [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells) yapman gerekiyor mu?

## Referanslar

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
