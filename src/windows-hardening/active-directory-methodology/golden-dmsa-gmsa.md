# Golden gMSA/dMSA Attack (Managed Service Account Password 오프라인 도출)

{{#include ../../banners/hacktricks-training.md}}

## 개요

Windows Managed Service Account는 관리자가 장기간 유지되는 비밀번호를 처리하지 않고도 서비스를 실행하도록 설계된 도메인 principal입니다.

1. **gMSA** (group Managed Service Account)는 `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`를 통해 권한이 부여된 컴퓨터에서 사용할 수 있습니다.
2. **dMSA** (delegated Managed Service Account)는 **Windows Server 2025**에서 도입되었습니다. 일반 인증을 권한이 부여된 머신 identity에 바인딩하며, migration workflow를 통해 기존 service account를 대체할 수 있습니다.

**Golden dMSA**를 **BadSuccessor**와 혼동하지 마세요. Golden dMSA에는 KDS root-key material의 compromise와 managed-account key 도출이 필요합니다. 반면 [BadSuccessor](badsuccessor-dmsa-migration-abuse.md)는 dMSA object와 해당 migration attribute에 대한 control을 악용합니다.

DC는 모든 gMSA에 대해 독립적으로 생성된 clear-text password를 저장하지 않습니다. 대신 **KDS root key**, 시간에 따라 인덱싱된 Group Key Distribution Protocol (GKDI) key, account SID를 사용해 account password를 도출합니다. Root-key object는 `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` 아래의 `msKds-ProvRootKey` object이며, 민감한 값은 `msKds-RootKeyData`입니다. `msDS-ManagedPasswordId`는 **GUID가 아닙니다**. 이는 KDS root-key GUID, GKDI `L0`/`L1`/`L2` index, domain/forest metadata를 포함하는 binary key identifier입니다. DC는 `GMSA PASSWORD` label과 binary SID를 context로 사용해 KDF를 적용한 후, gMSA password를 retrieve할 권한이 있는 principal에게만 `MSDS-MANAGEDPASSWORD_BLOB`을 제공합니다.<sup>[[2]](#references)</sup>

dMSA는 일반적으로 operational 측면에서 다릅니다. 해당 secret은 DC에 남아 있도록 설계되며, KDC는 권한이 부여된 machine에 credential을 발급합니다. 그러나 dMSA는 underlying KDS/GKDI password derivation을 재사용합니다. Golden dMSA는 이 secret을 직접 reconstruct하므로 의도된 machine-bound flow와 service host의 Credential Guard를 우회합니다.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

KDS root key를 추출한 후 공격자는 `msDS-ManagedPassword`를 읽지 않고도 해당 key에 연결된 account의 password를 도출할 수 있습니다. 이는 account별 password-retrieval ACL을 우회하며, compromise된 root key가 계속 사용되는 동안 일반적인 managed-password rotation에도 영향을 받지 않습니다. gMSA의 경우 읽을 수 있는 `msDS-ManagedPasswordId`가 일반적으로 정확한 key identifier를 제공합니다. ACL이 제한된 dMSA의 경우 Golden dMSA는 누락된 identifier를 **1,024개의 후보**로 줄입니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 사전 요구 사항

* 일반적으로 Enterprise Admin / forest-root Domain Admin 권한, DC의 `SYSTEM`, 또는 노출된 DC database나 backup을 통해 획득하는 관련 KDS root-key object.<sup>[[1]](#references)[[2]](#references)</sup>
* 대상 account의 SID, DNS domain, forest name, `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* 직접 gMSA computation을 수행하려면 base64로 인코딩된 `msDS-ManagedPasswordId`가 필요하며, Golden dMSA에서는 이를 추측할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
* [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA)를 사용하기 위한 .NET Framework 4.7.2가 설치된 x64 Windows host.<sup>[[3]](#references)</sup>

### Phase 1 - KDS root key 추출

`GoldenDMSA`와 [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA)는 root-key object field를 base64 blob으로 export합니다. domain argument가 없으면 tool은 forest root를 query하며 적절한 privileged directory access가 필요합니다. domain/forest argument를 지정하면 DC의 `SYSTEM`은 해당 DC의 local Configuration naming-context replica를 query할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
root-key GUID와 base64 root-key blob을 모두 기록합니다. 레지스트리의 `SECURITY`/`SYSTEM` hive export만으로는 KDS root key가 아닙니다. 권한 있는 자료는 AD Configuration partition에 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - gMSA / dMSA objects 열거

gMSA의 경우 `sAMAccountName`, `objectSid`, 바이너리 `msDS-ManagedPasswordId`를 가져옵니다. 호출자가 `msDS-ManagedPassword`를 검색할 권한이 없는 경우에도 후자는 일반적으로 읽을 수 있습니다.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
dMSA의 기본 ACL은 낮은 권한의 LDAP enumeration을 방지할 수 있습니다. `GoldenDMSA info`는 LDAP를 query하거나 후보 RID를 enumeration하고 `\PIPE\lsarpc`를 통해 `LsaLookupSids`로 SID를 resolve한 다음, dMSA를 computer account 및 gMSA와 구분할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Phase 3 - `msDS-ManagedPasswordId` 재구성 또는 추측

키 식별자에는 `L0Index`, `L1Index`, `L2Index`가 포함되며, 계정 생성 타임스탬프 뒤에 임의의 비트가 이어지는 형식이 아닙니다. Semperis는 password-generation 경로에서 후보 `L0Index`를 사용하지 않으며, `L1Index`와 `L2Index`는 각각 `0..31` 값으로 제한된다는 사실을 확인했습니다. 따라서 root-key GUID, domain, forest 및 SID를 알고 있는 attacker는 `32 * 32 = 1,024`개의 모든 후보 식별자를 구성할 수 있습니다.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
파생 계산은 offline으로 수행되지만, live candidate를 식별하려면 일반적으로 authentication 시도가 필요합니다. 이 과정에서 유효한 key를 찾기 전에 Kerberos pre-authentication 또는 NTLM validation 실패가 burst 형태로 발생할 수 있습니다. AES Kerberos keys의 경우, tool에서 사용하는 managed-account salt는 `UPPERCASE.DNS.DOMAIN` + `host` + 끝의 `$`를 제외한 소문자 account UPN입니다(예: `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - password 계산 및 사용

정확한 identifier를 알고 있다면 256-byte password buffer를 계산하고 이를 NTLM/AES material로 변환합니다. 이러한 tools에서 출력되는 base64 값은 encoded password buffer이며, LDAP `MSDS-MANAGEDPASSWORD_BLOB` 자체가 **아닙니다**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
NTLM 결과는 NTLM이 허용되는 곳에서 사용할 수 있으며, AES key는 managed account가 AES-only인 경우 overpass-the-hash / TGT requests에 사용할 수 있습니다. 이를 통해 공격자는 침해된 managed service account의 권한, SPNs, delegation configuration 및 resource access를 획득할 수 있으며, 공격자의 machine을 `PrincipalsAllowedToRetrieveManagedPassword`에 추가할 필요가 없습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 도메인 간 Configuration-partition 악용

KDS root-key objects는 forest Configuration naming context에 있으며, child domains의 DC로 복제됩니다. 따라서 child-domain DC의 `SYSTEM`은 child DC의 local replica에서 forest-root KDS material을 읽을 수 있습니다. 이는 child Domain Admins가 forest-root DC에서 직접 해당 object를 읽을 수 없는 경우에도 가능합니다. 공격자가 parent-domain gMSA의 `msDS-ManagedPasswordId`도 읽을 수 있다면, GoldenGMSA는 해당 parent account의 password를 계산할 수 있습니다. SID filtering은 이 cryptographic attack을 방지하지 못합니다.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## 탐지, 봉쇄 및 복구

* **Master Root Keys** 컨테이너에 SACL을 구성하고, `msKds-ProvRootKey` 객체에 상속되도록 하여 `msKds-RootKeyData`의 성공적인 읽기를 감사 대상으로 설정합니다. Directory Service Access auditing이 활성화된 경우 online extraction은 Security event **4662**를 생성하므로, 예상되지 않은 DC 또는 Tier-0 운영자가 주체인 이벤트를 조사합니다. 또한 이러한 SACL과 root-key 객체 ACL의 변경도 감사해야 합니다.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* child-to-parent attack은 침해된 child DC의 로컬 replica에서 KDS object를 읽으므로, forest-root domain에서는 해당 읽기를 관찰하지 못할 수 있습니다. parent domain에서는 `msDS-GroupManagedServiceAccount` 객체의 `msDS-ManagedPasswordId`(schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`)에 대한 성공적인 읽기를 감사하고, 다른 domain의 principal이 수행한 읽기를 조사합니다.<sup>[[5]](#references)</sup>
* KDS-object access를 managed account의 비정상적인 logon 및 `$` 접미사가 붙은 service account에서 발생하는 Kerberos/NTLM 실패 급증과 상관 분석합니다. 이전에 database/backup이 탈취된 후 수행되는 offline computation은 live DC에서 확인할 수 없습니다.<sup>[[1]](#references)[[3]](#references)</sup>
* 일반적인 password rotation만으로는 root-key exposure 이후 충분하지 않습니다. Microsoft의 현재 recovery procedure는 새 KDS root key를 생성하고, 관련된 모든 DC에서 KDS를 재시작한 다음, 영향을 받은 account를 해당 key로 이동합니다. exposure 범위 또는 시점을 알 수 없고 안전한 roll을 기다리는 것이 허용되지 않는 경우, 침해된 key를 사용한 모든 gMSA를 교체합니다. 범위가 알려진 경우 Microsoft는 안전한 rolling을 강제하는 authoritative-restore workflow를 문서화하고 있습니다. 이전 key를 삭제하기 전에 `msDS-ManagedPasswordId`에서 새 key GUID를 검증합니다.<sup>[[4]](#references)</sup>
* DC database 및 backup access, Configuration-partition replication, KDS root-key administration을 Tier-0으로 취급합니다. `ManagedPasswordIntervalInDays`를 줄이면 일부 recovery window를 제한할 수 있지만, 이미 침해된 root key를 revoke하지는 못합니다.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - dMSA/gMSA enumeration, identifier generation, 1,024-candidate validation, password computation 및 NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration 및 online, offline, cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) 및 [`Impacket`](https://github.com/fortra/impacket) - authorised testing에서 derived NTLM/AES key를 사용하거나 검증합니다.



## References

- [1] [위임된 Managed Service Account를 위한 인증 우회인 Golden dMSA](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Golden gMSA attack에서 복구하는 방법](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [domain 간 security boundary로서의 SID filter? Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
