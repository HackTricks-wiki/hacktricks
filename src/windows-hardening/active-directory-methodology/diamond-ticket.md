# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**golden ticket과 마찬가지로**, diamond ticket은 **어떤 사용자로든 어떤 서비스에 액세스하는 데** 사용할 수 있는 TGT입니다. golden ticket은 완전히 오프라인에서 위조되며, 해당 도메인의 krbtgt hash로 암호화된 다음 사용을 위해 logon session에 전달됩니다. domain controller는 자신이 정상적으로 발급한 TGT를 추적하지 않기 때문에, 자체 krbtgt hash로 암호화된 TGT를 기꺼이 수락합니다.<sup>[[1]](#references)</sup>

golden ticket의 사용을 탐지하는 일반적인 기법은 두 가지입니다.

- 대응하는 AS-REQ가 없는 TGS-REQ를 찾습니다.
- Mimikatz의 기본 10년 lifetime처럼 비정상적인 값을 가진 TGT를 찾습니다.

**diamond ticket은 DC가 발급한 정상적인 TGT의 필드를 수정하여** 생성됩니다. 이는 **TGT를 요청하고**, 도메인의 krbtgt hash로 **복호화한 다음**, ticket에서 원하는 필드를 **수정하고**, 이후 **다시 암호화**하여 수행합니다. 이 방식은 다음과 같은 **golden ticket의 앞서 언급한 두 가지 단점을 해결합니다**.<sup>[[1]](#references)</sup>

- TGS-REQ에는 선행하는 AS-REQ가 존재합니다.
- TGT는 DC가 발급했으므로 도메인의 Kerberos policy에 따른 모든 올바른 세부 정보를 포함합니다. 이러한 정보를 golden ticket에서도 정확하게 위조할 수 있지만, 더 복잡하고 실수가 발생하기 쉽습니다.

### 요구 사항 및 workflow

- **Cryptographic material**: TGT를 복호화하고 다시 서명하기 위한 krbtgt AES256 key(권장) 또는 NTLM hash입니다.
- **정상적인 TGT blob**: `/tgtdeleg`, `asktgt`, `s4u`를 사용하거나 memory에서 ticket을 export하여 얻습니다.
- **Context data**: 대상 사용자의 RID, group RID/SID, 그리고 (선택적으로) LDAP에서 가져온 PAC attribute입니다.
- **Service key**: service ticket을 다시 생성할 계획인 경우에만 필요하며, impersonate할 service SPN의 AES key입니다.

1. AS-REQ를 통해 제어 중인 임의의 사용자에 대한 TGT를 획득합니다(Rubeus `/tgtdeleg`는 credential 없이 client가 Kerberos GSS-API dance를 수행하도록 강제하므로 편리합니다).
2. krbtgt key로 반환된 TGT를 복호화하고 PAC attribute(user, group, logon info, SID, device claim 등)를 patch합니다.
3. 동일한 krbtgt key로 ticket을 다시 암호화하고 서명한 다음, 현재 logon session에 inject합니다(`kerberos::ptt`, `Rubeus.exe ptt`...).
4. 선택적으로 유효한 TGT blob과 대상 service key를 제공하여 service ticket에도 이 과정을 반복하면 wire 상에서 더욱 stealthy하게 유지할 수 있습니다.

### Updated Rubeus tradecraft (2024+)

Huntress의 최근 작업은 이전에는 golden/silver ticket에만 존재했던 `/ldap` 및 `/opsec` 개선 사항을 이식하여 Rubeus 내부의 `diamond` action을 modernize했습니다. 이제 `/ldap`는 LDAP를 query하고 **SYSVOL을 mount**하여 실제 PAC context를 가져오며, account/group attribute와 Kerberos/password policy(예: `GptTmpl.inf`)를 extract합니다. 또한 `/opsec`는 2단계 preauth exchange를 수행하고 AES-only 및 현실적인 KDCOptions를 적용하여 AS-REQ/AS-REP flow가 Windows와 일치하도록 합니다. 이를 통해 PAC field 누락이나 policy와 일치하지 않는 lifetime 같은 명백한 indicator가 크게 줄어듭니다.<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (선택 사항인 `/ldapuser` 및 `/ldappassword`와 함께 사용)는 AD와 SYSVOL을 조회하여 대상 사용자의 PAC policy 데이터를 미러링합니다.
- `/opsec`은 Windows와 유사한 AS-REQ 재시도를 강제하고, 노이즈가 많은 플래그를 0으로 설정하며 AES256만 사용합니다.
- `/tgtdeleg`은 복호화 가능한 TGT를 반환하면서도 victim의 cleartext password 또는 NTLM/AES key에는 접근하지 않습니다.

### Service-ticket recutting

동일한 Rubeus 업데이트에는 diamond technique을 TGS blobs에 적용하는 기능도 추가되었습니다. `diamond`에 **base64-encoded TGT** (`asktgt`, `/tgtdeleg` 또는 이전에 forged된 TGT에서 가져옴), **service SPN**, **service AES key**를 전달하면 KDC에 접근하지 않고 realistic service tickets를 생성할 수 있습니다. 사실상 더 stealthy한 silver ticket입니다.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
이 workflow는 이미 service account key를 제어하고 있고(예: `lsadump::lsa /inject` 또는 `secretsdump.py`로 dump한 경우), 새로운 AS/TGS traffic을 발생시키지 않으면서 AD policy, timelines, PAC data와 정확히 일치하는 일회성 TGS를 생성하려는 경우에 적합합니다.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

때때로 **sapphire ticket**이라고 불리는 새로운 변형은 Diamond의 "real TGT" base를 **S4U2self+U2U**와 결합해 privileged PAC를 탈취한 뒤 자신의 TGT에 삽입합니다. 추가 SID를 임의로 생성하는 대신, `sname`이 low-priv requester를 대상으로 하도록 high-privilege user에 대한 U2U S4U2self ticket을 요청합니다. 이때 KRB_TGS_REQ는 requester's TGT를 `additional-tickets`에 포함하고 `ENC-TKT-IN-SKEY`를 설정하므로, service ticket을 해당 user의 key로 decrypt할 수 있습니다. 그런 다음 privileged PAC를 추출하고, krbtgt key로 다시 서명하기 전에 이를 legitimate TGT에 삽입합니다.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket의 `ticketer.py`는 이제 `-impersonate` + `-request`를 통한 sapphire 지원을 제공합니다(live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate`는 username 또는 SID를 허용하며, `-request`에는 티켓을 decrypt/patch하기 위한 live user creds와 krbtgt key material (AES/NTLM)이 필요합니다.

이 variant를 사용할 때의 주요 OPSEC 징후:<sup>[[5]](#references)</sup>

- TGS-REQ에는 `ENC-TKT-IN-SKEY`와 `additional-tickets`(victim TGT)가 포함되며, 이는 일반적인 traffic에서는 드뭅니다.
- `sname`은 requesting user와 동일한 경우가 많으며(self-service access), Event ID 4769에는 caller와 target이 동일한 SPN/user로 표시됩니다.
- 동일한 client computer를 사용하지만 서로 다른 CNAME(낮은 권한의 requester와 privileged PAC owner)을 가진 4768/4769 entries 쌍이 나타날 것으로 예상됩니다.

### OPSEC 및 detection 참고 사항

- 기존 hunter heuristics(TGS without AS, 수십 년의 lifetime)는 여전히 golden tickets에 적용되지만, diamond tickets는 주로 **PAC content 또는 group mapping이 성립하지 않아 보일 때** 드러납니다. 모든 PAC field(logon hours, user profile paths, device IDs)를 채워 automated comparison에서 위조가 즉시 flag되지 않도록 하세요.<sup>[[3]](#references)</sup>
- **group/RID를 과도하게 추가하지 마세요**. `512`(Domain Admins)와 `519`(Enterprise Admins)만 필요하다면 거기서 멈추고, target account가 AD의 다른 위치에서도 해당 group에 속하는 것이 타당해 보이는지 확인하세요. 과도한 `ExtraSids`는 명백한 단서입니다.
- Sapphire-style swap은 U2U fingerprint를 남깁니다. 즉, `ENC-TKT-IN-SKEY` + `additional-tickets`, 4769에서 user(대개 requester)를 가리키는 `sname`, 그리고 forged ticket에서 비롯된 후속 4624 logon입니다. no-AS-REQ gap만 찾지 말고 이러한 field를 correlate하세요.<sup>[[5]](#references)</sup>
- Microsoft는 CVE-2026-20833 때문에 **RC4 service ticket issuance**를 단계적으로 폐지하기 시작했습니다. KDC에서 AES-only etype을 강제하면 domain을 harden하는 동시에 diamond/sapphire tooling과도 일치합니다(`/opsec`은 이미 AES를 강제합니다). forged PAC에 RC4를 섞으면 점점 더 눈에 띄게 됩니다.<sup>[[6]](#references)</sup>
- Splunk의 Security Content project는 diamond tickets에 대한 attack-range telemetry와 *Windows Domain Admin Impersonation Indicator* 같은 detection을 배포합니다. 이는 비정상적인 Event ID 4768/4769/4624 sequence와 PAC group change를 correlate합니다. 해당 dataset을 replay하거나(또는 위의 command로 직접 생성하여) T1558.001에 대한 SOC coverage를 검증하면, 구체적인 alert logic을 확보해 이를 evade하는 데 도움이 됩니다.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
