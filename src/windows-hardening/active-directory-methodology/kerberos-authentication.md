# Kerberos 인증

{{#include ../../banners/hacktricks-training.md}}

**다음 게시물을 확인하세요:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 공격자용 TL;DR
- Kerberos는 기본 AD 인증 프로토콜이며, 대부분의 lateral-movement 체인에서 사용됩니다. 실전용 치트시트(AS‑REP/Kerberoasting, ticket forging, delegation abuse 등)는 다음을 참조:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## 최신 공격 노트 (2024‑2026)
- **RC4가 마침내 사라짐** – Windows Server 2025 DC는 더 이상 RC4 TGT를 발급하지 않습니다; Microsoft는 Q2 2026 말까지 AD DC의 기본값으로 RC4를 비활성화할 계획입니다. 레거시 앱을 위해 RC4를 다시 활성화하는 환경은 Kerberoasting에 대한 다운그레이드/빠른 크랙 기회를 제공합니다.
- **PAC 검증 강제화 (Apr 2025)** – 2025년 4월 업데이트는 “Compatibility” 모드를 제거합니다; 강제가 활성화된 패치된 DC에서는 위조 PACs/golden tickets가 거부됩니다. 레거시/미패치 DC는 여전히 악용 가능합니다.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – DC가 미패치이거나 Audit 모드로 남겨진 경우, non‑NTAuth CA에 체인된 인증서가 SKI/altSecID로 매핑되면 여전히 로그온할 수 있습니다. 보호 기능이 작동하면 이벤트 45/21이 발생합니다.
- **NTLM 단계적 폐기** – Microsoft는 향후 Windows 릴리스에서 NTLM을 기본적으로 비활성화하여(2026년까지 단계적으로) 더 많은 인증을 Kerberos로 이동시킬 예정입니다. 하드닝된 네트워크에서는 Kerberos 노출면이 늘어나고 EPA/CBT가 더 엄격해질 것으로 예상됩니다.
- **크로스 도메인 RBCD는 여전히 강력** – Microsoft Learn은 resource‑based constrained delegation이 도메인/포리스트 간에 작동한다고 명시합니다; 리소스 객체의 쓰기 가능한 `msDS-AllowedToActOnBehalfOfOtherIdentity`는 프런트엔드 서비스 ACL을 건드리지 않고도 S4U2self→S4U2proxy 가장화를 허용합니다.

## 빠른 툴
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AES 해시를 출력합니다; GPU 크래킹을 계획하거나 대신 pre‑auth가 비활성화된 사용자를 대상으로 하세요.
- **RC4 다운그레이드 대상 탐색**: 아직 RC4를 광고하는 계정을 `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`로 열거하여 RC4가 완전히 비활성화되기 전 약한 kerberoast 후보를 찾으세요.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
