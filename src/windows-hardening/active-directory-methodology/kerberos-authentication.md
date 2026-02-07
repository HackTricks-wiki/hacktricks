# Kerberos 인증

{{#include ../../banners/hacktricks-training.md}}

**좋은 게시물 확인:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 공격자용 요약
- Kerberos는 기본 AD auth protocol입니다; 대부분의 lateral-movement 체인이 이를 거칩니다. 실습용 치트시트(AS‑REP/Kerberoasting, ticket forging, delegation abuse 등)는 다음을 참조하세요:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## 최신 공격 노트 (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DCs는 더 이상 RC4 TGT를 발급하지 않습니다; Microsoft는 2026년 Q2 말까지 AD DC에 대해 RC4를 기본적으로 비활성화할 계획입니다. 레거시 앱을 위해 RC4를 다시 활성화한 환경은 Kerberoasting에 대한 다운그레이드/빠른 크랙 기회를 만듭니다.
- **PAC validation enforcement (Apr 2025)** – 2025년 4월 업데이트는 “Compatibility” 모드를 제거합니다; enforcement가 활성화된 패치된 DC에서는 위조된 PACs/golden tickets가 거부됩니다. 레거시/미패치 DC는 여전히 악용 가능합니다.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – DC가 미패치이거나 Audit 모드로 남아 있는 경우, non‑NTAuth CA에 체인된 인증서지만 SKI/altSecID로 매핑된 인증서는 여전히 로그온할 수 있습니다. 보호가 작동하면 이벤트 45/21이 생성됩니다.
- **NTLM phase‑out** – Microsoft는 향후 Windows 릴리스를 기본적으로 NTLM 비활성화 상태로 출시할 예정입니다(2026년까지 단계적 적용), 이로 인해 더 많은 인증이 Kerberos로 이동할 것입니다. 하드닝된 네트워크에서는 Kerberos 표면 영역 증가와 더 엄격한 EPA/CBT를 예상하세요.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn에 따르면 resource‑based constrained delegation은 도메인/포리스트 간에 작동합니다; 리소스 객체의 쓰기 가능한 `msDS-AllowedToActOnBehalfOfOtherIdentity`는 프런트엔드 서비스 ACL을 건드리지 않고도 S4U2self→S4U2proxy impersonation을 허용합니다.

## 빠른 도구
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AES 해시를 출력합니다; GPU 크래킹을 계획하거나 대신 pre‑auth disabled 사용자를 대상으로 하세요.
- **RC4 downgrade target hunting**: RC4를 여전히 광고하는 계정을 `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`로 열거하여 RC4가 완전히 비활성화되기 전에 약한 kerberoast 후보를 찾으세요.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
