# Kerberos 认证

{{#include ../../banners/hacktricks-training.md}}

**查看这篇精彩文章：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 攻击者速览
- Kerberos 是默认的 AD 认证协议；大多数横向移动链路会涉及它。有关实操备忘（AS‑REP/Kerberoasting、ticket forging、delegation abuse 等），参见：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## 最新攻击要点（2024‑2026）
- **RC4 finally going away** – Windows Server 2025 的 DC 不再签发 RC4 TGTs；Microsoft 计划在 2026 年第二季度结束前将 RC4 作为 AD DC 的默认支持移除。为兼容遗留应用而重新启用 RC4 的环境会为 Kerberoasting 提供降级/快速破解的机会。
- **PAC validation enforcement (Apr 2025)** – 2025 年 4 月的更新移除了“Compatibility”模式；当开启强制时，伪造的 PACs/golden tickets 在已打补丁的 DC 上会被拒绝。遗留/未打补丁的 DC 仍可被利用。
- **CVE‑2025‑26647 (altSecID CBA mapping)** – 如果 DC 未打补丁或保持在 Audit 模式，通过 SKI/altSecID 映射到非‑NTAuth CA 的证书仍然可以登录。触发防护时会生成事件 45/21。
- **NTLM phase‑out** – Microsoft 将在未来的 Windows 发布中默认禁用 NTLM（分阶段至 2026 年），将更多认证推向 Kerberos。在加固网络中，请预期 Kerberos 的攻击面扩大以及更严格的 EPA/CBT。
- **Cross‑domain RBCD remains powerful** – Microsoft Learn 指出 resource‑based constrained delegation 可以跨域/林工作；资源对象上可写的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 仍允许在不修改前端服务 ACL 的情况下进行 S4U2self→S4U2proxy 模拟。

## 快速工具
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — 输出 AES 哈希；可计划使用 GPU 破解或改为针对 pre‑auth 被禁用的用户。
- **RC4 downgrade target hunting**: 使用 `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` 列举仍然声明支持 RC4 的账号，以在 RC4 完全禁用前定位脆弱的 kerberoast 候选者。



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
