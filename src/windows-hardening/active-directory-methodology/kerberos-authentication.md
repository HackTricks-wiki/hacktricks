# Kerberos 认证

{{#include ../../banners/hacktricks-training.md}}

**查看精彩文章：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR（针对攻击者）
- Kerberos 是默认的 AD auth 协议；大多数横向移动链路都会触及它。有关实操速查表（AS‑REP/Kerberoasting、ticket forging、delegation abuse 等），请参见：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## 最新攻击笔记（2024‑2026）
- **RC4 finally going away** – Windows Server 2025 DCs no longer issue RC4 TGTs; Microsoft plans to disable RC4 as default for AD DCs by end of Q2 2026. 启用 RC4 以支持遗留应用的环境会在 Kerberoasting 上制造降级/快速破解的机会。
- **PAC validation enforcement (Apr 2025)** – 2025 年 4 月更新移除了“Compatibility”模式；在启用强制验证的已修补 DC 上，伪造的 PACs/golden tickets 将被拒绝。未打补丁或旧有 DC 仍可被滥用。
- **CVE‑2025‑26647 (altSecID CBA mapping)** – 如果 DC 未打补丁或处于 Audit 模式，链到非‑NTAuth CA 的证书但通过 SKI/altSecID 映射仍可登录。触发保护时会出现 Events 45/21。
- **NTLM phase‑out** – Microsoft 将在未来的 Windows 发行版中默认禁用 NTLM（分阶段到 2026 年），将更多认证推向 Kerberos。预计在强化网络中会看到更多 Kerberos 的攻击面和更严格的 EPA/CBT。
- **Cross‑domain RBCD remains powerful** – Microsoft Learn 指出 resource‑based constrained delegation 可跨域/林工作；对资源对象可写的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 仍允许在不接触前端服务 ACL 的情况下进行 S4U2self→S4U2proxy 模拟。

## 快速工具
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — 输出 AES 哈希；考虑使用 GPU 破解，或改为针对 pre‑auth disabled users。
- **RC4 downgrade target hunting**: 枚举仍声明 RC4 的账户：`Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`，在 RC4 完全禁用之前定位弱的 kerberoast 候选对象。



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
