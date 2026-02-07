# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**すばらしい記事を確認してください：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- KerberosはデフォルトのAD認証プロトコルで、ほとんどのlateral-movementチェーンが関与します。ハンズオンのチートシート（AS‑REP/Kerberoasting、ticket forging、delegation abuse など）は以下を参照してください：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Fresh attack notes (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DCsはもはやRC4 TGTを発行しません。MicrosoftはQ2 2026末までにAD DCのデフォルトでRC4を無効化する予定です。レガシーアプリのためにRC4を再有効化している環境は、Kerberoastingに対するダウングレード／高速クラッキングの機会を生みます。
- **PAC validation enforcement (Apr 2025)** – 2025年4月の更新で“Compatibility”モードが削除されます。強製されたPACやgolden ticketsは、保護が有効なパッチ済みDCで拒否されます。古い／未パッチのDCは引き続き悪用可能です。
- **CVE‑2025‑26647 (altSecID CBA mapping)** – DCが未パッチまたはAuditモードにある場合、非‑NTAuth CAにチェーンされた証明書でもSKI/altSecID経由でマッピングされていればログオン可能なままです。保護がトリガーされるとEvents 45/21が記録されます。
- **NTLM phase‑out** – Microsoftは今後のWindowsリリースをNTLM無効で出荷する予定（2026年にかけて段階的に）で、より多くの認証がKerberosへ移行します。ハードニングされたネットワークではKerberosの攻撃面が増え、EPA/CBTがより厳格になることが予想されます。
- **Cross‑domain RBCD remains powerful** – Microsoft Learnは、resource‑based constrained delegationがドメイン／フォレスト間で動作することを示しています。resourceオブジェクトの書き込み可能な`msDS-AllowedToActOnBehalfOfOtherIdentity`は、フロントエンドサービスのACLに触れずにS4U2self→S4U2proxyのなりすましを可能にします。

## Quick tooling
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AESハッシュを出力します；GPUによるクラッキングを計画するか、代わりにpre‑auth無効のユーザーを狙ってください。
- **RC4 downgrade target hunting**: RC4をまだアドバタイズしているアカウントを列挙するには `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` を使用し、RC4が完全に無効化される前の弱いkerberoast候補を特定します。

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
