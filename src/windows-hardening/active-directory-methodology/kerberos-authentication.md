# Kerberos 認証

{{#include ../../banners/hacktricks-training.md}}

**この素晴らしい投稿を確認：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## 攻撃者向け TL;DR
- KerberosはADのデフォルト認証プロトコルで、ほとんどの横移動チェーンがこれに関わります。ハンズオン用チートシート（AS‑REP/Kerberoasting、ticket forging、delegation abuse など）は次を参照してください：
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## 最新の攻撃ノート（2024‑2026）
- **RC4 finally going away** – Windows Server 2025 の DC はもはや RC4 TGT を発行しません。Microsoft は Q2 2026 末までに AD DC のデフォルトで RC4 を無効化する予定です。レガシーアプリのために RC4 を再有効化している環境は、Kerberoasting に対するダウングレード／高速クラッキングの機会を生みます。
- **PAC validation enforcement (Apr 2025)** – 2025 年 4 月の更新で “Compatibility” モードが削除されます。強制が有効なパッチ済み DC では、偽造 PAC／golden tickets が拒否されます。レガシー／未パッチの DC は引き続き悪用可能です。
- **CVE‑2025‑26647 (altSecID CBA mapping)** – DC が未パッチまたは Audit モードのままの場合、非‑NTAuth CA にチェーンされた証明書でも SKI/altSecID 経由でマッピングされていればログオンできることがあります。保護が発動すると Events 45/21 が記録されます。
- **NTLM phase‑out** – Microsoft は今後の Windows リリースを NTLM をデフォルトで無効化した状態で出荷する予定（2026 年まで段階的実施）で、より多くの認証が Kerberos に移行します。ハードニングされたネットワークでは Kerberos の攻撃面が増え、EPA/CBT がより厳格化されることが予想されます。
- **Cross‑domain RBCD remains powerful** – Microsoft Learn によれば resource‑based constrained delegation はドメイン／フォレスト間でも機能します。リソースオブジェクト上の書き込み可能な `msDS-AllowedToActOnBehalfOfOtherIdentity` は、フロントエンドのサービス ACL に触れずに S4U2self→S4U2proxy のなりすましを可能にします。

## クイックツール
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AES ハッシュを出力します。GPU クラッキングを予定するか、代わりに pre‑auth disabled users をターゲットにしてください。
- **RC4 downgrade target hunting**: enumerate accounts that still advertise RC4 with `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` to locate weak kerberoast candidates before RC4 is fully disabled.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
