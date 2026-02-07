# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Harika yazıyı inceleyin:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Saldırganlar için TL;DR
- Kerberos, varsayılan AD auth protokolüdür; çoğu lateral-movement zinciri buna değecektir. Pratik cheatsheet'ler (AS‑REP/Kerberoasting, ticket forging, delegation abuse, vb.) için:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Güncel saldırı notları (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DC'leri artık RC4 TGT çıkarmıyor; Microsoft, Q2 2026 sonuna kadar AD DC'ler için RC4'ü varsayılan olarak devre dışı bırakmayı planlıyor. RC4'ü eski uygulamalar için yeniden etkinleştiren ortamlar, Kerberoasting için downgrade/fast‑crack fırsatları yaratır.
- **PAC validation enforcement (Apr 2025)** – Nisan 2025 güncellemeleri “Compatibility” modunu kaldırıyor; enforcement etkinleştirildiğinde yaması yapılmış DC'lerde sahte PAC'ler/golden ticket'lar reddedilir. Eski/yaması uygulanmamış DC'ler istismar edilebilir durumda kalır.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Eğer DC'ler yamalanmamış veya Audit modunda bırakılmışsa, non‑NTAuth CA'larına zincirlenmiş ancak SKI/altSecID ile eşlenmiş sertifikalar yine de oturum açabilir. Korumalar tetiklendiğinde Events 45/21 görünür.
- **NTLM phase‑out** – Microsoft, gelecek Windows sürümlerini NTLM varsayılan olarak devre dışı olacak şekilde (2026'ya kadar kademeli) dağıtacak; bu da daha fazla auth'ı Kerberos'a kaydıracak. Sertleştirilmiş ağlarda daha fazla Kerberos yüzeyi ve daha sıkı EPA/CBT bekleyin.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn, resource‑based constrained delegation'ın domainler/forest'lar arası çalıştığını belirtiyor; resource nesnelerindeki yazılabilir `msDS-AllowedToActOnBehalfOfOtherIdentity` hâlâ front‑end service ACL'larına dokunmadan S4U2self→S4U2proxy taklitine izin verir.

## Hızlı araçlar
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — AES hashleri üretir; GPU cracking planlayın veya bunun yerine pre‑auth disabled kullanıcıları hedefleyin.
- **RC4 downgrade target hunting**: RC4'ü hâlâ ilan eden hesapları `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` ile listeleyin; RC4 tamamen devre dışı kalmadan önce zayıf kerberoast adaylarını bulun.

## Referanslar
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
