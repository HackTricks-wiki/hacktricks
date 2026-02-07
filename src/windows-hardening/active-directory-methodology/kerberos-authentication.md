# Uwierzytelnianie Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź świetny post:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR dla atakujących
- Kerberos jest domyślnym protokołem uwierzytelniania w AD; większość lateral-movement chains będzie go używać. Dla praktycznych cheatsheetów (AS‑REP/Kerberoasting, ticket forging, delegation abuse, itp.) zobacz:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Aktualne notatki o atakach (2024‑2026)
- **RC4 wreszcie znika** – Windows Server 2025 DCs przestają wydawać RC4 TGTs; Microsoft planuje wyłączyć RC4 jako domyślne dla AD DCs do końca Q2 2026. Środowiska, które ponownie włączą RC4 dla aplikacji legacy, tworzą możliwości downgrade/fast‑crack dla Kerberoasting.
- **PAC validation enforcement (kwi 2025)** – Aktualizacje z kwietnia 2025 usuwają tryb “Compatibility”; sfałszowane PACs/golden tickets są odrzucane na załatanych DCs, gdy wymuszanie jest włączone. Legacy/unpatched DCs pozostają podatne na wykorzystanie.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Jeśli DCs są niezałatane lub pozostawione w trybie Audit, certyfikaty połączone z non‑NTAuth CA, ale zmapowane przez SKI/altSecID, nadal mogą się logować. Eventy 45/21 pojawiają się, gdy ochrony się uruchamiają.
- **NTLM phase‑out** – Microsoft dostarczy przyszłe wydania Windows z NTLM domyślnie wyłączonym (etapowo w 2026), przesuwając więcej uwierzytelniania do Kerberos. Spodziewaj się większej powierzchni Kerberos i surowszego EPA/CBT w zahartowanych sieciach.
- **Cross‑domain RBCD pozostaje potężne** – Microsoft Learn zauważa, że resource‑based constrained delegation działa między domenami/forests; zapisywalny `msDS-AllowedToActOnBehalfOfOtherIdentity` na resource objects nadal pozwala na impersonację S4U2self→S4U2proxy bez modyfikowania ACLs usług front‑end.

## Szybkie narzędzia
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — wypisuje hashe AES; zaplanuj łamanie na GPU lub zamiast tego celem wybierz użytkowników z wyłączonym pre‑auth.
- **RC4 downgrade target hunting**: enumerate accounts that still advertise RC4 with `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` to locate weak kerberoast candidates before RC4 is fully disabled.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
