# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте чудовий допис:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Коротко для зловмисників
- Kerberos is the default AD auth protocol; most lateral-movement chains will touch it. For hands‑on cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) see:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Оновлені нотатки щодо атак (2024‑2026)
- **RC4 finally going away** – Windows Server 2025 DCs більше не видають RC4 TGTs; Microsoft планує відключити RC4 за замовчуванням для AD DCs до кінця Q2 2026. Середовища, які знову вмикають RC4 для legacy apps, створюють можливості для downgrade/fast‑crack при Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – оновлення квітня 2025 прибирають режим “Compatibility”; підроблені PACs/golden tickets відхиляються на патчених DCs, коли увімкнено enforcement. Legacy/unpatched DCs залишаються вразливими.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – якщо DCs не патчені або залишені в Audit mode, сертифікати, що ланцюжаться до non‑NTAuth CAs але відображені через SKI/altSecID, все ще можуть логінитись. Поява Events 45/21 відбувається при спрацьовуванні захистів.
- **NTLM phase‑out** – Microsoft випустить майбутні релізи Windows з NTLM вимкненим за замовчуванням (поступово до 2026), переміщуючи більше автентифікації на Kerberos. Очікуйте збільшення Kerberos surface area та суворішого EPA/CBT у захищених мережах.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn зазначає, що resource‑based constrained delegation працює між доменами/forests; writable `msDS-AllowedToActOnBehalfOfOtherIdentity` на об'єктах ресурсів все ще дозволяє S4U2self→S4U2proxy імперсонізацію без торкання front‑end service ACLs.

## Швидкі інструменти
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — виводить AES хеші; плануйте GPU cracking або орієнтуйтесь на користувачів з вимкненою pre‑auth.
- **RC4 downgrade target hunting**: перелічуйте облікові записи, які все ще вказують RC4 за допомогою `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` щоб знайти слабкі кандидати для kerberoast до повного вимкнення RC4.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
