# Kerberos аутентифікація

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте чудову статтю:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Коротко для атакувальників
- Kerberos — протокол аутентифікації за замовчуванням в AD; більшість lateral-movement ланцюжків так чи інакше зачеплять його. Для практичних cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse тощо) див.:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Оновлені нотатки про атаки (2024‑2026)
- **RC4 нарешті зникає** – DCs на Windows Server 2025 більше не видають RC4 TGTs; Microsoft планує відключити RC4 за замовчуванням для AD DCs до кінця Q2 2026. Середовища, які повторно вмикають RC4 для legacy додатків, створюють можливості для downgrade/fast‑crack у Kerberoasting.
- **Запровадження перевірки PAC (Apr 2025)** – оновлення квітня 2025 прибирають режим “Compatibility”; підроблені PACs/golden tickets відхиляються на запатчених DCs, коли увімкнено примусове застосування. Legacy/unpatched DCs залишаються придатними для зловживань.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – якщо DCs не запатчено або залишено в Audit режимі, сертифікати, пов’язані з non‑NTAuth CAs, але змеплені через SKI/altSecID, все ще можуть виконувати log on. Події 45/21 з’являються, коли захисти спрацьовують.
- **Виведення NTLM з обігу** – Microsoft випускатиме майбутні версії Windows з NTLM відключеним за замовчуванням (поетапно в 2026), що перемістить більше аутентифікації на Kerberos. Очікуйте ширшої поверхні Kerberos та суворішого EPA/CBT у захищених мережах.
- **Cross‑domain RBCD залишається потужним** – Microsoft Learn зазначає, що resource‑based constrained delegation працює через домени/forests; записний msDS-AllowedToActOnBehalfOfOtherIdentity, що є writable на ресурсних об’єктах, все ще дозволяє S4U2self→S4U2proxy імперсонування без змін у front‑end service ACLs.

## Швидкі інструменти
- **Rubeus kerberoast (AES default):** `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — виводить AES хеші; плануйте GPU cracking або націлюйтесь на користувачів з вимкненим pre‑auth.
- **RC4 downgrade target hunting:** перераховуйте облікові записи, які все ще рекламують RC4 за допомогою `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes`, щоб знайти слабкі кандидати для kerberoast перед повним вимкненням RC4.



## Посилання
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
