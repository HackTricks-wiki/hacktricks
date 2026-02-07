# Autenticación Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consulta el excelente post en:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para atacantes
- Kerberos es el protocolo de auth predeterminado de AD; la mayoría de las cadenas de movimiento lateral lo tocarán. Para cheatsheets prácticos (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) ver:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Notas de ataques recientes (2024‑2026)
- **RC4 finalmente desaparece** – Los DCs de Windows Server 2025 ya no emiten TGTs RC4; Microsoft planea deshabilitar RC4 como predeterminado para DCs de AD a finales del Q2 de 2026. Los entornos que re‑habiliten RC4 para apps legacy crean oportunidades de downgrade/crack rápido para Kerberoasting.
- **Aplicación de validación PAC (abr 2025)** – Las actualizaciones de abril de 2025 eliminan el modo “Compatibility”; PACs forjados/golden tickets son rechazados en DCs parcheados cuando la aplicación está habilitada. Los DCs legacy/no parcheados siguen siendo abusables.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Si los DCs no están parcheados o se dejan en modo Audit, certificados encadenados a CAs no‑NTAuth pero mapeados vía SKI/altSecID aún pueden iniciar sesión. Aparecen eventos 45/21 cuando las protecciones se activan.
- **Eliminación progresiva de NTLM** – Microsoft enviará futuras versiones de Windows con NTLM deshabilitado por defecto (implementado durante 2026), empujando más autenticación hacia Kerberos. Espera más superficie de Kerberos y EPA/CBT más estrictos en redes endurecidas.
- **RBCD entre dominios sigue siendo potente** – Microsoft Learn indica que resource‑based constrained delegation funciona entre dominios/forests; un `msDS-AllowedToActOnBehalfOfOtherIdentity` escribible en objetos de recurso aún permite la suplantación S4U2self→S4U2proxy sin tocar los ACLs de servicios front‑end.

## Herramientas rápidas
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — outputs AES hashes; planifica el cracking por GPU o apunta en su lugar a usuarios con pre‑auth deshabilitado.
- **RC4 downgrade target hunting**: enumera cuentas que aún anuncian RC4 con `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` para localizar candidatos débiles para kerberoast antes de que RC4 se deshabilite por completo.



## Referencias
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
