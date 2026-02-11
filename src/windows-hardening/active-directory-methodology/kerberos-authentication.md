# Kerberos Autenticação

{{#include ../../banners/hacktricks-training.md}}

**Confira o post incrível de:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para atacantes
- Kerberos é o protocolo de autenticação padrão do AD; a maioria das cadeias de lateral-movement o envolverá. Para cheatsheets práticos (AS‑REP/Kerberoasting, ticket forging, delegation abuse, etc.) veja:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Notas de ataque recentes (2024‑2026)
- **RC4 finally going away** – Os DCs do Windows Server 2025 não emitem mais RC4 TGTs; a Microsoft planeja desabilitar RC4 como padrão para DCs do AD até o final do Q2 de 2026. Ambientes que re‑ativam RC4 para apps legados criam oportunidades de downgrade/fast‑crack para Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – As atualizações de abril de 2025 removem o modo “Compatibility”; PACs forjados/golden tickets são rejeitados em DCs com patch quando a aplicação é habilitada. DCs legados/não corrigidos continuam abusáveis.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Se os DCs não estiverem corrigidos ou permanecerem em modo Audit, certificados encadeados a CAs não‑NTAuth mas mapeados via SKI/altSecID ainda podem fazer logon. Eventos 45/21 aparecem quando as proteções são acionadas.
- **NTLM phase‑out** – A Microsoft entregará futuras versões do Windows com o NTLM desabilitado por padrão (implantado até 2026), empurrando mais autenticação para o Kerberos. Espere maior superfície do Kerberos e EPA/CBT mais rígidos em redes endurecidas.
- **Cross‑domain RBCD remains powerful** – O Microsoft Learn observa que resource‑based constrained delegation funciona entre domínios/florestas; o atributo gravável `msDS-AllowedToActOnBehalfOfOtherIdentity` em objetos resource ainda permite a impersonação S4U2self→S4U2proxy sem tocar os ACLs do serviço front‑end.

## Ferramentas rápidas
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — outputs AES hashes; planeje cracking por GPU ou mire em usuários com pre‑auth desabilitado.
- **RC4 downgrade target hunting**: enumere contas que ainda anunciam RC4 com `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` para localizar candidatos fracos para kerberoast antes que RC4 seja totalmente desabilitado.



## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
