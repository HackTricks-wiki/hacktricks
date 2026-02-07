# Autenticazione Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consulta l'ottimo post di:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR per gli attaccanti
- Kerberos è il protocollo di autenticazione predefinito di AD; la maggior parte delle catene di lateral movement lo coinvolgerà. Per cheatsheet pratiche (AS‑REP/Kerberoasting, ticket forging, delegation abuse, ecc.) vedi:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Note sugli attacchi recenti (2024‑2026)
- **RC4 finalmente eliminato** – I DC di Windows Server 2025 non emettono più TGT RC4; Microsoft prevede di disabilitare RC4 come impostazione predefinita per i DC AD entro la fine del Q2 2026. Gli ambienti che riabilitano RC4 per applicazioni legacy creano opportunità di downgrade/fast‑crack per Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Gli aggiornamenti di aprile 2025 rimuovono la modalità “Compatibility”; PAC falsificati/golden ticket vengono rifiutati sui DC patchati quando l'enforcement è abilitato. I DC legacy/non patchati restano sfruttabili.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Se i DC non sono patchati o rimangono in modalità Audit, certificati concatenati a CA non‑NTAuth ma mappati tramite SKI/altSecID possono ancora effettuare il logon. Appaiono eventi 45/21 quando le protezioni scattano.
- **NTLM phase‑out** – Microsoft rilascerà future versioni di Windows con NTLM disabilitato di default (gradualmente entro il 2026), spostando più autenticazione su Kerberos. Aspettati una maggiore superficie di Kerberos e controlli EPA/CBT più stringenti nelle reti fortificate.
- **Cross‑domain RBCD remains powerful** – Microsoft Learn osserva che resource‑based constrained delegation funziona attraverso domini/foreste; l'attributo scrivibile `msDS-AllowedToActOnBehalfOfOtherIdentity` sugli oggetti resource permette ancora l'impersonation S4U2self→S4U2proxy senza modificare gli ACL dei servizi front‑end.

## Strumenti rapidi
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — restituisce hash AES; pianifica cracking con GPU o prendi di mira utenti con pre‑auth disabilitato.
- **RC4 downgrade target hunting**: enumera gli account che ancora pubblicizzano RC4 con `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` per localizzare candidati deboli per Kerberoast prima che RC4 venga completamente disabilitato.



## Riferimenti
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
