# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Δείτε το εξαιρετικό άρθρο από:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos είναι το προεπιλεγμένο πρωτόκολλο αυθεντικοποίησης AD· οι περισσότερες αλυσίδες lateral‑movement θα το αγγίξουν. Για πρακτικά cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, κ.λπ.) δείτε:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Fresh attack notes (2024‑2026)
- **RC4 finally going away** – Τα DCs των Windows Server 2025 δεν εκδίδουν πλέον RC4 TGTs· η Microsoft σκοπεύει να απενεργοποιήσει το RC4 ως προεπιλογή για AD DCs μέχρι το τέλος του Q2 2026. Περιβάλλοντα που επαναενεργοποιούν RC4 για legacy apps δημιουργούν ευκαιρίες downgrade/fast‑crack για Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Οι ενημερώσεις Απριλίου 2025 αφαιρούν το “Compatibility” mode· πλαστά PACs/golden tickets απορρίπτονται σε patched DCs όταν η επιβολή είναι ενεργή. Legacy/μη ενημερωμένα DCs παραμένουν ευάλωτα σε εκμετάλλευση.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Εάν τα DCs δεν έχουν ενημερωθεί ή έχουν μείνει σε Audit mode, πιστοποιητικά που chained σε non‑NTAuth CAs αλλά mapped μέσω SKI/altSecID μπορούν ακόμα να κάνουν log on. Εμφανίζονται events 45/21 όταν ενεργοποιούνται οι προστασίες.
- **NTLM phase‑out** – Η Microsoft θα παραδώσει μελλοντικές εκδόσεις Windows με NTLM απενεργοποιημένο ως προεπιλογή (σταδιακά μέχρι το 2026), ωθώντας περισσότερη αυθεντικοποίηση στο Kerberos. Αναμένεται μεγαλύτερη επιφάνεια Kerberos και αυστηρότερη EPA/CBT σε hardened networks.
- **Cross‑domain RBCD remains powerful** – Το Microsoft Learn αναφέρει ότι το resource‑based constrained delegation λειτουργεί across domains/forests· το writable `msDS-AllowedToActOnBehalfOfOtherIdentity` στα resource objects εξακολουθεί να επιτρέπει S4U2self→S4U2proxy impersonation χωρίς να αγγίζει τα front‑end service ACLs.

## Quick tooling
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — outputs AES hashes· προγραμματίστε GPU cracking ή στοχεύστε χρήστες με pre‑auth disabled αντίστοιχα.
- **RC4 downgrade target hunting**: enumerate accounts that still advertise RC4 with `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` to locate weak kerberoast candidates before RC4 is fully disabled.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
