# Kerberos Πιστοποίηση

{{#include ../../banners/hacktricks-training.md}}

**Δείτε το εξαιρετικό άρθρο από:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR για επιτιθέμενους
- Ο Kerberos είναι το προεπιλεγμένο πρωτόκολλο πιστοποίησης του AD· οι περισσότερες αλυσίδες lateral-movement θα το αγγίξουν. Για πρακτικά cheatsheets (AS‑REP/Kerberoasting, ticket forging, delegation abuse, κ.λπ.) δείτε:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}

## Νεότερες σημειώσεις επιθέσεων (2024‑2026)
- **RC4 τελικά αποσύρεται** – Οι DCs των Windows Server 2025 δεν εκδίδουν πλέον RC4 TGTs· η Microsoft σχεδιάζει να απενεργοποιήσει το RC4 ως προεπιλογή για τους AD DCs έως το τέλος του Q2 2026. Περιβάλλοντα που επανενεργοποιούν το RC4 για legacy apps δημιουργούν ευκαιρίες downgrade/fast‑crack για Kerberoasting.
- **PAC validation enforcement (Apr 2025)** – Οι ενημερώσεις Απριλίου 2025 αφαιρούν τη λειτουργία “Compatibility”· forged PACs/golden tickets απορρίπτονται σε patched DCs όταν η επιβολή είναι ενεργοποιημένη. Legacy/unpatched DCs παραμένουν abusable.
- **CVE‑2025‑26647 (altSecID CBA mapping)** – Εάν οι DCs είναι unpatched ή παραμείνουν σε Audit mode, πιστοποιητικά αλυσιδωμένα σε non‑NTAuth CAs αλλά χαρτογραφημένα μέσω SKI/altSecID μπορούν ακόμη να κάνουν log on. Εμφανίζονται Events 45/21 όταν ενεργοποιούνται οι προστασίες.
- **NTLM phase‑out** – Η Microsoft θα κυκλοφορήσει μελλοντικές εκδόσεις των Windows με NTLM απενεργοποιημένο από προεπιλογή (σταδιακά έως το 2026), ωθώντας περισσότερη πιστοποίηση προς το Kerberos. Αναμένετε μεγαλύτερη επιφάνεια Kerberos και πιο αυστηρό EPA/CBT σε σκληρυμένα δίκτυα.
- **Cross‑domain RBCD παραμένει ισχυρό** – Το Microsoft Learn σημειώνει ότι το resource‑based constrained delegation λειτουργεί across domains/forests· writable `msDS-AllowedToActOnBehalfOfOtherIdentity` σε resource objects εξακολουθεί να επιτρέπει S4U2self→S4U2proxy impersonation χωρίς να αγγίζονται front‑end service ACLs.

## Γρήγορα εργαλεία
- **Rubeus kerberoast (AES default)**: `Rubeus.exe kerberoast /user:svc_sql /aes /nowrap /outfile:tgs.txt` — εξάγει AES hashes· προγραμματίστε GPU cracking ή στοχεύστε χρήστες με pre‑auth απενεργοποιημένο αντ' αυτού.
- **RC4 downgrade target hunting**: απαριθμήστε accounts που ακόμη διαφημίζουν RC4 με `Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes=4)' -Properties msDS-SupportedEncryptionTypes` για να εντοπίσετε αδύναμους kerberoast υποψήφιους πριν το RC4 απενεργοποιηθεί πλήρως.

## References
- [Microsoft – Beyond RC4 for Windows authentication (RC4 default removal timeline)](https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication)
- [Microsoft Support – Protections for CVE-2025-26647 Kerberos authentication](https://support.microsoft.com/en-gb/topic/protections-for-cve-2025-26647-kerberos-authentication-5f5d753b-4023-4dd3-b7b7-c8b104933d53)
- [Microsoft Support – PAC validation enforcement timeline](https://support.microsoft.com/en-us/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [Microsoft Learn – Kerberos constrained delegation overview (cross-domain RBCD)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Windows Central – NTLM deprecation roadmap](https://www.windowscentral.com/microsoft/windows/microsoft-plans-to-bury-its-ntlm-security-relic-after-30-years)
{{#include ../../banners/hacktricks-training.md}}
