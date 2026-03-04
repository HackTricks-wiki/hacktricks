# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

LDAP relay/MITM επιτρέπει σε επιτιθέμενους να προωθούν binds σε Domain Controllers για να αποκτήσουν authenticated contexts. Δύο server-side controls περιορίζουν αυτές τις οδούς:

- **LDAP Channel Binding (CBT)** συνδέει ένα LDAPS bind με το συγκεκριμένο TLS tunnel, διακόπτοντας relays/replays μεταξύ διαφορετικών καναλιών.
- **LDAP Signing** επιβάλλει integrity-protected LDAP μηνύματα, αποτρέποντας παραποιήσεις και τα περισσότερα unsigned relays.

**Quick offensive check**: εργαλεία όπως `netexec ldap <dc> -u user -p pass` εμφανίζουν τη στάση του server. Αν δείτε `(signing:None)` και `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** είναι εφικτά (π.χ. χρησιμοποιώντας KrbRelayUp για να γράψετε `msDS-AllowedToActOnBehalfOfOtherIdentity` για RBCD και να μιμηθείτε administrators).

**Server 2025 DCs** εισάγουν μια νέα GPO (**LDAP server signing requirements Enforcement**) που από προεπιλογή τίθεται σε **Require Signing** όταν είναι **Not Configured**. Για να αποφύγετε την επιβολή πρέπει να ορίσετε ρητά αυτή την πολιτική σε **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Απαιτήσεις**:
- CVE-2017-8563 patch (2017) προσθέτει υποστήριξη Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) προσθέτει LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (προεπιλογή, χωρίς CBT)
- `When Supported` (audit: εκπέμπει αποτυχίες, δεν μπλοκάρει)
- `Always` (enforce: απορρίπτει LDAPS binds χωρίς έγκυρο CBT)
- **Audit**: ορίστε **When Supported** για να εμφανίσετε:
- **3074** – ένα LDAPS bind θα είχε αποτύχει στην επικύρωση CBT αν εφαρμόζονταν.
- **3075** – ένα LDAPS bind παρέλειψε δεδομένα CBT και θα είχε απορριφθεί αν εφαρμοζόταν.
- (Το Event **3039** εξακολουθεί να σηματοδοτεί αποτυχίες CBT σε παλιότερα builds.)
- **Enforcement**: ορίστε **Always** όταν οι LDAPS clients στέλνουν CBTs; ισχύει μόνο για **LDAPS** (όχι raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (εναντίον `Negotiate signing` που είναι η προεπιλογή σε σύγχρονα Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (προεπιλογή είναι `None`).
- **Server 2025**: αφήστε την legacy policy σε `None` και ορίστε `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = επιβάλλεται από προεπιλογή· ορίστε `Disabled` για να το αποφύγετε).
- **Συμβατότητα**: μόνο Windows **XP SP3+** υποστηρίζει LDAP signing; παλαιότερα συστήματα θα σπάσουν όταν ενεργοποιηθεί η επιβολή.

## Εφαρμογή με προτεραιότητα στο audit (συνιστάται ~30 ημέρες)

1. Ενεργοποιήστε τα LDAP interface diagnostics σε κάθε DC για να καταγράψετε unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ορίστε στο DC GPO `LDAP server channel binding token requirements` = **When Supported** για να ξεκινήσει η τηλεμετρία CBT.
3. Παρακολουθήστε τα συμβάντα του Directory Service:
- **2889** – unsigned/unsigned-allow binds (μη συμβατά με signing).
- **3074/3075** – LDAPS binds that would fail or omit CBT (απαιτεί KB4520412 σε 2019/2022 και το βήμα 2 παραπάνω).
4. Εφαρμόστε σε ξεχωριστές αλλαγές:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Αναφορές

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
