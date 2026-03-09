# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

LDAP relay/MITM επιτρέπει σε επιτιθέμενους να προωθούν binds προς Domain Controllers για να αποκτήσουν επαληθευμένα πλαίσια αυθεντικοποίησης. Δύο ελέγχοι στην πλευρά του server αμβλύνουν αυτές τις διαδρομές:

- **LDAP Channel Binding (CBT)** συνδέει ένα LDAPS bind με τη συγκεκριμένη TLS σήραγγα, διακόπτοντας relays/replays μεταξύ διαφορετικών καναλιών.
- **LDAP Signing** επιβάλλει μηνύματα LDAP με προστασία ακεραιότητας, αποτρέποντας την παραποίηση και τα περισσότερα μη υπογεγραμμένα relays.

**Γρήγορος επιθετικός έλεγχος**: εργαλεία όπως `netexec ldap <dc> -u user -p pass` εκτυπώνουν τη στάση του διακομιστή. Αν δείτε `(signing:None)` και `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** είναι εφικτοί (π.χ., χρησιμοποιώντας KrbRelayUp για να γράψετε `msDS-AllowedToActOnBehalfOfOtherIdentity` για RBCD και να μιμηθείτε διαχειριστές).

**Server 2025 DCs** εισάγουν ένα νέο GPO (**LDAP server signing requirements Enforcement**) που προεπιλέγεται σε **Require Signing** όταν παραμένει **Not Configured**. Για να αποφύγετε την επιβολή πρέπει ρητά να ορίσετε αυτή την πολιτική σε **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Απαιτήσεις**:
- CVE-2017-8563 patch (2017) προσθέτει υποστήριξη Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) προσθέτει LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: set **When Supported** to surface:
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Event **3039** still signals CBT failures on older builds.)
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Compatibility**: only Windows **XP SP3+** supports LDAP signing; older systems will break when enforcement is enabled.

## Audit-first rollout (recommended ~30 days)

1. Ενεργοποιήστε το LDAP interface diagnostics σε κάθε DC για να καταγράφει μη υπογεγραμμένα binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ρύθμισε το GPO του DC `LDAP server channel binding token requirements` = **When Supported** για να ξεκινήσει η τηλεμετρία CBT.
3. Παρακολούθησε τα συμβάντα Directory Service:
- **2889** – unsigned/unsigned-allow binds (μη συμβατό με signing).
- **3074/3075** – LDAPS binds that would fail or omit CBT (απαιτεί KB4520412 σε 2019/2022 και το βήμα 2 παραπάνω).
4. Εφαρμόστε ξεχωριστά τις εξής αλλαγές:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) ή (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Αναφορές

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
