# Σκληροποίηση LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

Το LDAP relay/MITM επιτρέπει σε επιτιθέμενους να προωθούν binds σε Domain Controllers για να αποκτήσουν πιστοποιημένα contexts. Δύο ελεγκτικοί μηχανισμοί στην πλευρά του server μπλοκάρουν αυτές τις διαδρομές:

- **LDAP Channel Binding (CBT)** δένει ένα LDAPS bind με το συγκεκριμένο TLS tunnel, διασπώντας relays/replays μεταξύ διαφορετικών καναλιών.
- **LDAP Signing** επιβάλλει ότι τα LDAP μηνύματα έχουν προστασία ακεραιότητας, αποτρέποντας την παραποίηση και τα περισσότερα unsigned relays.

Οι Server 2025 DCs εισάγουν μια νέα GPO (**LDAP server signing requirements Enforcement**) που έχει ως προεπιλογή το **Require Signing** όταν αφήνεται **Not Configured**. Για να αποφύγετε την επιβολή πρέπει ρητά να ορίσετε αυτήν την πολιτική σε **Disabled**.

## LDAP Channel Binding (LDAPS μόνο)

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
  - **Server 2025**: αφήστε την legacy policy στο `None` και ορίστε `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = επιβάλλεται από προεπιλογή; ορίστε `Disabled` για να το αποφύγετε).
- **Compatibility**: μόνο Windows **XP SP3+** υποστηρίζουν LDAP signing; παλαιότερα συστήματα θα σταματήσουν να λειτουργούν όταν η επιβολή ενεργοποιηθεί.

## Εφαρμογή με προτεραιότητα στην επιτήρηση (συνιστάται ~30 ημέρες)

1. Ενεργοποιήστε τη διάγνωση διεπαφής LDAP σε κάθε DC για την καταγραφή unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Ορίστε στο GPO του DC `LDAP server channel binding token requirements` = **When Supported** για να ξεκινήσει η τηλεμετρία CBT.
3. Παρακολουθήστε τα γεγονότα του Directory Service:
- **2889** – unsigned/unsigned-allow binds (μη συμβατά με signing).
- **3074/3075** – LDAPS binds που θα αποτύχουν ή θα παραλείψουν CBT (απαιτεί KB4520412 σε 2019/2022 και το βήμα 2 παραπάνω).
4. Εφαρμόστε ως ξεχωριστές αλλαγές:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Αναφορές

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
