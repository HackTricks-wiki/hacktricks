# Hardening LDAP Signing και Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

Το LDAP relay/MITM επιτρέπει στους attackers να προωθούν binds σε Domain Controllers για να αποκτήσουν authenticated contexts. Δύο server-side controls περιορίζουν αυτές τις διαδρομές:

- **LDAP Channel Binding (CBT)** συνδέει ένα LDAPS bind με το συγκεκριμένο TLS tunnel, αποτρέποντας relays/replays μεταξύ διαφορετικών channels.
- **LDAP Signing** επιβάλλει integrity-protected LDAP messages, αποτρέποντας την παραποίηση και τα περισσότερα unsigned relays.

**Γρήγορος offensive έλεγχος**: εργαλεία όπως το `netexec ldap <dc> -u user -p pass` εμφανίζουν το posture του server. Αν δείτε `(signing:None)` και `(channel binding:Never)`, τα Kerberos/NTLM **relays προς LDAP** είναι εφικτά (π.χ. με χρήση του KrbRelayUp για εγγραφή του `msDS-AllowedToActOnBehalfOfOtherIdentity` για RBCD και impersonation administrators).<sup>[[4]](#references)</sup>

Οι **Server 2025 DCs** εισάγουν ένα νέο GPO (**LDAP server signing requirements Enforcement**) που έχει ως προεπιλογή το **Require Signing** όταν παραμένει **Not Configured**. Για να αποφύγετε το enforcement, πρέπει να ορίσετε ρητά την policy ως **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (μόνο LDAPS)

- **Requirements**:
- Το patch CVE-2017-8563 (2017) προσθέτει υποστήριξη Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- Το **KB4520412** (Server 2019/2022) προσθέτει LDAPS CBT “what-if” telemetry.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, χωρίς CBT)
- `When Supported` (audit: εκπέμπει failures, δεν κάνει block)
- `Always` (enforce: απορρίπτει LDAPS binds χωρίς έγκυρο CBT)<sup>[[1]](#references)</sup>
- **Audit**: ορίστε το **When Supported** για να εντοπίσετε:
- **3074** – Το LDAPS bind θα είχε αποτύχει στο CBT validation αν υπήρχε enforcement.
- **3075** – Το LDAPS bind δεν περιείχε CBT data και θα απορριπτόταν αν υπήρχε enforcement.
- (Το event **3039** εξακολουθεί να σηματοδοτεί CBT failures σε παλαιότερα builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: ορίστε το **Always** μόλις οι LDAPS clients στέλνουν CBTs· εφαρμόζεται μόνο σε **LDAPS** (όχι στο raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (σε αντίθεση με το προεπιλεγμένο `Negotiate signing` στα σύγχρονα Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (η προεπιλογή είναι `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: αφήστε την legacy policy στο `None` και ορίστε το `LDAP server signing requirements Enforcement` = `Enabled` (το Not Configured = enforced by default· ορίστε `Disabled` για να το αποφύγετε).<sup>[[1]](#references)</sup>
- **Compatibility**: μόνο τα Windows **XP SP3+** υποστηρίζουν LDAP signing· παλαιότερα συστήματα θα σταματήσουν να λειτουργούν όταν ενεργοποιηθεί το enforcement.

## Audit-first rollout (συνιστώνται περίπου 30 ημέρες)

1. Ενεργοποιήστε τα LDAP interface diagnostics σε κάθε DC, ώστε να καταγράφονται τα unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Set DC GPO `LDAP server channel binding token requirements` = **When Supported** to start CBT telemetry.<sup>[[1]](#references)</sup>
3. Monitor Directory Service events:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – binds χωρίς υπογραφή/με επιτρεπόμενη απουσία υπογραφής (μη συμμόρφωση με το signing).
- **3074/3075** – LDAPS binds που θα αποτύγχαναν ή θα παρέλειπαν το CBT (απαιτείται το KB4520412 σε 2019/2022 και το παραπάνω βήμα 2).
4. Enforce in separate changes:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding και LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Απαιτήσεις LDAP channel binding και LDAP signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ενημέρωση mitigation για LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
