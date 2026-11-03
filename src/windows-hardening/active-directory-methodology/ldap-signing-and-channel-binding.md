# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Why it matters

LDAP relay/MITM attacks forward authentication to a domain controller to obtain an authenticated LDAP context. The [name-resolution poisoning and relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) covers the broader workflow. Two related controls reduce these paths:

- **LDAP channel binding (CBT)** binds applicable authentication to the TLS server certificate/channel used by LDAPS, frustrating cross-channel relay.
- **LDAP signing** requires integrity protection for SASL LDAP binds. It does not add confidentiality; use TLS when LDAP contents also need encryption.<sup>[[2]](#references)</sup>

**Quick posture check**: tools such as `netexec ldap <dc> -u user -p pass` report observed signing and channel-binding policy. `(signing:None)` and `(channel binding:Never)` indicate missing controls, but a successful relay still depends on the captured authentication type, EPA behavior, account privileges, target protocol, and relay protections. When the relayed principal has the necessary rights, tooling such as KrbRelayUp can write `msDS-AllowedToActOnBehalfOfOtherIdentity`, configure resource-based constrained delegation (RBCD), and use the resulting delegation path to impersonate a privileged principal.<sup>[[4]](#references)</sup>

**Server 2025 DCs** introduce a new GPO (**LDAP server signing requirements Enforcement**) that defaults to **Require Signing** when left **Not Configured**. To avoid enforcement you must explicitly set that policy to **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
  - CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (default, no CBT)
  - `When Supported` (partial enforcement: CBT-capable clients must provide a valid token; clients without CBT support can still bind, and audit events are emitted)
  - `Always` (enforce: rejects LDAPS binds without valid CBT)<sup>[[1]](#references)</sup>
- **Audit**: set **When Supported** to surface:
  - **3074** – LDAPS bind would have failed CBT validation if enforced.
  - **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
  - (Event **3039** still signals CBT failures on older builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389).<sup>[[1]](#references)</sup>

`When Supported` is not audit-only: it validates CBT for capable clients while allowing clients without CBT support. The [Microsoft policy reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) describes its version-dependent defaults. LDAP signing applies to applicable binds on LDAP/389; channel binding applies to TLS-protected LDAP authentication.


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).<sup>[[1]](#references)</sup>
- **Compatibility**: Inventory non-Windows appliances and applications using simple binds or unsigned SASL binds. Microsoft documents support on maintained Windows versions; legacy-client compatibility statements should be verified against the actual client stack rather than reduced to an XP version threshold.<sup>[[2]](#references)</sup>

## Relay paths and signed-SASL reauthentication

If **only signing** is required, relaying to LDAPS can still work when channel binding is not enforced: TLS supplies transport integrity. If **only channel binding** is required, plain LDAP has no TLS channel to bind; a relay can authenticate on TCP 389 and then use StartTLS for operations that require TLS, provided the relayed identity has the necessary rights. Enforcing both closes these conventional alternatives, but it did not stop the following flaw on unpatched domain controllers.<sup>[[5]](#references)</sup>

### Stacking an LDAP operation after a relayed Bind

On affected Windows Server 2016–2025 domain controllers, first establish a **signed NTLM SASL LDAP connection** on TCP 389 as identity X, using credentials whose session key you know (or an anonymous NTLM SASL context where accepted). Coerce identity Y to authenticate **over SMB** to the relay. Forward Y's NTLM NEGOTIATE and the DC's CHALLENGE through GSS-SPNEGO Bind requests on X's existing LDAP connection. The Windows SMB client sets `NTLMSSP_NEGOTIATE_SIGN`, so the resulting LDAP bind requires a signed SASL layer; an HTTP/WebDAV-origin exchange generally lacks that flag and is not interchangeable here.<sup>[[5]](#references)</sup>

When Y sends NTLM AUTHENTICATE, put **two distinct LDAP messages in one length-prefixed SASL record**: a BindRequest carrying that response, then a ModifyRequest. Sign the entire record with X's known key. The vulnerable DC verifies the record under X, completes the Bind and switches the connection's authorization to Y, then executes the remaining ModifyRequest as Y without rechecking the record under Y's key. This does not disclose Y's password or session key; a later record signed by X fails. An RBCD write to `msDS-AllowedToActOnBehalfOfOtherIdentity` or a shadow-credential write to `msDS-KeyCredentialLink` still requires Y to have permission on the target object. See [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md), and, for a relayed DC machine account, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

This is a **plain LDAP** bypass, not an LDAPS channel-binding bypass. On LDAPS, TLS protects the connection and Windows does not establish the X-key NTLM SASL signing layer needed for this record-stacking path. If TCP 389 is unavailable, the technique does not simply transfer to TCP 636. The October 2026 cumulative update KB5126646 prevents the same-record operation by discarding remaining data after the Bind changes the connection identity.<sup>[[5]](#references)</sup>

The researcher's [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) wraps a modified `ntlmrelayx.py` for this workflow. It requires an **SMB** coercion source, a pinned Impacket tree exposing LDAP signing/security-context APIs (PyPI Impacket 0.13.1 is insufficient), and an attacker-controlled account for the initial signed bind. For an RBCD write, supply the victim object's DN and the SID of a controlled delegating computer; use `-attribute` with `-value` or `-value-hex` for another permitted write. Confirm the tool's independent signed read-back rather than treating a relay-side `FAILED` message as proof that the ModifyRequest failed.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Trigger the SMB authentication separately; see [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) for one coercion surface and the [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) for others. The tool's command and implementation are documented in its repository.<sup>[[6]](#references)</sup>

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Set DC GPO `LDAP server channel binding token requirements` = **When Supported** for partial CBT enforcement and telemetry; validate legacy-client compatibility first.<sup>[[1]](#references)</sup>
3. Monitor Directory Service events:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (signing noncompliant).
   - **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Enforce in separate changes:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signed, Sealed, and Relayed, NTLM-style](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo proof of concept](https://github.com/grayhatkiller/switcheroo)
{{#include ../../banners/hacktricks-training.md}}
