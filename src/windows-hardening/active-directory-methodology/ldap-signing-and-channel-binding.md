# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Why it matters

LDAP relay/MITM attacks forward authentication to a domain controller to obtain an authenticated LDAP context. Two related controls reduce these paths:

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
  - `When Supported` (audit: emits failures, does not block)
  - `Always` (enforce: rejects LDAPS binds without valid CBT)<sup>[[1]](#references)</sup>
- **Audit**: set **When Supported** to surface:
  - **3074** – LDAPS bind would have failed CBT validation if enforced.
  - **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
  - (Event **3039** still signals CBT failures on older builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).<sup>[[1]](#references)</sup>
- **Compatibility**: Inventory non-Windows appliances and applications using simple binds or unsigned SASL binds. Microsoft documents support on maintained Windows versions; legacy-client compatibility statements should be verified against the actual client stack rather than reduced to an XP version threshold.<sup>[[2]](#references)</sup>

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Set DC GPO `LDAP server channel binding token requirements` = **When Supported** to start CBT telemetry.<sup>[[1]](#references)</sup>
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

{{#include ../../banners/hacktricks-training.md}}
