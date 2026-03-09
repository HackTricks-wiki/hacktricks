# Endurecimento de LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

LDAP relay/MITM permite que atacantes encaminhem binds para Domain Controllers para obter contextos autenticados. Dois controles no lado do servidor bloqueiam esses caminhos:

- **LDAP Channel Binding (CBT)** ties an **LDAPS** bind to the specific **TLS** tunnel, breaking relays/replays across different channels.
- **LDAP Signing** forces integrity-protected **LDAP** messages, preventing tampering and most unsigned relays.

**Verificação ofensiva rápida**: ferramentas como `netexec ldap <dc> -u user -p pass` exibem a postura do servidor. Se você vir `(signing:None)` e `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** são viáveis (por exemplo, usando KrbRelayUp para escrever `msDS-AllowedToActOnBehalfOfOtherIdentity` para RBCD e impersonar administradores).

**Server 2025 DCs** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**) que padrãoiza para **Require Signing** quando deixada **Not Configured**. Para evitar a aplicação é preciso definir explicitamente essa política como **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.
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

## Implantação com auditoria primeiro (recomendada ~30 dias)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Defina a GPO do DC `LDAP server channel binding token requirements` = **When Supported** para iniciar a telemetria CBT.
3. Monitore os eventos do Directory Service:
- **2889** – unsigned/unsigned-allow binds (assinatura não compatível).
- **3074/3075** – LDAPS binds que falhariam ou omitiriam CBT (requer KB4520412 no 2019/2022 e o passo 2 acima).
4. Aplique em alterações separadas:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
