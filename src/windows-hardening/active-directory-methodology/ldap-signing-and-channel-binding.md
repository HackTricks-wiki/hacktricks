# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

LDAP relay/MITM permite que atacantes encaminhem binds para Controladores de Domínio para obter contextos autenticados. Dois controles no lado do servidor mitigam essas vias:

- **LDAP Channel Binding (CBT)** vincula um bind LDAPS ao túnel TLS específico, quebrando relays/replays across different channels.
- **LDAP Signing** força mensagens LDAP com integridade protegida, prevenindo adulterações e a maioria dos relays não assinados.

**Verificação ofensiva rápida**: ferramentas como `netexec ldap <dc> -u user -p pass` mostram a postura do servidor. Se você vir `(signing:None)` e `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** são viáveis (por exemplo, usando KrbRelayUp para escrever `msDS-AllowedToActOnBehalfOfOtherIdentity` para RBCD e se passar por administradores).

Server 2025 DCs introduzem uma nova GPO (**LDAP server signing requirements Enforcement**) que por padrão define **Require Signing** quando fica **Not Configured**. Para evitar a aplicação você deve explicitamente definir essa política como **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) adds Extended Protection for Authentication support.
- **KB4520412** (Server 2019/2022) adds LDAPS CBT “what-if” telemetry.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, sem CBT)
- `When Supported` (audit: emite falhas, não bloqueia)
- `Always` (enforce: rejeita binds LDAPS sem CBT válido)
- **Audit**: set **When Supported** to surface:
- **3074** – LDAPS bind would have failed CBT validation if enforced.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced.
- (Event **3039** still signals CBT failures on older builds.)
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389).

## LDAP Signing

- **GPO do cliente**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **GPO do DC**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it).
- **Compatibilidade**: only Windows **XP SP3+** supports LDAP signing; sistemas mais antigos vão quebrar quando a aplicação estiver habilitada.

## Implantação com auditoria primeiro (recomendada ~30 dias)

1. Habilite os diagnósticos da interface LDAP em cada DC para registrar binds não assinados (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Configure o GPO dos DCs `LDAP server channel binding token requirements` = **When Supported** para iniciar a telemetria de CBT.
3. Monitore eventos do Directory Service:
- **2889** – unsigned/unsigned-allow binds (signing noncompliant).
- **3074/3075** – LDAPS binds that would fail or omit CBT (requires KB4520412 on 2019/2022 and step 2 above).
4. Implemente em alterações separadas:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referências

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
