# Endurecimento de LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

O relay/MITM de LDAP permite que atacantes encaminhem binds para Domain Controllers para obter contextos autenticados. Dois controles do lado do servidor mitigam essas vias:

- **LDAP Channel Binding (CBT)** vincula um bind LDAPS ao túnel TLS específico, quebrando relays/replays entre diferentes canais.
- **LDAP Signing** força mensagens LDAP com proteção de integridade, impedindo adulterações e a maioria dos relays sem assinatura.

**Server 2025 DCs** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**) que por padrão passa a **Require Signing** quando deixada **Not Configured**. Para evitar a aplicação você deve explicitamente definir essa política como **Disabled**.

## LDAP Channel Binding (apenas LDAPS)

- **Requisitos**:
- O patch CVE-2017-8563 (2017) adiciona suporte a Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) adiciona telemetria “what-if” de LDAPS CBT.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (padrão, sem CBT)
- `When Supported` (auditoria: emite falhas, não bloqueia)
- `Always` (aplicação: rejeita binds LDAPS sem CBT válido)
- **Auditoria**: defina **When Supported** para expor:
- **3074** – O bind LDAPS teria falhado na validação CBT se aplicado.
- **3075** – O bind LDAPS omitiu dados CBT e seria rejeitado se aplicado.
- (O evento **3039** ainda sinaliza falhas de CBT em builds mais antigos.)
- **Aplicação**: configure **Always** depois que os clientes LDAPS começarem a enviar CBTs; efetivo apenas em **LDAPS** (não em 389 puro).

## LDAP Signing

- **GPO de cliente**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` padrão no Windows moderno).
- **GPO do DC**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (o padrão é `None`).
- **Server 2025**: deixe a política legada em `None` e defina `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = aplicado por padrão; defina `Disabled` para evitar).
- **Compatibilidade**: apenas Windows **XP SP3+** suporta LDAP signing; sistemas mais antigos irão falhar quando a aplicação for habilitada.

## Implantação com auditoria primeiro (recomendada ~30 dias)

1. Ative diagnostics da interface LDAP em cada DC para registrar binds sem assinatura (Evento **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Defina a GPO de DC `LDAP server channel binding token requirements` = **When Supported** para iniciar a telemetria de CBT.
3. Monitore eventos do Directory Service:
- **2889** – unsigned/unsigned-allow binds (assinatura não compatível).
- **3074/3075** – LDAPS binds que falhariam ou omitiriam CBT (requer KB4520412 no 2019/2022 e o passo 2 acima).
4. Aplique em alterações separadas:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clientes).
- `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referências

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
