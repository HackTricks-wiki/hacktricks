# Hardening de LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

LDAP relay/MITM permite que atacantes encaminhem binds para Domain Controllers para obter contextos autenticados. Dois controles no servidor reduzem esses caminhos:

- **LDAP Channel Binding (CBT)** vincula um bind LDAPS ao túnel TLS específico, interrompendo relays/replays entre canais diferentes.
- **LDAP Signing** força mensagens LDAP protegidas por integridade, impedindo adulterações e a maioria dos relays sem assinatura.

**Verificação ofensiva rápida**: ferramentas como `netexec ldap <dc> -u user -p pass` exibem a postura do servidor. Se você vir `(signing:None)` e `(channel binding:Never)`, **relays de Kerberos/NTLM para LDAP** são viáveis (por exemplo, usando KrbRelayUp para gravar `msDS-AllowedToActOnBehalfOfOtherIdentity` para RBCD e impersonar administradores).<sup>[[4]](#references)</sup>

**DCs Server 2025** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**) que assume **Require Signing** por padrão quando deixada como **Not Configured**. Para evitar a aplicação, você deve definir explicitamente essa política como **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (somente LDAPS)

- **Requisitos**:
- O patch do CVE-2017-8563 (2017) adiciona suporte a Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **KB4520412** (Server 2019/2022) adiciona telemetria “what-if” de CBT para LDAPS.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (padrão, sem CBT)
- `When Supported` (auditoria: emite falhas, mas não bloqueia)
- `Always` (aplicação: rejeita binds LDAPS sem CBT válido)<sup>[[1]](#references)</sup>
- **Auditoria**: defina como **When Supported** para identificar:
- **3074** – o bind LDAPS teria falhado na validação de CBT se a aplicação estivesse habilitada.
- **3075** – o bind LDAPS não incluiu dados de CBT e seria rejeitado se a aplicação estivesse habilitada.
- (O evento **3039** ainda sinaliza falhas de CBT em builds mais antigos.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicação**: defina como **Always** assim que os clientes LDAPS enviarem CBTs; só é efetivo em **LDAPS** (não em 389 bruto).<sup>[[1]](#references)</sup>


## LDAP Signing

- **GPO do cliente**: `Network security: LDAP client signing requirements` = `Require signing` (em vez do padrão `Negotiate signing` nas versões modernas do Windows).<sup>[[1]](#references)</sup>
- **GPO do DC**:
- Legado: `Domain controller: LDAP server signing requirements` = `Require signing` (o padrão é `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: mantenha a política legada como `None` e defina `LDAP server signing requirements Enforcement` como `Enabled` (`Not Configured` = aplicado por padrão; defina como `Disabled` para evitá-lo).<sup>[[1]](#references)</sup>
- **Compatibilidade**: somente o Windows **XP SP3+** oferece suporte a LDAP signing; sistemas mais antigos apresentarão falhas quando a aplicação estiver habilitada.

## Implementação priorizando a auditoria (recomendado: ~30 dias)

1. Habilite os diagnósticos da interface LDAP em cada DC para registrar binds sem assinatura (evento **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Defina a GPO do DC `LDAP server channel binding token requirements` = **When Supported** para iniciar a telemetria de CBT.<sup>[[1]](#references)</sup>
3. Monitore os eventos do Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – binds unsigned/unsigned-allow (incompatíveis com signing).
- **3074/3075** – binds LDAPS que falhariam ou omitiriam CBT (requer KB4520412 no 2019/2022 e a etapa 2 acima).
4. Aplique em alterações separadas:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clientes).
- `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referências

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
