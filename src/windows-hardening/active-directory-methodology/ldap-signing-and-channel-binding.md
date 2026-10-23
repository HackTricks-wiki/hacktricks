# Hardening de LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

Ataques de LDAP relay/MITM encaminham a autenticação para um controlador de domínio a fim de obter um contexto LDAP autenticado. A [visão geral de poisoning de resolução de nomes e relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) apresenta o fluxo de trabalho mais amplo. Dois controles relacionados reduzem esses caminhos:

- **LDAP channel binding (CBT)** vincula a autenticação aplicável ao certificado/canal TLS do servidor usado pelo LDAPS, dificultando relay entre canais.
- **LDAP signing** exige proteção de integridade para binds LDAP SASL. Não adiciona confidencialidade; use TLS quando o conteúdo LDAP também precisar de criptografia.<sup>[[2]](#references)</sup>

**Verificação rápida da postura**: ferramentas como `netexec ldap <dc> -u user -p pass` informam as políticas observadas de signing e channel binding. `(signing:None)` e `(channel binding:Never)` indicam ausência desses controles, mas um relay bem-sucedido ainda depende do tipo de autenticação capturada, do comportamento de EPA, dos privilégios da conta, do protocolo de destino e das proteções contra relay. Quando o principal retransmitido tem os direitos necessários, ferramentas como KrbRelayUp podem gravar `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurar delegação restrita baseada em recursos (RBCD) e usar o caminho de delegação resultante para se passar por um principal privilegiado.<sup>[[4]](#references)</sup>

**Controladores de domínio do Server 2025** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**) cujo padrão é **Require Signing** quando deixada como **Not Configured**. Para evitar a aplicação da política, é necessário defini-la explicitamente como **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (somente LDAPS)

- **Requisitos**:
  - O patch CVE-2017-8563 (2017) adiciona suporte a Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) adiciona telemetria “what-if” de CBT para LDAPS.<sup>[[2]](#references)</sup>
- **GPO (controladores de domínio)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (padrão, sem CBT)
  - `When Supported` (aplicação parcial: clientes compatíveis com CBT precisam fornecer um token válido; clientes sem suporte a CBT ainda podem fazer bind, e eventos de auditoria são emitidos)
  - `Always` (aplicação obrigatória: rejeita binds LDAPS sem CBT válido)<sup>[[1]](#references)</sup>
- **Auditoria**: defina **When Supported** para identificar:
  - **3074** – O bind LDAPS teria falhado na validação de CBT se a política estivesse aplicada.
  - **3075** – O bind LDAPS não incluiu dados de CBT e seria rejeitado se a política estivesse aplicada.
  - (O evento **3039** ainda indica falhas de CBT em versões mais antigas.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicação**: defina **Always** quando os clientes LDAPS enviarem CBTs; só é efetivo em **LDAPS** (não em 389 sem TLS).<sup>[[1]](#references)</sup>

`When Supported` não é apenas um modo de auditoria: valida CBT para clientes compatíveis e permite clientes sem suporte a CBT. A [referência de políticas da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descreve os padrões que variam conforme a versão. LDAP signing aplica-se aos binds pertinentes em LDAP/389; channel binding aplica-se à autenticação LDAP protegida por TLS.


## LDAP Signing

- **GPO do cliente**: `Network security: LDAP client signing requirements` = `Require signing` (em vez do padrão `Negotiate signing` nas versões modernas do Windows).<sup>[[1]](#references)</sup>
- **GPO do controlador de domínio**:
  - Legado: `Domain controller: LDAP server signing requirements` = `Require signing` (o padrão é `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: deixe a política legada como `None` e defina `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` significa que a política é aplicada por padrão; defina `Disabled` para evitá-la).<sup>[[1]](#references)</sup>
- **Compatibilidade**: inventarie dispositivos e aplicações que não sejam Windows e que usam simple binds ou binds SASL sem assinatura. A Microsoft documenta o suporte em versões mantidas do Windows; declarações de compatibilidade com clientes legados devem ser verificadas em relação à stack real do cliente, em vez de serem reduzidas a um limite de versão do XP.<sup>[[2]](#references)</sup>

## Implementação começando pela auditoria (recomendado: cerca de 30 dias)

1. Ative o diagnóstico da interface LDAP em cada controlador de domínio para registrar binds sem assinatura (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Defina `LDAP server channel binding token requirements` na GPO do DC como **When Supported** para aplicar a CBT parcialmente e coletar telemetria; valide primeiro a compatibilidade com clientes legados.<sup>[[1]](#references)</sup>
3. Monitore os eventos do Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds sem assinatura ou com assinatura opcional (não conformes com os requisitos de assinatura).
   - **3074/3075** – binds LDAPS que falhariam ou não incluiriam CBT (requer KB4520412 no Server 2019/2022 e a etapa 2 acima).
4. Aplique em alterações separadas:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clientes).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Vinculação de canal LDAP e assinatura LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de vinculação de canal e assinatura LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Atualização para mitigação de relay LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (assinatura LDAP desativada → relay Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
