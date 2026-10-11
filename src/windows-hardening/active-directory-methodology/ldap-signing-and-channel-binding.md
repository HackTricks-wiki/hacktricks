# Endurecimento de LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

Ataques de relay/MITM de LDAP encaminham a autenticação para um controlador de domínio para obter um contexto LDAP autenticado. Dois controles relacionados reduzem essas possibilidades:

- **LDAP channel binding (CBT)** vincula a autenticação aplicável ao certificado/canal TLS usado pelo LDAPS, dificultando o relay entre canais.
- **LDAP signing** exige proteção de integridade para binds LDAP SASL. Não adiciona confidencialidade; use TLS quando o conteúdo LDAP também precisar de criptografia.<sup>[[2]](#references)</sup>

**Verificação rápida da postura**: ferramentas como `netexec ldap <dc> -u user -p pass` informam as políticas observadas de signing e channel binding. `(signing:None)` e `(channel binding:Never)` indicam controles ausentes, mas o sucesso de um relay ainda depende do tipo de autenticação capturada, do comportamento do EPA, dos privilégios da conta, do protocolo de destino e das proteções contra relay. Quando o principal retransmitido tem os direitos necessários, ferramentas como KrbRelayUp podem gravar `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurar a delegação restrita baseada em recursos (RBCD) e usar o caminho de delegação resultante para se passar por um principal privilegiado.<sup>[[4]](#references)</sup>

**Controladores de domínio Server 2025** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**), que por padrão usa **Require Signing** quando deixada como **Not Configured**. Para evitar a imposição, é necessário definir explicitamente essa política como **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (somente LDAPS)

- **Requisitos**:
  - O patch CVE-2017-8563 (2017) adiciona suporte a Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) adiciona telemetria “what-if” de CBT para LDAPS.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (padrão, sem CBT)
  - `When Supported` (imposição parcial: clientes compatíveis com CBT devem fornecer um token válido; clientes sem suporte a CBT ainda podem fazer bind, e eventos de auditoria são emitidos)
  - `Always` (imposição: rejeita binds LDAPS sem CBT válido)<sup>[[1]](#references)</sup>
- **Auditoria**: defina **When Supported** para identificar:
  - **3074** – O bind LDAPS teria falhado na validação de CBT se a imposição estivesse ativa.
  - **3075** – O bind LDAPS não incluiu dados de CBT e seria rejeitado se a imposição estivesse ativa.
  - (O evento **3039** ainda indica falhas de CBT em builds mais antigos.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Imposição**: defina **Always** quando os clientes LDAPS enviarem CBTs; só é eficaz em **LDAPS** (não em LDAP bruto na porta 389).<sup>[[1]](#references)</sup>

`When Supported` não é apenas para auditoria: valida o CBT de clientes compatíveis, permitindo binds de clientes sem suporte a CBT. A [referência da política da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descreve os padrões, que variam conforme a versão. LDAP signing aplica-se aos binds pertinentes em LDAP/389; channel binding aplica-se à autenticação LDAP protegida por TLS.


## LDAP Signing

- **GPO do cliente**: `Network security: LDAP client signing requirements` = `Require signing` (em vez do padrão `Negotiate signing` nas versões modernas do Windows).<sup>[[1]](#references)</sup>
- **GPO do DC**:
  - Legado: `Domain controller: LDAP server signing requirements` = `Require signing` (o padrão é `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: mantenha a política legada como `None` e defina `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` aplica a imposição por padrão; defina `Disabled` para evitá-la).<sup>[[1]](#references)</sup>
- **Compatibilidade**: faça o inventário de dispositivos e aplicações que não sejam Windows e que usem simple binds ou binds SASL sem assinatura. A Microsoft documenta o suporte nas versões mantidas do Windows; afirmações de compatibilidade com clientes legados devem ser verificadas em relação à pilha real do cliente, em vez de reduzidas a um limite de versão do XP.<sup>[[2]](#references)</sup>

## Implantação começando pela auditoria (recomendação: ~30 dias)

1. Ative o diagnóstico da interface LDAP em cada DC para registrar binds sem assinatura (evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Defina `LDAP server channel binding token requirements` da GPO do DC como **When Supported** para aplicação parcial de CBT e telemetria; valide primeiro a compatibilidade com clientes legados.<sup>[[1]](#references)</sup>
3. Monitore os eventos do Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds sem assinatura/permitidos sem assinatura (não conformidade de signing).
   - **3074/3075** – binds LDAPS que falhariam ou não incluiriam CBT (requer KB4520412 no Windows Server 2019/2022 e a etapa 2 acima).
4. Aplique em alterações separadas:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clientes).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - Vinculação de canal LDAP e LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de vinculação de canal LDAP e signing LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Atualização de mitigação de relay LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing desabilitado → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
