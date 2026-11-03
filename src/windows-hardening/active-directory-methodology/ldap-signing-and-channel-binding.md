# Fortalecimento de LDAP Signing e Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Por que isso importa

Ataques de LDAP relay/MITM encaminham a autenticação para um controlador de domínio para obter um contexto LDAP autenticado. A [visão geral de envenenamento de resolução de nomes e relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) aborda o fluxo de trabalho mais amplo. Dois controles relacionados reduzem essas possibilidades:

- **LDAP channel binding (CBT)** vincula a autenticação aplicável ao certificado/canal TLS do servidor usado pelo LDAPS, dificultando o relay entre canais.
- **LDAP signing** exige proteção de integridade para binds LDAP SASL. Ele não adiciona confidencialidade; use TLS quando o conteúdo LDAP também precisar de criptografia.<sup>[[2]](#references)</sup>

**Verificação rápida da postura**: ferramentas como `netexec ldap <dc> -u user -p pass` informam as políticas observadas de signing e channel binding. `(signing:None)` e `(channel binding:Never)` indicam controles ausentes, mas um relay bem-sucedido ainda depende do tipo de autenticação capturada, do comportamento de EPA, dos privilégios da conta, do protocolo de destino e das proteções contra relay. Quando o principal retransmitido tem os direitos necessários, ferramentas como KrbRelayUp podem gravar `msDS-AllowedToActOnBehalfOfOtherIdentity`, configurar resource-based constrained delegation (RBCD) e usar o caminho de delegação resultante para se passar por um principal privilegiado.<sup>[[4]](#references)</sup>

**Controladores de domínio Server 2025** introduzem uma nova GPO (**LDAP server signing requirements Enforcement**), que assume o padrão **Require Signing** quando deixada como **Not Configured**. Para evitar a aplicação da política, é necessário defini-la explicitamente como **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (somente LDAPS)

- **Requisitos**:
  - O patch CVE-2017-8563 (2017) adiciona suporte a Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) adiciona telemetria “what-if” de CBT para LDAPS.<sup>[[2]](#references)</sup>
- **GPO (controladores de domínio)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (padrão, sem CBT)
  - `When Supported` (aplicação parcial: clientes compatíveis com CBT precisam fornecer um token válido; clientes sem suporte a CBT ainda podem fazer bind, e eventos de auditoria são emitidos)
  - `Always` (aplicação obrigatória: rejeita binds LDAPS sem CBT válido)<sup>[[1]](#references)</sup>
- **Auditoria**: defina **When Supported** para identificar:
  - **3074** – o bind LDAPS teria falhado na validação de CBT se a política estivesse sendo aplicada.
  - **3075** – o bind LDAPS não incluiu dados de CBT e seria rejeitado se a política estivesse sendo aplicada.
  - (O evento **3039** ainda sinaliza falhas de CBT em versões mais antigas.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Aplicação**: defina **Always** quando os clientes LDAPS enviarem CBTs; isso só é efetivo em **LDAPS** (não em LDAP sem TLS na porta 389).<sup>[[1]](#references)</sup>

`When Supported` não é apenas para auditoria: valida o CBT de clientes compatíveis e permite clientes sem suporte a CBT. A [referência da política da Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) descreve os padrões, que variam conforme a versão. LDAP signing se aplica aos binds aplicáveis em LDAP/389; channel binding se aplica à autenticação LDAP protegida por TLS.


## LDAP Signing

- **GPO de cliente**: `Network security: LDAP client signing requirements` = `Require signing` (em vez do padrão `Negotiate signing` nas versões modernas do Windows).<sup>[[1]](#references)</sup>
- **GPO do controlador de domínio**:
  - Legado: `Domain controller: LDAP server signing requirements` = `Require signing` (o padrão é `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: mantenha a política legada como `None` e defina `LDAP server signing requirements Enforcement` = `Enabled` (`Not Configured` aplica a política por padrão; defina `Disabled` para evitá-la).<sup>[[1]](#references)</sup>
- **Compatibilidade**: faça o inventário de dispositivos e aplicativos que não são Windows e usam binds simples ou binds SASL sem assinatura. A Microsoft documenta o suporte nas versões mantidas do Windows; declarações de compatibilidade com clientes legados devem ser verificadas em relação à pilha real do cliente, em vez de reduzidas a um limite de versão do XP.<sup>[[2]](#references)</sup>

## Caminhos de relay e reautenticação de SASL assinado

Se **somente signing** for obrigatório, o relay para LDAPS ainda poderá funcionar quando channel binding não estiver sendo aplicado: TLS fornece integridade de transporte. Se **somente channel binding** for obrigatório, LDAP simples não tem um canal TLS ao qual vincular a autenticação; um relay pode autenticar pela porta TCP 389 e depois usar StartTLS para operações que exigem TLS, desde que a identidade retransmitida tenha os direitos necessários. A aplicação de ambos fecha essas alternativas convencionais, mas não impediu a seguinte falha em controladores de domínio sem patch.<sup>[[5]](#references)</sup>

### Encadear uma operação LDAP após um Bind retransmitido

Em controladores de domínio Windows Server 2016–2025 afetados, primeiro estabeleça uma **conexão LDAP SASL NTLM assinada** na porta TCP 389 como a identidade X, usando credenciais cuja chave de sessão você conhece (ou um contexto SASL NTLM anônimo, quando aceito). Induza a identidade Y a se autenticar **por SMB** no relay. Encaminhe o NTLM NEGOTIATE de Y e o CHALLENGE do controlador de domínio por meio de solicitações Bind GSS-SPNEGO na conexão LDAP existente de X. O cliente SMB do Windows define `NTLMSSP_NEGOTIATE_SIGN`, então o bind LDAP resultante exige uma camada SASL assinada; uma troca originada por HTTP/WebDAV geralmente não tem essa flag e não é intercambiável nesse caso.<sup>[[5]](#references)</sup>

Quando Y envia NTLM AUTHENTICATE, coloque **duas mensagens LDAP distintas em um único registro SASL com prefixo de comprimento**: uma BindRequest contendo essa resposta e, em seguida, uma ModifyRequest. Assine todo o registro com a chave conhecida de X. O controlador de domínio vulnerável verifica o registro usando X, conclui o Bind e altera a autorização da conexão para Y; em seguida, executa a ModifyRequest restante como Y, sem verificar novamente o registro usando a chave de Y. Isso não revela a senha nem a chave de sessão de Y; um registro posterior assinado por X falha. Uma gravação de RBCD em `msDS-AllowedToActOnBehalfOfOtherIdentity` ou uma gravação de shadow credentials em `msDS-KeyCredentialLink` ainda exige que Y tenha permissão no objeto de destino. Consulte [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) e, para uma conta de máquina de controlador de domínio retransmitida, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Este é um bypass de **LDAP simples**, não um bypass de channel binding de LDAPS. Em LDAPS, TLS protege a conexão e o Windows não estabelece a camada de assinatura SASL NTLM com a chave de X necessária para esse caminho de encadeamento de registros. Se TCP 389 não estiver disponível, a técnica não pode simplesmente ser transferida para TCP 636. As atualizações de segurança de outubro de 2026 impedem a operação no mesmo registro descartando os dados restantes depois que o Bind altera a identidade da conexão.<sup>[[5]](#references)</sup> KB5126646 é a atualização do Windows Server 2025; as outras versões afetadas do Server têm números de KB diferentes.<sup>[[7]](#references)</sup>

A ferramenta [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) do pesquisador adapta uma versão modificada de `ntlmrelayx.py` para esse fluxo de trabalho. Ela exige uma origem de coerção **SMB**, uma árvore Impacket fixada em uma versão que exponha APIs de LDAP signing/security-context (Impacket 0.13.1 do PyPI não é suficiente) e uma conta controlada pelo atacante para o bind assinado inicial. Para uma gravação de RBCD, forneça o DN do objeto vítima e o SID de um computador delegador controlado; use `-attribute` com `-value` ou `-value-hex` para outra gravação permitida. Confirme a leitura de retorno assinada independente da ferramenta, em vez de considerar uma mensagem `FAILED` do lado do relay como prova de que a ModifyRequest falhou.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Acione a autenticação SMB separadamente; consulte [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) para conhecer uma superfície de coerção e a [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) para outras. O comando e a implementação da ferramenta estão documentados no repositório dela.<sup>[[6]](#references)</sup>

## Implementação priorizando a auditoria (recomendado: ~30 dias)

1. Habilite o diagnóstico da interface LDAP em cada DC para registrar binds sem assinatura (Evento **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Defina a GPO do DC `LDAP server channel binding token requirements` = **When Supported** para aplicação parcial de CBT e telemetria; valide primeiro a compatibilidade com clientes legados.<sup>[[1]](#references)</sup>
3. Monitore os eventos do Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – associações sem assinatura/permitidas sem assinatura (não conformidade com os requisitos de assinatura).
   - **3074/3075** – associações LDAPS que falhariam ou omitiriam CBT (requer KB4520412 no 2019/2022 e a etapa 2 acima).
4. Aplique em alterações separadas:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clientes).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ou** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Vinculação de canal LDAP e assinatura LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Requisitos de vinculação de canal LDAP e assinatura LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Atualização de mitigação de retransmissão LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (assinatura LDAP desativada → retransmissão Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Assinado, selado e retransmitido, estilo NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Prova de conceito do LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Informações sobre versões do Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
