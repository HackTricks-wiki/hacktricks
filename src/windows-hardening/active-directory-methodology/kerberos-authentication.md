# Autenticação Kerberos

{{#include ../../banners/hacktricks-training.md}}

Para uma explicação em nível de protocolo das trocas resumidas abaixo, consulte o artigo sobre Kerberos da Tarlogic.<sup>[[3]](#references)</sup>

## TL;DR para attackers
- Kerberos é o protocolo padrão de autenticação do AD; a maioria das cadeias de movimento lateral passará por ele.
- Pense em **três fases operacionais**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → use password/hash/certificate para obter um **TGT**. É aqui que entram **AS-REP roasting**, **over-pass-the-hash / pass-the-key** e **PKINIT**.
- **TGS-REQ / TGS-REP** → use um TGT para obter **service tickets**. É aqui que **Kerberoasting**, **S4U abuse**, **delegation abuse** e a maior parte do **ticket-forging tradecraft** se tornam relevantes.
- **AP-REQ / AP-REP** → apresente o ticket ao serviço. É aqui que ocorrem **pass-the-ticket** e o movimento lateral específico do serviço.
- Para cheatsheets práticos (AS-REP/Kerberoasting, ticket forgery, delegation abuse etc.), consulte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Use esta página como o índice de **visão geral / “o que mudou recentemente”** e, em seguida, acesse as páginas específicas sobre [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ou [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas recentes sobre ataques (2024-2026)
- **O hardening do RC4 mudou os padrões, não o Kerberos em si** – o hardening moderno dos DCs concentra-se nos **tipos de criptografia assumidos por padrão** para contas que **não** definem explicitamente `msDS-SupportedEncryptionTypes`. Após o rollout de 2026, essas contas passam cada vez mais a usar **AES-only** por padrão em DCs corrigidos, portanto as suposições cegas de Kerberoast com `/rc4` falham com mais frequência. No entanto, **contas de serviço explicitamente habilitadas para RC4 continuam sendo excelentes alvos para cracking offline**.<sup>[[1]](#references)</sup>
- **A aplicação da validação de PAC é importante para forged tickets** – o hardening de assinaturas PAC de 2024 significa que **golden/diamond/sapphire/extraSID-style abuses** precisam de dados PAC mais realistas e do contexto correto de assinatura. Domínios sem patches ou mantidos em implantações de compatibilidade/auditoria continuam sendo alvos mais fáceis.<sup>[[2]](#references)</sup>
- **O Kerberos baseado em certificados mudou duas vezes**:
- **Strong certificate binding** (cronograma do KB5014754) torna mapeamentos negligentes de certificado para conta menos confiáveis em ambientes totalmente enforced.
- **CVE-2025-26647** adicionou outra camada de hardening em torno de mapeamentos `altSecurityIdentities` que usam o Subject Key Identifier de um certificado. Portanto, o nível de patches, o estado de enforcement ou auditoria e a configuração explícita do mapeamento são relevantes ao avaliar pass-the-certificate e caminhos relacionados baseados em certificados.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Para PKINIT, o KDC também valida o caminho do certificado e verifica se o emissor é confiável por meio do armazenamento NTAuth.<sup>[[8]](#references)</sup>
- **O abuso de delegation entre domínios/florestas continua muito ativo** – o Windows oferece suporte a fluxos modernos de **S4U2Self/S4U2Proxy** entre realms, portanto atributos de delegation graváveis em outro domínio continuam valiosos. O obstáculo geralmente está na fidelidade das ferramentas e nos detalhes de trust/policy, não no suporte do protocolo.
- **A RBCD recursiva em múltiplos domínios é operacionalmente importante** – em florestas com 3 ou mais domínios, **S4U2Self/S4U2Proxy** pode recursar por meio de referrals de trust, e o abuso **SPN-less** pode exigir um salto final **`S4U2Self+U2U`** e o tratamento de tickets dependente de RC4. Consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **O Windows Server 2025 introduziu Managed Service Accounts delegadas (dMSAs)** e sua lógica de migração. Se você encontrar direitos delegados sobre OUs ou objetos de contas de serviço em um domínio de 2025, consulte a [página do BadSuccessor](acl-persistence-abuse/BadSuccessor.md), em vez de tratá-lo como “apenas mais uma gMSA”.<sup>[[7]](#references)</sup>

## Verificações rápidas do operador em domínios modernos

Antes de escolher um caminho de ataque Kerberos, responda rapidamente a quatro perguntas:

1. **Quais contas ainda são compatíveis com RC4?**
2. **Quais usuários não exigem pre-auth?**
3. **Quais objetos expõem delegation abuse?**
4. **Quais partes do domínio são novas o suficiente para aplicar o hardening recente?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Interpretação prática:
- Se as contas **SPN interessantes são explicitamente compatíveis com RC4**, o Kerberoasting continua barato e rápido.
- Se a maioria das contas de serviço **não possui configuração explícita de etype**, espere um comportamento **somente AES** em DCs atualizados de 2026 e planeje um cracking offline mais lento ou um caminho diferente.
- Se **RBCD / KCD / unconstrained delegation** estiver presente, S4U frequentemente supera o brute-force.
- Se a **autenticação por certificado** estiver em uso, lembre-se de que uma falha no caminho PKINIT **nem sempre** significa que o certificado é inútil; em muitos ambientes, o mesmo certificado ainda funciona para abuso de **Schannel/LDAPS** (consulte [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erros comuns do Kerberos que alteram o plano de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → A conta-alvo / DC não usará o encryption type solicitado. Pare de tentar somente com RC4; forneça **chaves AES** ou solicite material de roast em **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Provavelmente você possui a **chave de serviço errada**, o **SPN errado** ou um ticket forjado que não corresponde à conta de serviço que realmente o está descriptografando.
- **`KRB_AP_ERR_SKEW`** → Seu horário está incorreto. Sincronize com o DC antes de depurar qualquer outra coisa.
- **`KDC_ERR_BADOPTION`** durante fluxos de S4U / delegation → frequentemente significa **usuários sensíveis/não delegáveis**, o modelo de delegation incorreto ou que você está tentando usar **classic KCD** quando somente **RBCD** aceitaria um ticket S4U2Self não encaminhável.

## References
- [1] [Microsoft Learn - Detectar e corrigir o uso de RC4 no Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Orientações mais recentes de hardening do Windows e datas importantes](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Como funciona o Kerberos? – Teoria](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Explorando RBCD em ambientes Cross-Domain e Cross-Forest: Parte 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Alterações na autenticação baseada em certificados da KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647: vulnerabilidade de mapeamento de certificados do Kerberos](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Visão geral de Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Requisitos de certificados de smart card e validação pelo KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
