# Autenticação Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Confira o post incrível sobre:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para atacantes
- Kerberos é o protocolo padrão de autenticação do AD; a maioria das cadeias de movimento lateral passará por ele.
- Pense em **três fases operacionais**:
- **AS-REQ / AS-REP** → senha/hash/certificado para obter um **TGT**. É aqui que entram **AS-REP roasting**, **over-pass-the-hash / pass-the-key** e **PKINIT**.
- **TGS-REQ / TGS-REP** → usar um TGT para obter **service tickets**. É aqui que **Kerberoasting**, **S4U abuse**, **delegation abuse** e a maior parte do **ticket-forging tradecraft** se tornam relevantes.
- **AP-REQ / AP-REP** → apresentar o ticket ao serviço. É aqui que ocorrem **pass-the-ticket** e o movimento lateral específico do serviço.
- Para cheatsheets práticos (AS-REP/Kerberoasting, ticket forgery, delegation abuse etc.), consulte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Use esta página como o índice de **visão geral / “o que mudou recentemente”** e depois acesse as páginas dedicadas a [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ou [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas recentes sobre ataques (2024-2026)
- **O hardening do RC4 alterou os padrões, não o Kerberos em si** – o hardening moderno dos DCs se concentra nos **tipos de criptografia assumidos por padrão** para contas que não definem explicitamente `msDS-SupportedEncryptionTypes`. Após o rollout de 2026, essas contas passam cada vez mais a usar **AES-only** por padrão em DCs corrigidos, portanto as suposições cegas de Kerberoast com `/rc4` falham com mais frequência. No entanto, contas de serviço **explicitamente habilitadas para RC4 continuam sendo excelentes alvos para cracking offline**.
- **A aplicação da validação do PAC é importante para forged tickets** – o hardening das assinaturas PAC de 2024 significa que abusos no estilo **golden/diamond/sapphire/extraSID** precisam de dados PAC mais realistas e do contexto correto de assinatura. Domínios sem patches ou mantidos em implantações de compatibilidade/auditoria continuam sendo alvos mais fáceis.
- **O Kerberos baseado em certificados mudou duas vezes**:
- O **Strong certificate binding** (linha do tempo do KB5014754) torna mapeamentos negligentes de certificado para conta menos confiáveis em ambientes totalmente aplicados.
- O **CVE-2025-26647** adicionou outra camada de hardening em torno dos mapeamentos de certificados **altSecID / SKI**. Se os DCs não tiverem patches, ainda estiverem em modo de auditoria ou ignorarem explicitamente a validação do NTAuth, o abuso subsequente de pass-the-certificate / shadow-credential continua mais prático.
- **O abuso de delegation entre domínios/florestas continua muito ativo** – o Windows oferece suporte a fluxos modernos de **S4U2Self/S4U2Proxy** entre realms, portanto atributos de delegation graváveis em outro domínio continuam valiosos. O bloqueio normalmente está na fidelidade das ferramentas e nos detalhes de trust/policy, não no suporte do protocolo.
- **A RBCD recursiva em múltiplos domínios é operacionalmente importante** – em florestas com 3 ou mais domínios, **S4U2Self/S4U2Proxy** pode recorrer através de trust referrals, e o abuso **SPN-less** pode exigir um salto final de **`S4U2Self+U2U`**, além de manipulação de tickets dependente de RC4. Consulte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- O **Windows Server 2025 introduziu uma nova superfície de ataque adjacente ao Kerberos** por meio da lógica de migração do **dMSA**. Se você encontrar direitos delegados sobre OUs ou objetos de contas de serviço em um domínio 2025, consulte a [página dedicada ao BadSuccessor](acl-persistence-abuse/BadSuccessor.md) em vez de tratá-lo como “apenas mais um gMSA”.

## Verificações rápidas para operadores em domínios modernos

Antes de escolher um caminho de ataque Kerberos, responda rapidamente a quatro perguntas:

1. **Quais contas ainda são compatíveis com RC4?**
2. **Quais usuários não exigem pre-auth?**
3. **Quais objetos expõem possibilidades de delegation abuse?**
4. **Quais partes do domínio são recentes o suficiente para aplicar o hardening mais atual?**
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
- Se as contas **SPN interessantes forem explicitamente compatíveis com RC4**, o Kerberoasting continua barato e rápido.
- Se a maioria das contas de serviço **não tiver nenhuma configuração explícita de etype**, espere um comportamento **somente AES** em DCs atualizados de 2026 e planeje um cracking offline mais lento ou um caminho diferente.
- Se **RBCD / KCD / unconstrained delegation** estiver presente, o S4U geralmente é mais eficaz do que brute-force.
- Se a **autenticação por certificado** estiver em uso, lembre-se de que uma falha no caminho PKINIT **nem sempre significa que o certificado é inútil**; em muitos ambientes, o mesmo certificado ainda funciona para abuso de **Schannel/LDAPS** (consulte [Certificados AD / abuso de PKINIT](ad-certificates.md)).

## Erros comuns do Kerberos que alteram o plano de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → A conta-alvo / DC não usará o tipo de criptografia solicitado. Pare de tentar somente com RC4; forneça **chaves AES** ou solicite material de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Você provavelmente tem a **chave de serviço errada**, o **SPN errado** ou um ticket forjado que não corresponde à conta de serviço que realmente o está descriptografando.
- **`KRB_AP_ERR_SKEW`** → Seu horário está incorreto. Sincronize com o DC antes de investigar qualquer outra coisa.
- **`KDC_ERR_BADOPTION`** durante fluxos de S4U / delegation → frequentemente significa **usuários sensíveis/não delegáveis**, o modelo de delegation incorreto ou que você está tentando usar **KCD clássico**, quando somente **RBCD** aceitaria um ticket S4U2Self não encaminhável.

## Referências
- [Microsoft Learn - Detectar e corrigir o uso de RC4 no Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Orientações mais recentes de hardening do Windows e datas importantes](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
