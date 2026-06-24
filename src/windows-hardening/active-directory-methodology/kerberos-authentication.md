# Autenticação Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Confira o post incrível de:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR para atacantes
- Kerberos é o protocolo de autenticação padrão do AD; a maioria das cadeias de lateral movement vai tocá-lo.
- Pense em **três fases operacionais**:
- **AS-REQ / AS-REP** → senha/hash/certificado para obter um **TGT**. É aqui que vivem **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, e **PKINIT**.
- **TGS-REQ / TGS-REP** → use um TGT para obter **service tickets**. É aqui que entram **Kerberoasting**, **abuse de S4U**, **abuse de delegation**, e a maior parte do **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → apresente o ticket ao serviço. É aqui que acontecem **pass-the-ticket** e o lateral movement específico do serviço.
- Para cheatsheets práticas (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.) veja:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Use esta página como índice de **visão geral / “o que mudou recentemente”**, e depois vá para as páginas dedicadas de [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), ou [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notas rápidas de ataque (2024-2026)
- **O hardening do RC4 mudou os padrões, não o Kerberos em si** – o hardening moderno de DCs foca nos **tipos de criptografia assumidos por padrão** para contas que **não** definem explicitamente `msDS-SupportedEncryptionTypes`. Após o rollout de 2026, essas contas passam cada vez mais a usar o padrão **AES-only** em DCs corrigidos, então suposições cegas de `/rc4` para Kerberoast falham com mais frequência. No entanto, **contas de serviço explicitamente habilitadas para RC4 continuam sendo alvos excelentes para crack offline**.
- **A enforcement da validação do PAC importa para tickets forjados** – o hardening da assinatura do PAC em 2024 significa que abusos do tipo **golden/diamond/sapphire/extraSID** precisam de dados de PAC mais realistas e do contexto correto de assinatura. Domínios não corrigidos ou domínios deixados em deployments de compatibilidade/auditoria continuam sendo alvos mais fracos.
- **Kerberos baseado em certificado mudou duas vezes**:
- **Strong certificate binding** (linha do tempo do KB5014754) torna mapeamentos mal feitos entre certificado e conta menos confiáveis em ambientes totalmente enforced.
- **CVE-2025-26647** adicionou outra camada de hardening em torno de mapeamentos de certificado **altSecID / SKI**. Se os DCs não estiverem corrigidos, ainda estiverem em modo de auditoria, ou estiverem explicitamente contornando a validação NTAuth, o abuso subsequente de pass-the-certificate / shadow-credential continua mais prático.
- **Abuse de delegation cross-domain / cross-forest ainda está muito vivo** – o Windows suporta fluxos modernos cross-realm **S4U2Self/S4U2Proxy**, então atributos de delegation graváveis em outro domínio ainda são valiosos. O bloqueio normalmente é a fidelidade das ferramentas e detalhes de trust/policy, não o suporte do protocolo.
- **Windows Server 2025 introduziu nova superfície de ataque adjacente ao Kerberos** por meio da lógica de migração de **dMSA**. Se você vir direitos delegados sobre OUs ou objetos de service account em um domínio 2025, confira a página dedicada [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) em vez de tratar isso como “apenas mais um gMSA”.

## Checagens rápidas de operador em domínios modernos

Antes de escolher um caminho de ataque Kerberos, responda rapidamente a quatro perguntas:

1. **Quais contas ainda são compatíveis com RC4?**
2. **Quais usuários não exigem pre-auth?**
3. **Quais objetos expõem abuse de delegation?**
4. **Quais partes do domínio são novas o suficiente para impor o hardening recente?**
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
- Se **contas SPN interessantes forem explicitamente compatíveis com RC4**, Kerberoasting continua barato e rápido.
- Se a maioria das contas de serviço tiver **sem configuração explícita de etype**, espere comportamento **somente AES** em DCs atualizados de 2026 e planeje cracking offline mais lento ou um caminho diferente.
- Se houver **RBCD / KCD / unconstrained delegation**, o S4U frequentemente supera brute-force.
- Se a **autenticação por certificado** estiver em uso, lembre que uma falha no caminho PKINIT nem sempre significa que o certificado é inútil; em muitos ambientes, o mesmo certificado ainda funciona para abuso de **Schannel/LDAPS** (veja [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erros comuns do Kerberos que mudam o plano de ataque
- **`KDC_ERR_ETYPE_NOTSUPP`** → A conta / DC alvo não usará o tipo de criptografia que você pediu. Pare de insistir só com RC4; forneça **chaves AES** ou solicite material de roast **AES** em vez disso.
- **`KRB_AP_ERR_MODIFIED`** → Você provavelmente tem a **chave de serviço errada**, o **SPN errado**, ou um ticket forjado que não corresponde à conta de serviço que realmente o está descriptografando.
- **`KRB_AP_ERR_SKEW`** → Seu horário está errado. Sincronize com o DC antes de depurar qualquer outra coisa.
- **`KDC_ERR_BADOPTION`** durante fluxos S4U / delegation → frequentemente significa **usuários sensíveis/não delegáveis**, o modelo de delegation errado, ou que você está tentando fazer **KCD clássico** onde apenas **RBCD** aceitaria um ticket S4U2Self não encaminhável.

## Referências
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
