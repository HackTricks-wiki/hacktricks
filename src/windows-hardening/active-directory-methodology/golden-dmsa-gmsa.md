# Golden gMSA/dMSA Attack (Derivação Offline de Senhas de Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Windows Managed Service Accounts são principals de domínio destinados a executar serviços sem que um administrador precise gerenciar uma senha de longa duração:

1. **gMSA** (group Managed Service Account) pode ser usado pelos computadores autorizados por meio de `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) foi introduzido no **Windows Server 2025**. Ele vincula a autenticação normal às identidades de máquinas autorizadas e pode substituir uma service account legada por meio de um fluxo de migração.

Não confunda **Golden dMSA** com **BadSuccessor**. Golden dMSA exige o comprometimento do material da root key do KDS e deriva as chaves das managed accounts; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md), por outro lado, explora o controle de um objeto dMSA e seus atributos de migração.

Um DC não armazena uma senha em texto claro gerada independentemente para cada gMSA. Ele deriva a senha da conta a partir de uma **KDS root key**, de uma chave Group Key Distribution Protocol (GKDI) indexada por tempo e do SID da conta. Os objetos de root key são objetos `msKds-ProvRootKey` abaixo de `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; o valor sensível é `msKds-RootKeyData`. `msDS-ManagedPasswordId` **não é um GUID**: é um identificador de chave binário que contém o GUID da root key do KDS, os índices `L0`/`L1`/`L2` do GKDI e metadados do domínio/forest. O DC aplica o KDF com o label `GMSA PASSWORD` e o SID binário como contexto, então expõe um `MSDS-MANAGEDPASSWORD_BLOB` somente aos principals autorizados a recuperar uma senha de gMSA.<sup>[[2]](#references)</sup>

Uma dMSA normalmente difere operacionalmente: seu secret deve permanecer no DC, e o KDC emite credenciais para uma máquina autorizada. No entanto, dMSAs reutilizam a derivação de senha subjacente do KDS/GKDI. Golden dMSA reconstrói esse secret diretamente e, portanto, contorna o fluxo pretendido vinculado à máquina e o Credential Guard no host do serviço.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Após extrair uma KDS root key, um atacante pode derivar senhas para contas vinculadas a essa chave sem ler `msDS-ManagedPassword`. Isso contorna a ACL de recuperação de senha por conta e permanece eficaz após rotações comuns de managed passwords enquanto a root key comprometida continuar em uso. Para gMSAs, o `msDS-ManagedPasswordId`, que pode ser lido, normalmente fornece o identificador exato da chave. Para dMSAs com ACL restrita, Golden dMSA reduz o identificador ausente a apenas **1.024 candidatos**.<sup>[[1]](#references)[[2]](#references)</sup>

### Pré-requisitos

* O objeto de KDS root key relevante, geralmente obtido com direitos de Enterprise Admin / Domain Admin da forest root, `SYSTEM` em um DC ou a partir de um banco de dados ou backup de DC exposto.<sup>[[1]](#references)[[2]](#references)</sup>
* O SID, o domínio DNS, o nome da forest e o `sAMAccountName` da conta-alvo.<sup>[[1]](#references)[[2]](#references)</sup>
* Para a computação direta de gMSA, seu `msDS-ManagedPasswordId` codificado em base64; para Golden dMSA, isso pode ser adivinhado.<sup>[[1]](#references)[[2]](#references)</sup>
* Um host Windows x64 com .NET Framework 4.7.2 para [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Fase 1 - Extrair a KDS root key

`GoldenDMSA` e [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) exportam os campos do objeto de root key como um blob em base64. Sem um argumento de domínio, as ferramentas consultam a forest root e exigem acesso privilegiado adequado ao diretório. Com o argumento de domínio/forest, `SYSTEM` em um DC pode consultar a réplica local desse DC do naming context de Configuration.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Registre o GUID da root key e o blob da root key em base64. Uma exportação das hives `SECURITY`/`SYSTEM` do Registry, por si só, não é a root key do KDS: o material autoritativo está na partição de Configuração do AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Fase 2 - Enumerar objetos gMSA / dMSA

Para gMSAs, obtenha `sAMAccountName`, `objectSid` e o `msDS-ManagedPasswordId` binário. Este último normalmente pode ser lido mesmo quando o caller não tem permissão para recuperar `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
A ACL padrão de um dMSA pode impedir a enumeração LDAP por usuários com poucos privilégios. `GoldenDMSA info` pode consultar o LDAP ou enumerar RIDs candidatos e resolver SIDs por meio de `LsaLookupSids` sobre `\PIPE\lsarpc`, distinguindo então dMSAs de contas de computador e gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Fase 3 - Reconstruct or guess `msDS-ManagedPasswordId`

O identificador de chave inclui `L0Index`, `L1Index` e `L2Index`, não um timestamp de criação da conta seguido por bits aleatórios. A Semperis descobriu que o caminho de geração de senha não consome o `L0Index` candidato, enquanto `L1Index` e `L2Index` estão limitados individualmente aos valores `0..31`. Consequentemente, um atacante que conheça o GUID da root-key, o domínio, a forest e o SID pode construir todos os `32 * 32 = 1,024` identificadores candidatos.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
As derivações são offline, mas identificar o candidato ativo geralmente requer tentativas de autenticação. Isso pode produzir uma sequência de falhas de pré-autenticação Kerberos ou validação NTLM antes que a chave válida seja encontrada. Para chaves Kerberos AES, o salt da conta gerenciada usado pela ferramenta é `UPPERCASE.DNS.DOMAIN` + `host` + o UPN da conta em minúsculas, sem o `$` final (por exemplo, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Fase 4 - Calcular e usar a senha

Se o identificador exato for conhecido, calcule o buffer de senha de 256 bytes e converta-o em material NTLM/AES. O valor base64 exibido por essas ferramentas é o buffer de senha codificado, **não** o próprio `MSDS-MANAGEDPASSWORD_BLOB` do LDAP.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
O resultado NTLM pode ser usado onde NTLM é aceito; a chave AES pode ser usada para overpass-the-hash / solicitações de TGT quando a conta gerenciada é somente AES. Isso fornece os privilégios, SPNs, configuração de delegation e acesso a recursos da managed service account comprometida, sem adicionar a máquina do atacante a `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Abuso da partição Configuration entre domínios

Os objetos de chave-raiz KDS residem no contexto de nomenclatura Configuration da forest, que é replicado para os DCs em child domains. Consequentemente, `SYSTEM` em um DC de child domain pode ler o material KDS da forest-root a partir da réplica local do child DC, mesmo que os Domain Admins do child domain não possam ler o objeto diretamente de um forest-root DC. Se o atacante também puder ler o `msDS-ManagedPasswordId` de uma gMSA do parent domain, o GoldenGMSA poderá calcular a senha dessa conta parent; o SID filtering não impede esse ataque criptográfico.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Detecção, Contenção e Recuperação

* Configure uma SACL no contêiner **Master Root Keys**, herdada por objetos `msKds-ProvRootKey`, para leituras bem-sucedidas de `msKds-RootKeyData`. Com a auditoria de acesso ao serviço de diretório habilitada, uma extração online produz o evento de Segurança **4662**; investigue sujeitos que não sejam DCs esperados ou operadores Tier-0. Audite também alterações nessas SACLs e nas ACLs dos objetos de root key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Um ataque de filho para pai lê o objeto KDS da réplica local do DC filho comprometido, portanto o domínio forest-root pode não observar essa leitura. No domínio pai, audite leituras bem-sucedidas de `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) em objetos `msDS-GroupManagedServiceAccount` e investigue leituras realizadas por principals de outro domínio.<sup>[[5]](#references)</sup>
* Correlacione o acesso a objetos KDS com logons incomuns de managed accounts e picos de falhas Kerberos/NTLM para service accounts com sufixo `$`. A computação offline após o roubo prévio do banco de dados ou de backups não é visível para um DC ativo.<sup>[[1]](#references)[[3]](#references)</sup>
* A rotação comum de senha não é suficiente após a exposição de uma root key. O procedimento de recuperação atual da Microsoft cria uma nova KDS root key, reinicia o KDS em todos os DCs relevantes e move as contas afetadas para essa key. Se o escopo/período da exposição for desconhecido e esperar por um roll seguro for inaceitável, substitua cada gMSA que usou a key comprometida; se o escopo for conhecido, a Microsoft documenta um workflow de authoritative restore para forçar um rolling seguro. Valide o novo GUID da key em `msDS-ManagedPasswordId` antes de excluir a key antiga.<sup>[[4]](#references)</sup>
* Trate o acesso ao banco de dados e aos backups dos DCs, a replicação da partição Configuration e a administração de KDS root keys como Tier-0. Reduzir `ManagedPasswordIntervalInDays` limita algumas janelas de recuperação, mas não revoga uma root key já comprometida.<sup>[[4]](#references)</sup>

## Ferramentas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumeração de dMSA/gMSA, geração de identificadores, validação de 1.024 candidatos, computação de senha e conversão NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - enumeração de gMSA/KDS e computação de senha online, offline e cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) e [`Impacket`](https://github.com/fortra/impacket) - use ou valide as chaves NTLM/AES derivadas em testes autorizados.



## References

- [1] [Golden dMSA - bypass de autenticação para Managed Service Accounts delegadas](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Ataques de gMSA no Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repositório do Semperis/GoldenDMSA no GitHub](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Como se recuperar de um ataque Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter como limite de segurança entre domínios? Parte 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
