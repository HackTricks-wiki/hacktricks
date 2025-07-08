# Abusando de ACLs/ACEs do Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Contas de Serviço Gerenciadas Delegadas (**dMSAs**) são um novo tipo de principal do AD introduzido com **Windows Server 2025**. Elas foram projetadas para substituir contas de serviço legadas, permitindo uma “migração” com um clique que copia automaticamente os Nomes de Principal de Serviço (SPNs), associações de grupo, configurações de delegação e até mesmo chaves criptográficas da conta antiga para a nova dMSA, proporcionando uma transição suave para as aplicações e eliminando o risco de Kerberoasting.

Pesquisadores da Akamai descobriram que um único atributo — **`msDS‑ManagedAccountPrecededByLink`** — informa ao KDC qual conta legada uma dMSA “sucede”. Se um atacante puder escrever esse atributo (e alternar **`msDS‑DelegatedMSAState` → 2**), o KDC construirá um PAC que **herda todos os SIDs da vítima escolhida**, permitindo efetivamente que a dMSA se passe por qualquer usuário, incluindo Administradores de Domínio.

## O que exatamente é uma dMSA?

* Construída sobre a tecnologia **gMSA**, mas armazenada como a nova classe AD **`msDS‑DelegatedManagedServiceAccount`**.
* Suporta uma **migração opt-in**: chamar `Start‑ADServiceAccountMigration` vincula a dMSA à conta legada, concede à conta legada acesso de gravação a `msDS‑GroupMSAMembership` e altera `msDS‑DelegatedMSAState` = 1.
* Após `Complete‑ADServiceAccountMigration`, a conta substituída é desativada e a dMSA se torna totalmente funcional; qualquer host que anteriormente usou a conta legada é automaticamente autorizado a obter a senha da dMSA.
* Durante a autenticação, o KDC incorpora uma dica **KERB‑SUPERSEDED‑BY‑USER** para que clientes Windows 11/24H2 tentem novamente de forma transparente com a dMSA.

## Requisitos para atacar
1. **Pelo menos um Windows Server 2025 DC** para que a classe LDAP dMSA e a lógica KDC existam.
2. **Quaisquer direitos de criação de objeto ou gravação de atributo em uma OU** (qualquer OU) – por exemplo, `Create msDS‑DelegatedManagedServiceAccount` ou simplesmente **Create All Child Objects**. A Akamai descobriu que 91% dos inquilinos do mundo real concedem tais permissões “benignas” de OU a não administradores.
3. Capacidade de executar ferramentas (PowerShell/Rubeus) de qualquer host associado ao domínio para solicitar tickets Kerberos.
*Nenhum controle sobre o usuário vítima é necessário; o ataque nunca toca a conta alvo diretamente.*

## Passo a passo: escalonamento de privilégios BadSuccessor

1. **Localize ou crie uma dMSA que você controla**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Como você criou o objeto dentro de uma OU que pode gravar, você possui automaticamente todos os seus atributos.

2. **Simule uma “migração concluída” em duas gravações LDAP**:
- Defina `msDS‑ManagedAccountPrecededByLink = DN` de qualquer vítima (por exemplo, `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Defina `msDS‑DelegatedMSAState = 2` (migração concluída).

Ferramentas como **Set‑ADComputer, ldapmodify**, ou até mesmo **ADSI Edit** funcionam; não são necessários direitos de administrador de domínio.

3. **Solicite um TGT para a dMSA** — Rubeus suporta a flag `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

O PAC retornado agora contém o SID 500 (Administrador) além dos grupos Administradores de Domínio/Administradores de Empresa.

## Coletar todas as senhas dos usuários

Durante migrações legítimas, o KDC deve permitir que a nova dMSA decifre **tickets emitidos para a conta antiga antes da transição**. Para evitar quebrar sessões ativas, ele coloca tanto as chaves atuais quanto as chaves anteriores dentro de um novo blob ASN.1 chamado **`KERB‑DMSA‑KEY‑PACKAGE`**.

Como nossa migração falsa afirma que a dMSA sucede a vítima, o KDC copiosamente copia a chave RC4‑HMAC da vítima para a lista de **chaves anteriores** – mesmo que a dMSA nunca tenha tido uma senha “anterior”. Essa chave RC4 não é salteada, portanto, é efetivamente o hash NT da vítima, dando ao atacante **capacidade de cracking offline ou “pass-the-hash”**.

Portanto, vincular em massa milhares de usuários permite que um atacante despeje hashes “em escala”, transformando **BadSuccessor em um primitivo de escalonamento de privilégios e comprometimento de credenciais**.

## Ferramentas

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Referências

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
