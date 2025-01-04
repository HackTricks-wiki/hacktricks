# Delegação Não Restrita

{{#include ../../banners/hacktricks-training.md}}

## Delegação não restrita

Esta é uma funcionalidade que um Administrador de Domínio pode definir para qualquer **Computador** dentro do domínio. Assim, sempre que um **usuário fizer login** no Computador, uma **cópia do TGT** desse usuário será **enviada dentro do TGS** fornecido pelo DC **e salva na memória no LSASS**. Portanto, se você tiver privilégios de Administrador na máquina, poderá **extrair os tickets e se passar pelos usuários** em qualquer máquina.

Assim, se um administrador de domínio fizer login em um Computador com a funcionalidade "Delegação Não Restrita" ativada, e você tiver privilégios de administrador local nessa máquina, poderá extrair o ticket e se passar pelo Administrador de Domínio em qualquer lugar (privesc de domínio).

Você pode **encontrar objetos de Computador com esse atributo** verificando se o atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contém [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Você pode fazer isso com um filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:

<pre class="language-bash"><code class="lang-bash"># Listar computadores não restritos
## Powerview
Get-NetComputer -Unconstrained #DCs sempre aparecem, mas não são úteis para privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Exportar tickets com Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Forma recomendada
kerberos::list /export #Outra forma

# Monitorar logins e exportar novos tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Verificar a cada 10s por novos TGTs</code></pre>

Carregue o ticket de Administrador (ou usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais informações: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre Delegação Não Restrita em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Forçar Autenticação**

Se um atacante conseguir **comprometer um computador permitido para "Delegação Não Restrita"**, ele poderia **enganar** um **servidor de impressão** para **fazer login automaticamente** contra ele **salvando um TGT** na memória do servidor.\
Então, o atacante poderia realizar um **ataque Pass the Ticket para se passar** pela conta de computador do usuário do servidor de impressão.

Para fazer um servidor de impressão fazer login em qualquer máquina, você pode usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT for de um controlador de domínio, você pode realizar um [**ataque DCSync**](acl-persistence-abuse/index.html#dcsync) e obter todos os hashes do DC.\
[**Mais informações sobre este ataque em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Aqui estão outras maneiras de tentar forçar uma autenticação:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigação

- Limitar logins de DA/Admin a serviços específicos
- Definir "Conta é sensível e não pode ser delegada" para contas privilegiadas.

{{#include ../../banners/hacktricks-training.md}}
