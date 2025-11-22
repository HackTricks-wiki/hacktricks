# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

Comme un golden ticket, un diamond ticket est un TGT qui peut être utilisé pour accéder à n'importe quel service en tant que n'importe quel utilisateur. Un golden ticket est forgé complètement hors ligne, chiffré avec le hash krbtgt de ce domaine, puis injecté dans une session de connexion pour être utilisé. Parce que les contrôleurs de domaine ne suivent pas les TGT qu'ils ont légitimement émis, ils accepteront volontiers des TGT chiffrés avec leur propre hash krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

- Rechercher des TGS-REQ sans AS-REQ correspondant.
- Rechercher des TGTs avec des valeurs absurdes, comme la durée de vie par défaut de 10 ans utilisée par Mimikatz.

Un diamond ticket est fabriqué en modifiant les champs d'un TGT légitime qui a été émis par un DC. Cela se réalise en demandant un TGT, en le déchiffrant avec le hash krbtgt du domaine, en modifiant les champs désirés du ticket, puis en le rechiffrant. Cela surmonte les deux limitations mentionnées précédemment parce que :

- Les TGS-REQ auront une AS-REQ préalable.
- Le TGT a été émis par un DC, ce qui signifie qu'il contiendra tous les détails corrects issus de la politique Kerberos du domaine. Même si ces éléments peuvent être correctement forgés dans un golden ticket, c'est plus complexe et sujet aux erreurs.

### Requirements & workflow

- Cryptographic material : la clé AES256 krbtgt (préférée) ou le hash NTLM pour pouvoir déchiffrer et ré-signer le TGT.
- Legitimate TGT blob : obtenu avec `/tgtdeleg`, `asktgt`, `s4u`, ou en exportant des tickets depuis la mémoire.
- Context data : le RID de l'utilisateur cible, les RIDs/SIDs des groupes, et (optionnellement) des attributs PAC dérivés de LDAP.
- Service keys (only if you plan to re-cut service tickets) : clé AES du SPN de service à usurper.

1. Obtenir un TGT pour n'importe quel utilisateur contrôlé via AS-REQ (Rubeus `/tgtdeleg` est pratique car il contraint le client à effectuer le Kerberos GSS-API dance sans credentials).
2. Déchiffrer le TGT retourné avec la clé krbtgt, patcher les attributs PAC (user, groups, logon info, SIDs, device claims, etc.).
3. Re-chiffrer/signer le ticket avec la même clé krbtgt et l'injecter dans la session de connexion courante (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionnellement, répéter le processus sur un service ticket en fournissant un TGT blob valide plus la clé du service cible afin de rester discret sur le réseau.

### Updated Rubeus tradecraft (2024+)

Des travaux récents par Huntress ont modernisé l'action `diamond` dans Rubeus en important les améliorations `/ldap` et `/opsec` qui existaient auparavant uniquement pour les golden/silver tickets. `/ldap` remplit désormais automatiquement des attributs PAC précis directement depuis AD (user profile, logon hours, sidHistory, domain policies), tandis que `/opsec` rend le flux AS-REQ/AS-REP indiscernable d'un client Windows en effectuant la séquence de pré-auth en deux étapes et en n'autorisant que la crypto AES. Cela réduit drastiquement les indicateurs évidents tels que des device IDs vides ou des fenêtres de validité irréalistes.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (avec optionnel `/ldapuser` & `/ldappassword`) interroge AD et SYSVOL pour répliquer les données de politique PAC de l'utilisateur cible.
- `/opsec` force une tentative AS-REQ de type Windows, remet à zéro les flags bruyants et s'en tient à AES256.
- `/tgtdeleg` évite d'avoir à manipuler le mot de passe en clair ou la clé NTLM/AES de la victime, tout en renvoyant un TGT déchiffrable.

### Service-ticket recutting

La même mise à jour de Rubeus a ajouté la capacité d'appliquer la technique diamond aux blobs TGS. En fournissant à `diamond` un **base64-encoded TGT** (provenant de `asktgt`, `/tgtdeleg`, ou d'un TGT forgé précédemment), le **service SPN**, et la **service AES key**, vous pouvez générer des service tickets réalistes sans toucher le KDC — en pratique un silver ticket plus discret.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé de compte de service (par ex., dumpée avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous souhaitez forger un TGS ponctuel qui correspond parfaitement à la politique AD, aux durées et aux données PAC sans émettre de nouveau trafic AS/TGS.

### OPSEC & notes de détection

- Les heuristiques traditionnelles des hunters (TGS sans AS, durées de vie d'une décennie) s'appliquent toujours aux golden tickets, mais les diamond tickets apparaissent principalement lorsque le **contenu du PAC ou le mappage des groupes semble impossible**. Remplissez chaque champ du PAC (logon hours, user profile paths, device IDs) afin que les comparaisons automatisées ne signalent pas immédiatement la falsification.
- **N'attribuez pas trop de groupes/RIDs**. Si vous n'avez besoin que de `512` (Domain Admins) et `519` (Enterprise Admins), contentez-vous de cela et assurez-vous que le compte cible appartient de façon plausible à ces groupes ailleurs dans AD. Des `ExtraSids` excessifs trahissent la supercherie.
- Le projet Security Content de Splunk distribue la télémétrie d'attack-range pour les diamond tickets ainsi que des détections telles que *Windows Domain Admin Impersonation Indicator*, qui corrèle des séquences inhabituelles d'Event ID 4768/4769/4624 et des changements de groupes PAC. Rejouer ce jeu de données (ou générer le vôtre avec les commandes ci-dessus) aide à valider la couverture SOC pour T1558.001 tout en vous fournissant une logique d'alerte concrète à contourner.

## Références

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
