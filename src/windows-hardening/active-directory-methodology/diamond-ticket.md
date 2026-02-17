# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un golden ticket est forgé entièrement hors ligne, chiffré avec le krbtgt hash de ce domaine, puis injecté dans une session de connexion pour être utilisé. Parce que les domain controllers ne suivent pas les TGTs qu'ils ont légitimement émis, ils accepteront sans problème des TGTs chiffrés avec leur propre krbtgt hash.

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

- Rechercher des TGS-REQs qui n'ont pas d'AS-REQ correspondant.
- Rechercher des TGTs avec des valeurs absurdes, comme la durée de vie par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d'un TGT légitime émis par un DC**. Cela s'obtient en **demandant** un **TGT**, en le **déchiffrant** avec le krbtgt du domaine, en **modifiant** les champs désirés du ticket, puis en le **rechiffrant**. Cela **surmonte les deux faiblesses mentionnées précédemment** car :

- Les TGS-REQs auront une AS-REQ préalable.
- Le TGT a été émis par un DC, ce qui signifie qu'il contiendra tous les détails corrects issus de la politique Kerberos du domaine. Même si ces éléments peuvent être fidèlement forgés dans un golden ticket, c'est plus complexe et sujet aux erreurs.

### Exigences & workflow

- **Cryptographic material** : la clé krbtgt AES256 (préférée) ou le hash NTLM afin de déchiffrer et re-signer le TGT.
- **Legitimate TGT blob** : obtenu avec `/tgtdeleg`, `asktgt`, `s4u`, ou en exportant les tickets depuis la mémoire.
- **Context data** : le RID de l'utilisateur cible, les RIDs/SIDs des groupes, et (optionnellement) les attributs PAC dérivés de LDAP.
- **Service keys** (only if you plan to re-cut service tickets) : clé AES du SPN de service à usurper.

1. Obtenir un TGT pour n'importe quel utilisateur contrôlé via AS-REQ (Rubeus `/tgtdeleg` est pratique car il contraint le client à effectuer la séquence Kerberos GSS-API sans identifiants).
2. Déchiffrer le TGT retourné avec la clé krbtgt, modifier les attributs PAC (utilisateur, groupes, infos de connexion, SIDs, device claims, etc.).
3. Rechiffrer/signer le ticket avec la même clé krbtgt et l'injecter dans la session de connexion en cours (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionnellement, répéter le processus sur un service ticket en fournissant un TGT blob valide plus la clé du service cible pour rester discret sur le réseau.

### Updated Rubeus tradecraft (2024+)

Des travaux récents par Huntress ont modernisé l'action `diamond` dans Rubeus en important les améliorations `/ldap` et `/opsec` qui existaient auparavant uniquement pour golden/silver tickets. `/ldap` remplit maintenant automatiquement des attributs PAC précis directement depuis AD (profil utilisateur, logon hours, sidHistory, domain policies), tandis que `/opsec` rend le flux AS-REQ/AS-REP indiscernable d'un client Windows en effectuant la séquence de pré-auth en deux étapes et en imposant du crypto AES-only. Cela réduit drastiquement les indicateurs évidents tels que des device IDs vides ou des fenêtres de validité irréalistes.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (avec `/ldapuser` et `/ldappassword` optionnels) interroge AD et SYSVOL pour reproduire les données de politique PAC de l'utilisateur cible.
- `/opsec` force un réessai AS-REQ de type Windows, met à zéro les flags bruyants et s'en tient à AES256.
- `/tgtdeleg` évite d'exposer le mot de passe en clair ou la clé NTLM/AES de la victime tout en retournant un TGT déchiffrable.

### Recoupage de tickets de service

La même mise à jour de Rubeus a ajouté la capacité d'appliquer la diamond technique aux blobs TGS. En fournissant à `diamond` un **base64-encoded TGT** (depuis `asktgt`, `/tgtdeleg`, ou un TGT forgé précédemment), le **service SPN**, et la **service AES key**, vous pouvez générer des tickets de service réalistes sans toucher au KDC — en fait un silver ticket plus furtif.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé d'un compte de service (par ex. dumpée avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous voulez générer un TGS ponctuel qui correspond parfaitement à la politique AD, aux durées et aux données PAC sans émettre de nouveau trafic AS/TGS.

### Sapphire-style PAC swaps (2025)

Une variante plus récente, parfois appelée **sapphire ticket**, combine la base "real TGT" de Diamond avec **S4U2self+U2U** pour voler un PAC privilégié et l'insérer dans votre propre TGT. Au lieu d'inventer des SIDs supplémentaires, vous demandez un ticket U2U S4U2self pour un utilisateur à haut privilège, extrayez ce PAC, et le greffez dans votre TGT légitime avant de le re-signer avec la clé krbtgt. Parce que U2U définit `ENC-TKT-IN-SKEY`, le flux réseau résultant ressemble à un échange utilisateur-à-utilisateur légitime.

Reproduction minimale côté Linux avec le fork patché d'Impacket `ticketer.py` (ajoute le support sapphire) :
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ contiendra `ENC-TKT-IN-SKEY` et `additional-tickets` (le TGT de la victime) — rare dans le trafic normal.
- `sname` est souvent égal à l'utilisateur demandeur (accès en libre-service) et Event ID 4769 montre l'appelant et la cible comme le même SPN/utilisateur.
- Attendez des entrées appariées 4768/4769 avec le même ordinateur client mais des CNAMES différents (demandeur peu privilégié vs. propriétaire PAC privilégié).

### OPSEC & detection notes

- Les heuristiques traditionnelles des hunters (TGS without AS, durées de vie de plusieurs années) s'appliquent toujours aux golden tickets, mais les diamond tickets apparaissent principalement lorsque le **contenu du PAC ou le mapping de groupes semble impossible**. Remplissez chaque champ du PAC (heures de connexion, chemins de profil utilisateur, ID de périphérique) afin que les comparaisons automatisées ne signalent pas immédiatement la falsification.
- **Ne pas surabonner les groupes/RIDs**. Si vous n'avez besoin que de `512` (Domain Admins) et `519` (Enterprise Admins), arrêtez-vous là et assurez-vous que le compte ciblé appartient vraisemblablement à ces groupes ailleurs dans AD. Des `ExtraSids` excessifs trahissent la tentative.
- Les swaps de style Sapphire laissent des empreintes U2U : `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` dans 4769, et une connexion 4624 ultérieure provenant du ticket forgé. Corrélez ces champs au lieu de ne regarder que les écarts no-AS-REQ.
- Microsoft a commencé à supprimer progressivement l'**émission de RC4 service ticket** en raison de CVE-2026-20833 ; forcer uniquement AES comme etypes sur le KDC renforce le domaine et s'aligne avec les outils diamond/sapphire (/opsec force déjà AES). Mélanger RC4 dans des PAC forgés sera de plus en plus visible.
- Le projet Splunk's Security Content distribue la télémétrie d'attack-range pour les diamond tickets ainsi que des détections telles que *Windows Domain Admin Impersonation Indicator*, qui corrèle des séquences inhabituelles d'Event ID 4768/4769/4624 et des changements de groupes PAC. Rejouer ce dataset (ou générer le vôtre avec les commandes ci-dessus) aide à valider la couverture SOC pour T1558.001 tout en vous donnant une logique d'alerte concrète à contourner.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
