# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un golden ticket est entièrement forgé hors ligne, chiffré avec le hash krbtgt de ce domaine, puis injecté dans une session de connexion pour être utilisé. Comme les contrôleurs de domaine ne suivent pas les TGT qu'ils ont émis légitimement, ils acceptent volontiers les TGT chiffrés avec leur propre hash krbtgt.<sup>[[1]](#references)</sup>

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

- Rechercher des TGS-REQ sans AS-REQ correspondant.
- Rechercher des TGT contenant des valeurs aberrantes, comme la durée de validité par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d'un TGT légitime émis par un DC**. Cela est réalisé en **demandant** un **TGT**, en le **déchiffrant** avec le hash krbtgt du domaine, en **modifiant** les champs souhaités du ticket, puis en le **rechiffrant**. Cela **résout les deux lacunes susmentionnées** d'un golden ticket, car :<sup>[[1]](#references)</sup>

- Les TGS-REQ seront précédés d'un AS-REQ.
- Le TGT a été émis par un DC, ce qui signifie qu'il contient tous les détails corrects provenant de la stratégie Kerberos du domaine. Même si ces éléments peuvent être forgés avec précision dans un golden ticket, le processus est plus complexe et davantage sujet aux erreurs.

### Requirements & workflow

- **Matériel cryptographique** : la clé AES256 krbtgt (à privilégier) ou le hash NTLM afin de déchiffrer et de re-signer le TGT.
- **Blob TGT légitime** : obtenu avec `/tgtdeleg`, `asktgt`, `s4u`, ou en exportant les tickets depuis la mémoire.
- **Données de contexte** : le RID de l'utilisateur cible, les RIDs/SIDs des groupes et, éventuellement, les attributs PAC obtenus via LDAP.
- **Clés de service** (uniquement si vous prévoyez de recréer des tickets de service) : la clé AES du SPN de service à usurper.

1. Obtenir un TGT pour n'importe quel utilisateur contrôlé via AS-REQ (`/tgtdeleg` de Rubeus est pratique, car il contraint le client à effectuer l'échange Kerberos GSS-API sans identifiants).
2. Déchiffrer le TGT renvoyé avec la clé krbtgt, puis modifier les attributs PAC (utilisateur, groupes, informations de connexion, SIDs, claims de périphérique, etc.).
3. Rechiffrer et signer le ticket avec la même clé krbtgt, puis l'injecter dans la session de connexion actuelle (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facultativement, répéter le processus sur un ticket de service en fournissant un blob TGT valide ainsi que la clé du service cible afin de rester furtif sur le réseau.

### Updated Rubeus tradecraft (2024+)

Des travaux récents de Huntress ont modernisé l'action `diamond` de Rubeus en y intégrant les améliorations `/ldap` et `/opsec`, qui n'existaient auparavant que pour les golden/silver tickets. `/ldap` récupère désormais le contexte PAC réel en interrogeant LDAP **et** en montant SYSVOL afin d'extraire les attributs des comptes/groupes ainsi que la stratégie Kerberos/de mots de passe (par exemple, `GptTmpl.inf`), tandis que `/opsec` fait correspondre le flux AS-REQ/AS-REP à celui de Windows en effectuant l'échange de pré-authentification en deux étapes et en imposant AES uniquement ainsi que des KDCOptions réalistes. Cela réduit considérablement les indicateurs évidents tels que les champs PAC manquants ou les durées de validité incompatibles avec la stratégie.<sup>[[3]](#references)</sup>
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
- `/ldap` (avec `/ldapuser` et `/ldappassword` facultatifs) interroge AD et SYSVOL afin de reproduire les données de stratégie PAC de l'utilisateur cible.
- `/opsec` force une nouvelle tentative d'AS-REQ similaire à celle de Windows, en mettant à zéro les flags bruyants et en s'en tenant à AES256.
- `/tgtdeleg` évite de manipuler le mot de passe en clair ou la clé NTLM/AES de la victime, tout en renvoyant un TGT déchiffrable.

### Re-découpage des tickets de service

La même mise à jour de Rubeus a ajouté la possibilité d'appliquer la diamond technique aux blobs TGS. En fournissant à `diamond` un **TGT encodé en base64** (provenant de `asktgt`, de `/tgtdeleg` ou d'un TGT précédemment forgé), le **SPN du service** et la **clé AES du service**, vous pouvez créer des tickets de service réalistes sans interagir avec le KDC, ce qui revient à utiliser un silver ticket plus furtif.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé de compte de service (par exemple, extraite avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous souhaitez générer un TGS ponctuel qui respecte parfaitement la politique AD, les timelines et les données PAC, sans générer de nouveau trafic AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Une variante plus récente, parfois appelée **sapphire ticket**, combine la base « real TGT » de Diamond avec **S4U2self+U2U** afin de voler un PAC privilégié et de l'insérer dans votre propre TGT. Au lieu d'inventer des SIDs supplémentaires, vous demandez un ticket U2U S4U2self pour un utilisateur hautement privilégié, avec un `sname` ciblant le demandeur peu privilégié ; le KRB_TGS_REQ transporte le TGT du demandeur dans `additional-tickets` et définit `ENC-TKT-IN-SKEY`, ce qui permet de déchiffrer le service ticket avec la clé de cet utilisateur. Vous extrayez ensuite le PAC privilégié et l'insérez dans votre TGT légitime avant de le re-signer avec la clé krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Le `ticketer.py` d'Impacket prend désormais en charge sapphire via `-impersonate` + `-request` (échange live avec le KDC) :<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepte un nom d’utilisateur ou un SID ; `-request` nécessite des identifiants utilisateur actifs ainsi que le matériel de clé krbtgt (AES/NTLM) pour déchiffrer et modifier les tickets.

Principaux indices OPSEC lors de l’utilisation de cette variante :<sup>[[5]](#references)</sup>

- Le TGS-REQ contiendra `ENC-TKT-IN-SKEY` et `additional-tickets` (le TGT de la victime) — une combinaison rare dans le trafic normal.
- `sname` est souvent égal à l’utilisateur qui effectue la requête (accès self-service), et l’Event ID 4769 montre l’appelant et la cible comme étant le même SPN/utilisateur.
- Attendez-vous à des entrées 4768/4769 appariées avec le même ordinateur client, mais des CNAMES différents (demandeur à faibles privilèges contre propriétaire privilégié du PAC).

### OPSEC et notes de détection

- Les heuristiques traditionnelles des hunters (TGS sans AS, durées de vie de plusieurs décennies) s’appliquent toujours aux golden tickets, mais les diamond tickets apparaissent principalement lorsque le **contenu du PAC ou le mappage des groupes semble impossible**. Remplissez chaque champ du PAC (heures de connexion, chemins des profils utilisateur, identifiants des appareils) afin que les comparaisons automatisées ne détectent pas immédiatement la falsification.<sup>[[3]](#references)</sup>
- **N’ajoutez pas trop de groupes/RIDs**. Si vous avez uniquement besoin de `512` (Domain Admins) et `519` (Enterprise Admins), arrêtez-vous là et assurez-vous que le compte cible appartient de manière plausible à ces groupes ailleurs dans AD. Un nombre excessif d’`ExtraSids` est un indice évident.
- Les swaps de type Sapphire laissent des empreintes U2U : `ENC-TKT-IN-SKEY` + `additional-tickets`, ainsi qu’un `sname` pointant vers un utilisateur (souvent le demandeur) dans 4769, puis une ouverture de session 4624 provenant du ticket falsifié. Corrélez ces champs au lieu de rechercher uniquement les absences de requêtes no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft a commencé à supprimer progressivement l’émission de **tickets de service RC4** en raison de CVE-2026-20833 ; imposer des etypes AES uniquement sur le KDC renforce le domaine et s’aligne sur les outils diamond/sapphire (`/opsec` force déjà AES). Mélanger RC4 dans des PAC falsifiés deviendra de plus en plus visible.<sup>[[6]](#references)</sup>
- Le projet Security Content de Splunk distribue des données de télémétrie d’attack-range pour les diamond tickets, ainsi que des détections telles que *Windows Domain Admin Impersonation Indicator*, qui corrèlent des séquences inhabituelles d’Event ID 4768/4769/4624 et des changements de groupes dans le PAC. Rejouer ce jeu de données (ou en générer un avec les commandes ci-dessus) aide à valider la couverture du SOC pour T1558.001, tout en vous fournissant une logique d’alerte concrète à contourner.<sup>[[4]](#references)</sup>

## Références

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
