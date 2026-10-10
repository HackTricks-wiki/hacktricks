# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n’importe quel service en tant que n’importe quel utilisateur**. Un golden ticket est entièrement forgé hors ligne, chiffré avec le hash krbtgt du domaine, puis injecté dans une session d’ouverture de session pour être utilisé. Comme les contrôleurs de domaine ne suivent pas les TGT qu’ils ont (ou qu’ils) légitimement émis, ils accepteront volontiers les TGT chiffrés avec leur propre hash krbtgt.<sup>[[1]](#references)</sup>

Il existe deux techniques courantes pour détecter l’utilisation de golden tickets :

- Rechercher les TGS-REQ sans AS-REQ correspondant.
- Rechercher les TGT avec des valeurs aberrantes, comme la durée de vie par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d’un TGT légitime émis par un DC**. Pour cela, on **demande** un **TGT**, on le **déchiffre** avec le hash krbtgt du domaine, on **modifie** les champs souhaités du ticket, puis on le **chiffre à nouveau**. Cette technique **remédie aux deux inconvénients précités** d’un golden ticket, car :<sup>[[1]](#references)</sup>

- Les TGS-REQ seront précédés d’un AS-REQ.
- Le TGT a été émis par un DC, ce qui signifie qu’il contiendra tous les détails appropriés de la stratégie Kerberos du domaine. Même s’il est possible de les forger avec précision dans un golden ticket, cela est plus complexe et sujet aux erreurs.

### Prérequis et déroulement

- **Matériel cryptographique** : la clé AES256 krbtgt (de préférence) ou le hash NTLM, pour déchiffrer et signer à nouveau le TGT.
- **Blob TGT légitime** : obtenu avec `/tgtdeleg`, `asktgt`, `s4u` ou par l’exportation de tickets depuis la mémoire.
- **Données de contexte** : le RID de l’utilisateur cible, les RID/SID des groupes et, éventuellement, les attributs PAC obtenus via LDAP.
- **Clés de service** (uniquement si vous prévoyez de recréer des tickets de service) : clé AES du SPN du service à usurper.

1. Obtenir un TGT pour n’importe quel utilisateur contrôlé via AS-REQ (`/tgtdeleg` de Rubeus est pratique, car il contraint le client à effectuer l’échange Kerberos GSS-API sans identifiants).
2. Déchiffrer le TGT obtenu avec la clé krbtgt et modifier les attributs PAC (utilisateur, groupes, informations de connexion, SID, claims de périphérique, etc.).
3. Chiffrer et signer à nouveau le ticket avec la même clé krbtgt, puis l’injecter dans la session d’ouverture de session actuelle (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Facultativement, répéter le processus sur un ticket de service en fournissant un blob TGT valide et la clé du service cible, afin de rester discret sur le réseau.

### Techniques Rubeus actualisées (2024+)

Des travaux récents de Huntress ont modernisé l’action `diamond` de Rubeus en y intégrant les améliorations `/ldap` et `/opsec`, auparavant disponibles uniquement pour les golden/silver tickets. `/ldap` récupère désormais le contexte PAC réel en interrogeant LDAP **et** en montant SYSVOL afin d’extraire les attributs des comptes et des groupes, ainsi que la stratégie Kerberos/des mots de passe (par exemple, `GptTmpl.inf`). `/opsec` reproduit le flux AS-REQ/AS-REP de Windows en effectuant l’échange de préauthentification en deux étapes et en imposant AES uniquement ainsi que des KDCOptions réalistes. Cela réduit considérablement les indicateurs évidents, comme les champs PAC manquants ou les durées de vie incompatibles avec la stratégie.<sup>[[3]](#references)</sup>

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

- `/ldap` (avec `/ldapuser` et `/ldappassword` facultatifs) interroge AD et SYSVOL pour reproduire les données de stratégie PAC de l’utilisateur cible.
- `/opsec` force une nouvelle tentative AS-REQ similaire à celle de Windows, en mettant à zéro les indicateurs bruyants et en se limitant à AES256.
- `/tgtdeleg` évite de toucher au mot de passe en clair ou à la clé NTLM/AES de la victime, tout en renvoyant un TGT déchiffrable.

### Réusinage des tickets de service

La même mise à jour de Rubeus a ajouté la possibilité d’appliquer la technique diamond aux blobs TGS. En fournissant à `diamond` un **TGT encodé en base64** (issu de `asktgt`, de `/tgtdeleg` ou d’un TGT précédemment forgé), le **SPN du service** et la **clé AES du service**, vous pouvez créer des tickets de service réalistes sans contacter le KDC — ce qui revient à un silver ticket plus furtif.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Ce workflow est idéal lorsque vous contrôlez déjà une clé de compte de service (par exemple, extraite avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous voulez créer un TGS ponctuel qui correspond parfaitement à la stratégie AD, aux délais et aux données PAC, sans générer de nouveau trafic AS/TGS.<sup>[[3]](#references)</sup>

### Échanges de PAC de type Sapphire (2025)

Une variante plus récente, parfois appelée **sapphire ticket**, combine la base « real TGT » de Diamond avec **S4U2self+U2U** pour voler un PAC privilégié et l’insérer dans votre propre TGT. Au lieu d’inventer des SID supplémentaires, vous demandez un ticket S4U2self U2U pour un utilisateur à hauts privilèges, où le `sname` cible le demandeur à faibles privilèges ; le KRB_TGS_REQ transporte le TGT du demandeur dans `additional-tickets` et définit `ENC-TKT-IN-SKEY`, ce qui permet de déchiffrer le ticket de service avec la clé de cet utilisateur. Vous extrayez ensuite le PAC privilégié et l’insérez dans votre TGT légitime avant de le signer à nouveau avec la clé krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

`ticketer.py` d’Impacket intègre désormais la prise en charge de sapphire via `-impersonate` + `-request` (échange KDC en direct) :<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` accepte un nom d’utilisateur ou un SID ; `-request` nécessite des identifiants utilisateur valides ainsi que le matériel de clé krbtgt (AES/NTLM) pour déchiffrer/modifier les tickets.

Principaux indicateurs OPSEC lors de l’utilisation de cette variante :<sup>[[5]](#references)</sup>

- Le TGS-REQ contiendra `ENC-TKT-IN-SKEY` et `additional-tickets` (le TGT de la victime) — une configuration rare dans le trafic normal.
- `sname` correspond souvent à l’utilisateur qui fait la requête (accès en libre-service) et l’Event ID 4769 indique le même SPN/utilisateur comme appelant et cible.
- Attendez-vous à des entrées 4768/4769 appariées avec le même ordinateur client, mais des CNAMES différents (requérant à faibles privilèges vs propriétaire privilégié du PAC).

### OPSEC et notes de détection

- Les heuristiques traditionnelles des chasseurs (TGS sans AS, durées de vie de plusieurs décennies) s’appliquent toujours aux golden tickets, mais les diamond tickets se manifestent surtout lorsque le **contenu du PAC ou le mappage des groupes semble impossible**. Renseignez tous les champs du PAC (heures de connexion, chemins du profil utilisateur, ID d’appareil) afin que les comparaisons automatisées ne signalent pas immédiatement la falsification.<sup>[[3]](#references)</sup>
- **N’ajoutez pas trop de groupes/RID**. Si vous n’avez besoin que de `512` (Domain Admins) et `519` (Enterprise Admins), arrêtez-vous là et assurez-vous que le compte cible appartient de façon plausible à ces groupes ailleurs dans AD. Un nombre excessif d’`ExtraSids` est un indice révélateur.
- Les substitutions de type Sapphire laissent des traces U2U : `ENC-TKT-IN-SKEY` + `additional-tickets`, ainsi qu’un `sname` qui désigne un utilisateur (souvent le requérant) dans 4769, puis une connexion 4624 provenant du ticket falsifié. Corrélez ces champs au lieu de rechercher uniquement les séquences sans AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft a commencé à abandonner progressivement **l’émission de tickets de service RC4** en raison de CVE-2026-20833 ; imposer des etypes AES uniquement sur le KDC renforce le domaine et correspond aux outils diamond/sapphire (`/opsec` force déjà AES). L’utilisation de RC4 dans les PAC falsifiés sera de plus en plus suspecte.<sup>[[6]](#references)</sup>
- Le projet Security Content de Splunk distribue de la télémétrie issue d’attack-range pour les diamond tickets, ainsi que des détections telles que *Windows Domain Admin Impersonation Indicator*, qui corrèlent les séquences inhabituelles d’Event ID 4768/4769/4624 et les changements de groupes dans le PAC. Rejouer ce jeu de données (ou en générer un vous-même avec les commandes ci-dessus) aide à valider la couverture du SOC pour T1558.001 tout en vous donnant des règles d’alerte concrètes à contourner.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Pierres précieuses : la nouvelle génération d’attaques Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket : nous aimons jouer avec les tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Repensons le Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Données d’attaque et détections des Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Le côté obscur des pierres précieuses : Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Application de RC4 aux tickets de service pour CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
