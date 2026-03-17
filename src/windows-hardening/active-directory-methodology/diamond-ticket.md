# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Comme un golden ticket**, un diamond ticket est un TGT qui peut être utilisé pour **accéder à n'importe quel service en tant que n'importe quel utilisateur**. Un golden ticket est forgé complètement hors ligne, chiffré avec le hash krbtgt de ce domaine, puis injecté dans une session de connexion pour être utilisé. Parce que les contrôleurs de domaine ne suivent pas les TGT qu'ils ont légitimement émis, ils accepteront sans problème des TGT chiffrés avec leur propre hash krbtgt.

Il existe deux techniques courantes pour détecter l'utilisation de golden tickets :

- Cherchez des TGS-REQs qui n'ont pas d'AS-REQ correspondant.
- Cherchez des TGTs qui ont des valeurs absurdes, comme la durée de vie par défaut de 10 ans de Mimikatz.

Un **diamond ticket** est créé en **modifiant les champs d'un TGT légitime qui a été émis par un DC**. Cela s'obtient en **demandant** un **TGT**, en le **décryptant** avec le hash krbtgt du domaine, en **modifiant** les champs souhaités du ticket, puis en le **ré-encryptant**. Cela **corrige les deux inconvénients susmentionnés** d'un golden ticket parce que :

- Les TGS-REQs auront une AS-REQ précédente.
- Le TGT a été émis par un DC, ce qui signifie qu'il contiendra tous les détails corrects issus de la politique Kerberos du domaine. Même si ces éléments peuvent être soigneusement forgés dans un golden ticket, c'est plus complexe et sujet aux erreurs.

### Exigences et flux de travail

- **Matériel cryptographique** : la clé AES256 krbtgt (préférée) ou le hash NTLM afin de déchiffrer et de re-signer le TGT.
- **Blob TGT légitime** : obtenu avec `/tgtdeleg`, `asktgt`, `s4u`, ou en exportant les tickets depuis la mémoire.
- **Données de contexte** : le RID de l'utilisateur cible, les RIDs/SIDs de groupes, et (optionnellement) les attributs PAC dérivés de LDAP.
- **Clés de service** (uniquement si vous prévoyez de réémettre des service tickets) : clé AES du SPN de service à usurper.

1. Obtenez un TGT pour n'importe quel utilisateur contrôlé via AS-REQ (Rubeus `/tgtdeleg` est pratique car il contraint le client à effectuer le GSS-API Kerberos sans identifiants).
2. Déchiffrez le TGT retourné avec la clé krbtgt, modifiez les attributs PAC (utilisateur, groupes, informations de connexion, SIDs, device claims, etc.).
3. Re-chiffrez/signez le ticket avec la même clé krbtgt et injectez-le dans la session de connexion en cours (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionnellement, répétez le processus pour un service ticket en fournissant un blob TGT valide ainsi que la clé du service cible pour rester discret sur le réseau.

### Tradecraft Rubeus mis à jour (2024+)

Des travaux récents de Huntress ont modernisé l'action `diamond` dans Rubeus en y important les améliorations `/ldap` et `/opsec` qui existaient auparavant uniquement pour les golden/silver tickets. `/ldap` récupère désormais un contexte PAC réel en interrogeant LDAP **et** en montant SYSVOL pour extraire les attributs de comptes/groupes ainsi que la politique Kerberos/password (par ex., `GptTmpl.inf`), tandis que `/opsec` fait correspondre le flux AS-REQ/AS-REP à Windows en réalisant l'échange de pré-auth en deux étapes et en n'autorisant que AES + des KDCOptions réalistes. Cela réduit fortement les indicateurs évidents tels que des champs PAC manquants ou des durées de vie non conformes à la politique.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) interroge AD et SYSVOL pour refléter les données de politique PAC de l'utilisateur cible.
- `/opsec` force une reprise AS-REQ de type Windows, remet à zéro les flags bruyants et s'en tient à AES256.
- `/tgtdeleg` évite d'exposer le mot de passe en clair ou la clé NTLM/AES de la victime tout en renvoyant un TGT déchiffrable.

### Service-ticket recutting

La même mise à jour de Rubeus a ajouté la possibilité d'appliquer la technique diamond aux blobs TGS. En fournissant à `diamond` un **TGT encodé en base64** (depuis `asktgt`, `/tgtdeleg`, ou un TGT précédemment forgé), le **service SPN**, et la **clé AES du service**, vous pouvez fabriquer des tickets de service réalistes sans toucher au KDC—en pratique un silver ticket plus discret.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé de compte de service (par ex., dumpée avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous souhaitez générer un TGS ponctuel qui correspond parfaitement à la politique AD, aux timelines et aux données PAC sans émettre de nouveau trafic AS/TGS.

### Sapphire-style PAC swaps (2025)

Une variante plus récente, parfois appelée **sapphire ticket**, combine la base "real TGT" de Diamond avec **S4U2self+U2U** pour voler un PAC privilégié et l'insérer dans votre propre TGT. Plutôt que d'inventer des SIDs supplémentaires, vous demandez un ticket U2U S4U2self pour un utilisateur à haut privilège où le `sname` cible le demandeur à faibles privilèges ; la requête KRB_TGS_REQ transporte le TGT du demandeur dans `additional-tickets` et active `ENC-TKT-IN-SKEY`, permettant que le service ticket soit déchiffré avec la clé de cet utilisateur. Vous extrayez ensuite le PAC privilégié et le greffez dans votre TGT légitime avant de le re-signer avec la clé krbtgt.

Le `ticketer.py` d'Impacket inclut désormais le support sapphire via `-impersonate` + `-request` (échange en direct avec le KDC) :
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepte un nom d'utilisateur ou un SID ; `-request` nécessite des identifiants utilisateur actifs plus le matériel de clé krbtgt (AES/NTLM) pour décrypter/patcher les tickets.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & notes de détection

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **PAC content or group mapping looks impossible**. Populate every PAC field (logon hours, user profile paths, device IDs) so automated comparisons do not immediately flag the forgery.
- **Do not oversubscribe groups/RIDs**. If you only need `512` (Domain Admins) and `519` (Enterprise Admins), stop there and make sure the target account plausibly belongs to those groups elsewhere in AD. Excessive `ExtraSids` is a giveaway.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` plus a `sname` that points at a user (often the requester) in 4769, and a follow-up 4624 logon sourced from the forged ticket. Correlate those fields instead of only looking for no-AS-REQ gaps.
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; enforcing AES-only etypes on the KDC both hardens the domain and aligns with diamond/sapphire tooling (/opsec already forces AES). Mixing RC4 into forged PACs will increasingly stick out.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Replaying that dataset (or generating your own with the commands above) helps validate SOC coverage for T1558.001 while giving you concrete alert logic to evade.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
