# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **accéder à n'importe quel service en tant que n'importe quel utilisateur**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Comme les contrôleurs de domaine ne suivent pas les TGT qu'ils ont légitimement émis, ils accepteront sans problème des TGT chiffrés avec leur propre krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Rechercher des TGS-REQ qui n'ont pas d'AS-REQ correspondant.
- Rechercher des TGT qui ont des valeurs absurdes, comme la durée par défaut de 10 ans de Mimikatz.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- Les TGS-REQ auront un AS-REQ préalable.
- Le TGT a été émis par un DC, ce qui signifie qu'il contiendra tous les détails corrects issus de la Kerberos policy du domaine. Bien que ces éléments puissent être précisément forgés dans un golden ticket, c'est plus complexe et sujet aux erreurs.

### Exigences & flux de travail

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (avec en option `/ldapuser` & `/ldappassword`) interroge AD et SYSVOL pour répliquer les données de stratégie PAC de l'utilisateur cible.
- `/opsec` force une tentative AS-REQ de style Windows, met à zéro les flags bruyants et s'en tient à AES256.
- `/tgtdeleg` évite d'exposer le mot de passe en clair ou la clé NTLM/AES de la victime tout en renvoyant un TGT déchiffrable.

### Service-ticket recutting

La même mise à jour de Rubeus a ajouté la possibilité d'appliquer la diamond technique aux blobs TGS. En fournissant à `diamond` un **base64-encoded TGT** (provenant de `asktgt`, `/tgtdeleg`, ou d'un TGT forgé précédemment), le **service SPN**, et la **service AES key**, vous pouvez forger des service tickets réalistes sans toucher au KDC — offrant en pratique un silver ticket plus furtif.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé d'un compte de service (par exemple, dumpée avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous souhaitez créer un TGS ponctuel qui correspond parfaitement à la politique AD, aux délais et aux données PAC sans émettre de nouveau trafic AS/TGS.

### OPSEC & notes de détection

- The traditional hunter heuristics (TGS without AS, decade-long lifetimes) still apply to golden tickets, but diamond tickets mainly surface when the **le contenu du PAC ou le mappage des groupes semble impossible**. Remplissez chaque champ PAC (logon hours, user profile paths, device IDs) afin que les comparaisons automatisées ne signalent pas immédiatement la falsification.
- **Ne pas attribuer trop de groupes/RIDs**. Si vous n'avez besoin que des `512` (Domain Admins) et `519` (Enterprise Admins), contentez-vous de cela et assurez-vous que le compte ciblé appartient de manière plausible à ces groupes ailleurs dans AD. Des `ExtraSids` excessifs trahissent la supercherie.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Rejouer cet ensemble de données (ou en générer un vous-même avec les commandes ci-dessus) aide à valider la couverture SOC pour T1558.001 tout en vous fournissant une logique d'alerte concrète à contourner.

## Références

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
