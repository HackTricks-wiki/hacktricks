# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Exigences et flux de travail

- **Matériel cryptographique** : la clé AES256 krbtgt (préférée) ou le hash NTLM afin de déchiffrer et de re-signer le TGT.
- **Bloc TGT légitime** : obtenu avec `/tgtdeleg`, `asktgt`, `s4u`, ou en exportant les tickets depuis la mémoire.
- **Données de contexte** : le RID de l'utilisateur cible, les RIDs/SIDs des groupes, et (optionnellement) les attributs PAC dérivés de LDAP.
- **Clés de service** (uniquement si vous comptez re-créer des tickets de service) : clé AES du SPN de service à usurper.

1. Obtenez un TGT pour n'importe quel utilisateur contrôlé via AS-REQ (Rubeus `/tgtdeleg` est pratique car il force le client à effectuer l'échange Kerberos GSS-API sans identifiants).
2. Déchiffrez le TGT retourné avec la clé krbtgt, modifiez les attributs PAC (utilisateur, groupes, informations de connexion, SIDs, claims de l'appareil, etc.).
3. Rechiffrez/signez le ticket avec la même clé krbtgt et injectez-le dans la session de connexion actuelle (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionnellement, répétez le processus sur un ticket de service en fournissant un blob TGT valide ainsi que la clé du service cible pour rester discret sur le réseau.

### Mise à jour du tradecraft Rubeus (2024+)

Des travaux récents par Huntress ont modernisé l'action `diamond` dans Rubeus en portant les améliorations `/ldap` et `/opsec` qui auparavant n'existaient que pour les golden/silver tickets. `/ldap` récupère maintenant un contexte PAC réel en interrogeant LDAP **et** en montant SYSVOL pour extraire les attributs de comptes/groupes ainsi que la politique Kerberos/de mot de passe (p.ex., `GptTmpl.inf`), tandis que `/opsec` fait correspondre le flux AS-REQ/AS-REP à Windows en réalisant l'échange préauth en deux étapes et en imposant AES-only + des KDCOptions réalistes. Cela réduit drastiquement les indicateurs évidents tels que l'absence de champs PAC ou des durées de vie incompatibles avec la politique.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) interroge AD et SYSVOL pour reproduire les données de politique PAC de l'utilisateur cible.
- `/opsec` force une nouvelle tentative AS-REQ à la manière de Windows, met à zéro les flags bruyants et se cantonne à AES256.

### Recoupage de tickets de service

La même mise à jour de Rubeus a ajouté la capacité d'appliquer la technique diamond aux blobs TGS. En fournissant à `diamond` un **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), le **service SPN**, et la **service AES key**, vous pouvez forger des tickets de service réalistes sans toucher au KDC—effectivement un silver ticket plus furtif.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Ce workflow est idéal lorsque vous contrôlez déjà une clé de compte de service (par ex., dumpée avec `lsadump::lsa /inject` ou `secretsdump.py`) et que vous souhaitez créer un TGS ponctuel qui correspond parfaitement à la politique AD, aux délais et aux données PAC sans émettre de nouveau trafic AS/TGS.

### Sapphire-style PAC swaps (2025)

Une variante plus récente, parfois appelée **sapphire ticket**, combine la base "real TGT" de Diamond avec **S4U2self+U2U** pour voler un PAC privilégié et l'injecter dans votre propre TGT. Au lieu d'inventer des SIDs supplémentaires, vous demandez un ticket U2U S4U2self pour un utilisateur à haut privilège dont le `sname` cible le demandeur à faible privilège ; la KRB_TGS_REQ transporte le TGT du demandeur dans `additional-tickets` et définit `ENC-TKT-IN-SKEY`, permettant au service ticket d'être déchiffré avec la clé de cet utilisateur. Vous extrayez ensuite le PAC privilégié et l'incorporez dans votre TGT légitime avant de le re-signer avec la clé krbtgt.

Impacket's `ticketer.py` intègre désormais le support sapphire via `-impersonate` + `-request` (échange KDC en direct) :
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` accepte un nom d'utilisateur ou un SID ; `-request` nécessite les identifiants d'un utilisateur actif plus la clé krbtgt (AES/NTLM) pour déchiffrer/patcher les tickets.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — rare in normal traffic.
- `sname` often equals the requesting user (self-service access) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & detection notes

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
