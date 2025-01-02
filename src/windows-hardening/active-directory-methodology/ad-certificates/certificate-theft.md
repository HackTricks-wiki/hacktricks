# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un petit résumé des chapitres sur le vol dans la recherche incroyable de [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Que puis-je faire avec un certificat

Avant de vérifier comment voler les certificats, voici quelques informations sur la façon de trouver à quoi sert le certificat :
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportation des certificats en utilisant les Crypto APIs – THEFT1

Dans une **session de bureau interactive**, l'extraction d'un certificat utilisateur ou machine, ainsi que de la clé privée, peut être facilement réalisée, en particulier si la **clé privée est exportable**. Cela peut être accompli en naviguant vers le certificat dans `certmgr.msc`, en cliquant avec le bouton droit dessus, et en sélectionnant `All Tasks → Export` pour générer un fichier .pfx protégé par mot de passe.

Pour une **approche programmatique**, des outils tels que le cmdlet PowerShell `ExportPfxCertificate` ou des projets comme [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) sont disponibles. Ceux-ci utilisent la **Microsoft CryptoAPI** (CAPI) ou l'API de cryptographie : Next Generation (CNG) pour interagir avec le magasin de certificats. Ces APIs fournissent une gamme de services cryptographiques, y compris ceux nécessaires pour le stockage et l'authentification des certificats.

Cependant, si une clé privée est définie comme non-exportable, CAPI et CNG bloqueront normalement l'extraction de tels certificats. Pour contourner cette restriction, des outils comme **Mimikatz** peuvent être employés. Mimikatz offre des commandes `crypto::capi` et `crypto::cng` pour patcher les APIs respectives, permettant l'exportation des clés privées. Plus précisément, `crypto::capi` patch le CAPI dans le processus actuel, tandis que `crypto::cng` cible la mémoire de **lsass.exe** pour le patching.

## Vol de certificats utilisateur via DPAPI – THEFT2

Plus d'infos sur DPAPI dans :

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Dans Windows, **les clés privées des certificats sont protégées par DPAPI**. Il est crucial de reconnaître que les **emplacements de stockage pour les clés privées utilisateur et machine** sont distincts, et les structures de fichiers varient en fonction de l'API cryptographique utilisée par le système d'exploitation. **SharpDPAPI** est un outil qui peut naviguer automatiquement dans ces différences lors du déchiffrement des blobs DPAPI.

Les **certificats utilisateur** sont principalement logés dans le registre sous `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, mais certains peuvent également être trouvés dans le répertoire `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Les **clés privées** correspondantes pour ces certificats sont généralement stockées dans `%APPDATA%\Microsoft\Crypto\RSA\User SID\` pour les clés **CAPI** et `%APPDATA%\Microsoft\Crypto\Keys\` pour les clés **CNG**.

Pour **extraire un certificat et sa clé privée associée**, le processus implique :

1. **Sélectionner le certificat cible** dans le magasin de l'utilisateur et récupérer son nom de magasin de clés.
2. **Localiser la masterkey DPAPI requise** pour déchiffrer la clé privée correspondante.
3. **Déchiffrer la clé privée** en utilisant la masterkey DPAPI en clair.

Pour **acquérir la masterkey DPAPI en clair**, les approches suivantes peuvent être utilisées :
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Pour simplifier le déchiffrement des fichiers masterkey et des fichiers de clé privée, la commande `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) s'avère utile. Elle accepte `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` comme arguments pour déchiffrer les clés privées et les certificats associés, générant ensuite un fichier `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Vol de certificats de machine via DPAPI – THEFT3

Les certificats de machine stockés par Windows dans le registre à `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` et les clés privées associées situées dans `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (pour CAPI) et `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (pour CNG) sont chiffrés à l'aide des clés maîtresses DPAPI de la machine. Ces clés ne peuvent pas être déchiffrées avec la clé de sauvegarde DPAPI du domaine ; au lieu de cela, le **secret LSA DPAPI_SYSTEM**, auquel seul l'utilisateur SYSTEM peut accéder, est requis.

Le déchiffrement manuel peut être réalisé en exécutant la commande `lsadump::secrets` dans **Mimikatz** pour extraire le secret LSA DPAPI_SYSTEM, puis en utilisant cette clé pour déchiffrer les clés maîtresses de la machine. Alternativement, la commande `crypto::certificates /export /systemstore:LOCAL_MACHINE` de Mimikatz peut être utilisée après avoir patché CAPI/CNG comme décrit précédemment.

**SharpDPAPI** offre une approche plus automatisée avec sa commande de certificats. Lorsque le drapeau `/machine` est utilisé avec des permissions élevées, il s'élève à SYSTEM, extrait le secret LSA DPAPI_SYSTEM, l'utilise pour déchiffrer les clés maîtresses DPAPI de la machine, puis utilise ces clés en texte clair comme table de recherche pour déchiffrer toutes les clés privées de certificats de machine.

## Recherche de fichiers de certificats – THEFT4

Les certificats se trouvent parfois directement dans le système de fichiers, comme dans des partages de fichiers ou le dossier Téléchargements. Les types de fichiers de certificats les plus couramment rencontrés ciblant les environnements Windows sont les fichiers `.pfx` et `.p12`. Bien que moins fréquemment, des fichiers avec les extensions `.pkcs12` et `.pem` apparaissent également. D'autres extensions de fichiers liées aux certificats notables incluent :

- `.key` pour les clés privées,
- `.crt`/`.cer` pour les certificats uniquement,
- `.csr` pour les demandes de signature de certificat, qui ne contiennent pas de certificats ni de clés privées,
- `.jks`/`.keystore`/`.keys` pour les Java Keystores, qui peuvent contenir des certificats ainsi que des clés privées utilisées par des applications Java.

Ces fichiers peuvent être recherchés à l'aide de PowerShell ou de l'invite de commande en cherchant les extensions mentionnées.

Dans les cas où un fichier de certificat PKCS#12 est trouvé et qu'il est protégé par un mot de passe, l'extraction d'un hachage est possible grâce à l'utilisation de `pfx2john.py`, disponible sur [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Par la suite, JohnTheRipper peut être utilisé pour tenter de cracker le mot de passe.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Le contenu donné explique une méthode pour le vol de crédentiels NTLM via PKINIT, spécifiquement à travers la méthode de vol étiquetée comme THEFT5. Voici une réexplication à la voix passive, avec le contenu anonymisé et résumé lorsque cela est applicable :

Pour soutenir l'authentification NTLM [MS-NLMP] pour les applications qui ne facilitent pas l'authentification Kerberos, le KDC est conçu pour renvoyer la fonction unidirectionnelle NTLM (OWF) de l'utilisateur dans le certificat d'attribut de privilège (PAC), spécifiquement dans le tampon `PAC_CREDENTIAL_INFO`, lorsque PKCA est utilisé. Par conséquent, si un compte s'authentifie et obtient un Ticket-Granting Ticket (TGT) via PKINIT, un mécanisme est intrinsèquement fourni qui permet à l'hôte actuel d'extraire le hachage NTLM du TGT pour maintenir les protocoles d'authentification hérités. Ce processus implique le déchiffrement de la structure `PAC_CREDENTIAL_DATA`, qui est essentiellement une représentation NDR sérialisée du texte en clair NTLM.

L'utilitaire **Kekeo**, accessible à [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), est mentionné comme capable de demander un TGT contenant ces données spécifiques, facilitant ainsi la récupération du NTLM de l'utilisateur. La commande utilisée à cet effet est la suivante :
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
De plus, il est noté que Kekeo peut traiter des certificats protégés par carte à puce, à condition que le code PIN puisse être récupéré, avec référence à [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La même capacité est indiquée comme étant prise en charge par **Rubeus**, disponible à [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Cette explication encapsule le processus et les outils impliqués dans le vol de crédentiels NTLM via PKINIT, en se concentrant sur la récupération des hachages NTLM à travers le TGT obtenu en utilisant PKINIT, et les utilitaires qui facilitent ce processus.

{{#include ../../../banners/hacktricks-training.md}}
