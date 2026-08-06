# Vol de certificats AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Voici un bref résumé des chapitres consacrés au Theft issus de l'excellente recherche disponible sur [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Que puis-je faire avec un certificat

Avant de voir comment voler les certificats, voici quelques informations sur la manière de déterminer à quoi sert le certificat :
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportation de certificats à l’aide des Crypto APIs – THEFT1

Dans une **session de bureau interactive**, l’extraction d’un certificat utilisateur ou machine, avec sa clé privée, peut être effectuée facilement, en particulier si la **clé privée est exportable**. Pour cela, accédez au certificat dans `certmgr.msc`, cliquez dessus avec le bouton droit, puis sélectionnez `All Tasks → Export` afin de générer un fichier .pfx protégé par mot de passe.<sup>[[1]](#references)</sup>

Pour une **approche programmatique**, des outils tels que l’applet de commande PowerShell `ExportPfxCertificate` ou des projets comme le [projet CertStealer C# de TheWover](https://github.com/TheWover/CertStealer) sont disponibles. Ceux-ci utilisent la **Microsoft CryptoAPI** (CAPI) ou la Cryptography API: Next Generation (CNG) pour interagir avec le magasin de certificats. Ces APIs fournissent divers services cryptographiques, notamment ceux nécessaires au stockage des certificats et à l’authentification.

Cependant, si une clé privée est définie comme non exportable, CAPI et CNG bloquent normalement l’extraction de ces certificats. Pour contourner cette restriction, des outils comme **Mimikatz** peuvent être utilisés. Mimikatz propose les commandes `crypto::capi` et `crypto::cng` pour patcher les APIs correspondantes et permettre l’exportation des clés privées. Plus précisément, `crypto::capi` patche CAPI au sein du processus actuel, tandis que `crypto::cng` cible la mémoire de **lsass.exe** afin de la patcher.

## Vol de certificats utilisateur via DPAPI – THEFT2

Plus d’informations sur DPAPI dans :


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Sous Windows, les **clés privées des certificats sont protégées par DPAPI**. Il est essentiel de comprendre que les **emplacements de stockage des clés privées utilisateur et machine** sont distincts, et que les structures des fichiers varient selon l’API cryptographique utilisée par le système d’exploitation. **SharpDPAPI** est un outil capable de gérer automatiquement ces différences lors du déchiffrement des blobs DPAPI.<sup>[[1]](#references)</sup>

Les **certificats utilisateur** sont principalement stockés dans le registre, sous `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, mais certains peuvent également se trouver dans le répertoire `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Les **clés privées** correspondantes sont généralement stockées dans `%APPDATA%\Microsoft\Crypto\RSA\User SID\` pour les clés **CAPI**, et dans `%APPDATA%\Microsoft\Crypto\Keys\` pour les clés **CNG**.

Pour **extraire un certificat et sa clé privée associée**, le processus comprend les étapes suivantes :

1. **Sélectionner le certificat cible** dans le magasin de l’utilisateur et récupérer le nom de son magasin de clés.
2. **Localiser le DPAPI masterkey requis** pour déchiffrer la clé privée correspondante.
3. **Déchiffrer la clé privée** à l’aide du DPAPI masterkey en clair.

Pour **obtenir le DPAPI masterkey en clair**, les approches suivantes peuvent être utilisées :
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Pour simplifier le déchiffrement des fichiers masterkey et des fichiers de clé privée, la commande `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) s’avère utile. Elle accepte `/pvk`, `/mkfile`, `/password` ou `{GUID}:KEY` comme arguments pour déchiffrer les clés privées et les certificats associés, puis génère un fichier `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Vol de certificats machine via DPAPI – THEFT3

Les certificats machine stockés par Windows dans le registre à l’emplacement `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` et les clés privées associées situées dans `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (pour CAPI) et `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (pour CNG) sont chiffrés à l’aide des clés principales DPAPI de la machine. Ces clés ne peuvent pas être déchiffrées avec la clé de sauvegarde DPAPI du domaine ; le **secret LSA DPAPI_SYSTEM**, auquel seul l’utilisateur SYSTEM peut accéder, est requis.<sup>[[1]](#references)</sup>

Un déchiffrement manuel peut être effectué en exécutant la commande `lsadump::secrets` dans **Mimikatz** afin d’extraire le secret LSA DPAPI_SYSTEM, puis en utilisant cette clé pour déchiffrer les clés principales de la machine. Une autre possibilité consiste à utiliser la commande `crypto::certificates /export /systemstore:LOCAL_MACHINE` de Mimikatz après avoir patché CAPI/CNG comme décrit précédemment.

**SharpDPAPI** propose une approche plus automatisée avec sa commande certificates. Lorsque l’indicateur `/machine` est utilisé avec des privilèges élevés, il passe au contexte SYSTEM, extrait le secret LSA DPAPI_SYSTEM, l’utilise pour déchiffrer les clés principales DPAPI de la machine, puis emploie ces clés en clair comme table de correspondance pour déchiffrer les clés privées des certificats machine.

## Recherche de fichiers de certificats – THEFT4

Les certificats se trouvent parfois directement dans le système de fichiers, notamment dans des partages de fichiers ou dans le dossier Downloads. Les types de fichiers de certificats les plus couramment rencontrés et ciblés dans les environnements Windows sont les fichiers `.pfx` et `.p12`. Bien que moins fréquents, les fichiers portant les extensions `.pkcs12` et `.pem` apparaissent également. D’autres extensions de fichiers liées aux certificats sont à noter :<sup>[[1]](#references)</sup>

- `.key` pour les clés privées,
- `.crt`/`.cer` pour les certificats uniquement,
- `.csr` pour les Certificate Signing Requests, qui ne contiennent ni certificats ni clés privées,
- `.jks`/`.keystore`/`.keys` pour les Java Keystores, qui peuvent contenir des certificats ainsi que des clés privées utilisées par des applications Java.

Ces fichiers peuvent être recherchés avec PowerShell ou l’invite de commandes en recherchant les extensions mentionnées.

Lorsqu’un fichier de certificat PKCS#12 est trouvé et protégé par un mot de passe, il est possible d’en extraire le hash à l’aide de `pfx2john.py`, disponible sur [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). JohnTheRipper peut ensuite être utilisé pour tenter de cracker le mot de passe.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Vol de credentials NTLM via PKINIT – THEFT5 (UnPAC the hash)

Le contenu fourni explique une méthode de vol de credentials NTLM via PKINIT, plus précisément au moyen de la méthode de vol intitulée THEFT5. Voici une réexplication à la voix passive, avec un contenu anonymisé et résumé lorsque cela est pertinent :<sup>[[1]](#references)</sup>

Pour prendre en charge l'authentification NTLM `MS-NLMP` des applications qui ne permettent pas l'authentification Kerberos, le KDC est conçu pour renvoyer la fonction à sens unique (OWF) NTLM de l'utilisateur dans le privilege attribute certificate (PAC), plus précisément dans le buffer `PAC_CREDENTIAL_INFO`, lorsque PKCA est utilisé. Par conséquent, lorsqu'un compte s'authentifie et obtient un Ticket-Granting Ticket (TGT) via PKINIT, un mécanisme est implicitement fourni afin de permettre à l'hôte actuel d'extraire le hash NTLM du TGT pour assurer la compatibilité avec les protocoles d'authentification legacy. Ce processus implique le déchiffrement de la structure `PAC_CREDENTIAL_DATA`, qui est essentiellement une représentation sérialisée en NDR du texte en clair NTLM.

L'outil **Kekeo**, disponible à l'adresse [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), est présenté comme pouvant demander un TGT contenant ces données, permettant ainsi de récupérer le NTLM de l'utilisateur. La commande utilisée à cette fin est la suivante :
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** peut également obtenir ces informations avec l’option **`asktgt [...] /getcredentials`**.

De plus, il est indiqué que Kekeo peut traiter les certificats protégés par smartcard, à condition de pouvoir récupérer le PIN, avec une référence à [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Il est également indiqué que cette fonctionnalité est prise en charge par **Rubeus**, disponible à l’adresse [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Cette explication décrit le processus et les outils impliqués dans le vol d’identifiants NTLM via PKINIT, en se concentrant sur la récupération des hashes NTLM au moyen d’un TGT obtenu via PKINIT, ainsi que sur les utilitaires qui facilitent ce processus.

## Références

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
