# Certificats

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce qu'un certificat

Un **certificat de clé publique** est une ID numérique utilisée en cryptographie pour prouver qu'une personne possède une clé publique. Il inclut les détails de la clé, l'identité du propriétaire (le sujet) et une signature numérique d'une autorité de confiance (l'émetteur). Si le logiciel fait confiance à l'émetteur et que la signature est valide, une communication sécurisée avec le propriétaire de la clé est possible.

Les certificats sont principalement émis par des [autorités de certification](https://en.wikipedia.org/wiki/Certificate_authority) (CAs) dans une [infrastructure à clé publique](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI). Une autre méthode est le [web de confiance](https://en.wikipedia.org/wiki/Web_of_trust), où les utilisateurs vérifient directement les clés des autres. Le format commun pour les certificats est [X.509](https://en.wikipedia.org/wiki/X.509), qui peut être adapté à des besoins spécifiques comme indiqué dans le RFC 5280.

## Champs communs x509

### **Champs communs dans les certificats x509**

Dans les certificats x509, plusieurs **champs** jouent des rôles critiques pour garantir la validité et la sécurité du certificat. Voici un aperçu de ces champs :

- **Numéro de version** signifie la version du format x509.
- **Numéro de série** identifie de manière unique le certificat au sein du système d'une Autorité de Certification (CA), principalement pour le suivi des révocations.
- Le champ **Sujet** représente le propriétaire du certificat, qui peut être une machine, un individu ou une organisation. Il inclut une identification détaillée telle que :
- **Nom commun (CN)** : Domaines couverts par le certificat.
- **Pays (C)**, **Localité (L)**, **État ou Province (ST, S, ou P)**, **Organisation (O)**, et **Unité organisationnelle (OU)** fournissent des détails géographiques et organisationnels.
- **Nom distinctif (DN)** encapsule l'identification complète du sujet.
- **Émetteur** détaille qui a vérifié et signé le certificat, y compris des sous-champs similaires à ceux du Sujet pour la CA.
- La **période de validité** est marquée par les horodatages **Non avant** et **Non après**, garantissant que le certificat n'est pas utilisé avant ou après une certaine date.
- La section **Clé publique**, cruciale pour la sécurité du certificat, spécifie l'algorithme, la taille et d'autres détails techniques de la clé publique.
- Les **extensions x509v3** améliorent la fonctionnalité du certificat, spécifiant **Utilisation de la clé**, **Utilisation de clé étendue**, **Nom alternatif du sujet**, et d'autres propriétés pour affiner l'application du certificat.

#### **Utilisation de la clé et extensions**

- **Utilisation de la clé** identifie les applications cryptographiques de la clé publique, comme la signature numérique ou le chiffrement de clé.
- **Utilisation de clé étendue** précise davantage les cas d'utilisation du certificat, par exemple, pour l'authentification de serveur TLS.
- **Nom alternatif du sujet** et **Contrainte de base** définissent des noms d'hôtes supplémentaires couverts par le certificat et s'il s'agit d'un certificat CA ou d'entité finale, respectivement.
- Des identifiants comme **Identifiant de clé du sujet** et **Identifiant de clé d'autorité** garantissent l'unicité et la traçabilité des clés.
- **Accès à l'information d'autorité** et **Points de distribution CRL** fournissent des chemins pour vérifier la CA émettrice et vérifier l'état de révocation du certificat.
- Les **SCTs de pré-certificat CT** offrent des journaux de transparence, cruciaux pour la confiance publique dans le certificat.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Différence entre OCSP et points de distribution CRL**

**OCSP** (**RFC 2560**) implique qu'un client et un répondant travaillent ensemble pour vérifier si un certificat de clé publique numérique a été révoqué, sans avoir besoin de télécharger la **CRL** complète. Cette méthode est plus efficace que la **CRL** traditionnelle, qui fournit une liste de numéros de série de certificats révoqués mais nécessite le téléchargement d'un fichier potentiellement volumineux. Les CRL peuvent inclure jusqu'à 512 entrées. Plus de détails sont disponibles [ici](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm).

### **Qu'est-ce que la transparence des certificats**

La transparence des certificats aide à lutter contre les menaces liées aux certificats en garantissant que l'émission et l'existence des certificats SSL sont visibles pour les propriétaires de domaine, les CA et les utilisateurs. Ses objectifs sont :

- Empêcher les CA d'émettre des certificats SSL pour un domaine sans la connaissance du propriétaire du domaine.
- Établir un système d'audit ouvert pour suivre les certificats émis par erreur ou de manière malveillante.
- Protéger les utilisateurs contre les certificats frauduleux.

#### **Journaux de certificats**

Les journaux de certificats sont des enregistrements audités publiquement, en mode ajout uniquement, de certificats, maintenus par des services réseau. Ces journaux fournissent des preuves cryptographiques à des fins d'audit. Les autorités d'émission et le public peuvent soumettre des certificats à ces journaux ou les interroger pour vérification. Bien que le nombre exact de serveurs de journaux ne soit pas fixe, on s'attend à ce qu'il soit inférieur à mille dans le monde. Ces serveurs peuvent être gérés indépendamment par des CA, des FAI ou toute entité intéressée.

#### **Interrogation**

Pour explorer les journaux de transparence des certificats pour un domaine quelconque, visitez [https://crt.sh/](https://crt.sh).

Différents formats existent pour stocker des certificats, chacun ayant ses propres cas d'utilisation et compatibilité. Ce résumé couvre les principaux formats et fournit des conseils sur la conversion entre eux.

## **Formats**

### **Format PEM**

- Format le plus largement utilisé pour les certificats.
- Nécessite des fichiers séparés pour les certificats et les clés privées, encodés en Base64 ASCII.
- Extensions courantes : .cer, .crt, .pem, .key.
- Principalement utilisé par Apache et des serveurs similaires.

### **Format DER**

- Un format binaire de certificats.
- Manque les déclarations "BEGIN/END CERTIFICATE" trouvées dans les fichiers PEM.
- Extensions courantes : .cer, .der.
- Souvent utilisé avec des plateformes Java.

### **Format P7B/PKCS#7**

- Stocké en Base64 ASCII, avec les extensions .p7b ou .p7c.
- Contient uniquement des certificats et des certificats de chaîne, excluant la clé privée.
- Pris en charge par Microsoft Windows et Java Tomcat.

### **Format PFX/P12/PKCS#12**

- Un format binaire qui encapsule les certificats de serveur, les certificats intermédiaires et les clés privées dans un seul fichier.
- Extensions : .pfx, .p12.
- Principalement utilisé sur Windows pour l'importation et l'exportation de certificats.

### **Conversion de formats**

**Les conversions PEM** sont essentielles pour la compatibilité :

- **x509 à PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM à DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER à PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM à P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7 à PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Les conversions PFX** sont cruciales pour la gestion des certificats sur Windows :

- **PFX à PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX à PKCS#8** implique deux étapes :
1. Convertir PFX en PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convertir PEM en PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B à PFX** nécessite également deux commandes :
1. Convertir P7B en CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertir CER et clé privée en PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
---

{{#include ../banners/hacktricks-training.md}}
