# Attaques Homograph / Homoglyph dans le Phishing

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Une attaque homograph (également appelée homoglyph) exploite le fait que de nombreux **points de code Unicode provenant de scripts non latins sont visuellement identiques ou extrêmement similaires aux caractères ASCII**. En remplaçant un ou plusieurs caractères latins par leurs homologues visuellement similaires, un attaquant peut créer :

* Des noms d'affichage, des sujets ou des corps de message qui semblent légitimes à l'œil humain mais contournent les détections basées sur des mots-clés.
* Des domaines, sous-domaines ou chemins d'URL qui trompent les victimes en leur faisant croire qu'elles visitent un site de confiance.

Parce que chaque glyphe est identifié en interne par son **point de code Unicode**, un seul caractère substitué suffit à vaincre des comparaisons de chaînes naïves (par exemple, `"Παypal.com"` contre `"Paypal.com"`).

## Flux de Travail Typique du Phishing

1. **Créer le contenu du message** – Remplacer des lettres latines spécifiques dans la marque / mot-clé usurpé par des caractères visuellement indiscernables d'un autre script (grec, cyrillique, arménien, cherokee, etc.).
2. **Enregistrer l'infrastructure de soutien** – Enregistrer éventuellement un domaine homoglyph et obtenir un certificat TLS (la plupart des CA ne font pas de vérifications de similarité visuelle).
3. **Envoyer un email / SMS** – Le message contient des homoglyphes dans un ou plusieurs des emplacements suivants :
* Nom d'affichage de l'expéditeur (par exemple, `Ηеlрdеѕk`)
* Ligne de sujet (`Urgеnt Аctіon Rеquіrеd`)
* Texte de lien hypertexte ou nom de domaine entièrement qualifié
4. **Chaîne de redirection** – La victime est redirigée à travers des sites Web apparemment bénins ou des raccourcisseurs d'URL avant d'atterrir sur l'hôte malveillant qui collecte des identifiants / livre des malwares.

## Plages Unicode Couramment Abusées

| Script | Plage | Glyphe exemple | Semble être |
|--------|-------|----------------|-------------|
| Grec  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Grec  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillique | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillique | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Arménien | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Astuce : Des tableaux Unicode complets sont disponibles sur [unicode.org](https://home.unicode.org/).

## Techniques de Détection

### 1. Inspection de Scripts Mixtes

Les emails de phishing visant une organisation anglophone devraient rarement mélanger des caractères de plusieurs scripts. Une heuristique simple mais efficace consiste à :

1. Itérer chaque caractère de la chaîne inspectée.
2. Mapper le point de code à son bloc Unicode.
3. Élever une alerte si plus d'un script est présent **ou** si des scripts non latins apparaissent là où ils ne sont pas attendus (nom d'affichage, domaine, sujet, URL, etc.).

Preuve de concept en Python :
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Normalisation Punycode (Domaines)

Les noms de domaine internationalisés (IDN) sont encodés avec **punycode** (`xn--`). Convertir chaque nom d'hôte en punycode puis le reconvertir en Unicode permet de faire correspondre avec une liste blanche ou d'effectuer des vérifications de similarité (par exemple, distance de Levenshtein) **après** que la chaîne a été normalisée.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dictionnaires / Algorithmes de Homoglyphes

Des outils tels que **dnstwist** (`--homoglyph`) ou **urlcrazy** peuvent énumérer des permutations de domaines visuellement similaires et sont utiles pour des actions proactives de suppression / surveillance.

## Prévention & Atténuation

* Appliquer des politiques DMARC/DKIM/SPF strictes – prévenir le spoofing depuis des domaines non autorisés.
* Implémenter la logique de détection ci-dessus dans les **Secure Email Gateways** et les playbooks **SIEM/XSOAR**.
* Marquer ou mettre en quarantaine les messages où le domaine du nom d'affichage ≠ domaine de l'expéditeur.
* Éduquer les utilisateurs : copier-coller du texte suspect dans un inspecteur Unicode, survoler les liens, ne jamais faire confiance aux raccourcisseurs d'URL.

## Exemples du Monde Réel

* Nom d'affichage : `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillique `С`, `е`, `а`; Cherokee `Ꭲ`; petite capitale latine `ꮯ`).
* Chaîne de domaine : `bestseoservices.com` ➜ répertoire municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ faux login Microsoft à `mlcorsftpsswddprotcct.approaches.it.com` protégé par un CAPTCHA OTP personnalisé.
* Usurpation d'identité Spotify : expéditeur `Sρօtifւ` avec lien caché derrière `redirects.ca`.

Ces échantillons proviennent de la recherche de l'Unité 42 (juillet 2025) et illustrent comment l'abus de homoglyphes est combiné avec la redirection d'URL et l'évasion de CAPTCHA pour contourner l'analyse automatisée.

## Références

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
