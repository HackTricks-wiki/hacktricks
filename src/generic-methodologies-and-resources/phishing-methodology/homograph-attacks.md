# Homograph / Homoglyph Attacks dans le Phishing

{{#include ../../banners/hacktricks-training.md}}

## Présentation

Une attaque Homograph (également appelée Homoglyph) exploite le fait que de nombreux **points de code Unicode provenant de scripts non latins sont visuellement identiques ou extrêmement similaires aux caractères ASCII**. En remplaçant un ou plusieurs caractères latins par leurs équivalents visuels, un attaquant peut créer :

* Des noms d'affichage, objets ou corps de messages qui semblent légitimes à l'œil humain, mais contournent les mécanismes de détection basés sur des mots-clés.
* Des domaines, sous-domaines ou chemins d'URL qui trompent les victimes en leur faisant croire qu'elles consultent un site de confiance.

Comme chaque glyphe est identifié en interne par son **point de code Unicode**, un seul caractère substitué suffit à contourner les comparaisons de chaînes naïves (par exemple, `"Παypal.com"` contre `"Paypal.com"`).

## Workflow de Phishing Typique

1. **Créer le contenu du message** – Remplacer certaines lettres latines de la marque / du mot-clé usurpé par des caractères visuellement indissociables provenant d'un autre script (grec, cyrillique, arménien, cherokee, etc.).
2. **Enregistrer l'infrastructure nécessaire** – Enregistrer éventuellement un domaine homoglyphe et obtenir un certificat TLS (la plupart des CA n'effectuent aucun contrôle de similarité visuelle).
3. **Envoyer un email / SMS** – Le message contient des homoglyphes dans un ou plusieurs des emplacements suivants :
* Nom d'affichage de l'expéditeur (par exemple, `Ηеlрdеѕk`)
* Ligne d'objet (`Urgеnt Аctіon Rеquіrеd`)
* Texte du lien hypertexte ou nom de domaine pleinement qualifié
4. **Chaîne de redirections** – La victime est redirigée par des sites semblant inoffensifs ou des raccourcisseurs d'URL avant d'arriver sur l'hôte malveillant qui récupère ses identifiants / distribue un malware.

## Plages Unicode Couramment Abusées

| Script | Plage | Exemple de glyphe | Ressemble à |
|--------|-------|---------------|------------|
| Grec  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Grec  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillique | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillique | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Arménien | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Conseil : Les tableaux Unicode complets sont disponibles sur [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Techniques de Détection

### 1. Inspection des Scripts Mixtes

Les emails de Phishing ciblant une organisation anglophone devraient rarement mélanger des caractères provenant de plusieurs scripts. Une heuristique simple mais efficace consiste à :

1. Parcourir chaque caractère de la chaîne inspectée.
2. Associer le point de code à son bloc Unicode.
3. Déclencher une alerte si plusieurs scripts sont présents **ou** si des scripts non latins apparaissent là où ils ne sont pas attendus (nom d'affichage, domaine, objet, URL, etc.).

Proof-of-concept Python :
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

Les noms de domaine internationalisés (IDN) sont encodés avec le **punycode** (`xn--`). Convertir chaque nom d’hôte en punycode, puis à nouveau en Unicode, permet d’effectuer une correspondance avec une whitelist ou des contrôles de similarité (par exemple, la distance de Levenshtein) **après** la normalisation de la chaîne.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Dictionnaires / algorithmes de Homoglyph

Des outils tels que **dnstwist** (`--homoglyph`) ou **urlcrazy** peuvent énumérer les permutations de domaines visuellement similaires et sont utiles pour les actions proactives de retrait / monitoring.<sup>[[3]](#references)</sup>

## Prévention et atténuation

* Appliquer des politiques DMARC/DKIM/SPF strictes – empêcher le spoofing depuis des domaines non autorisés.
* Implémenter la logique de détection ci-dessus dans les **Secure Email Gateways** et les playbooks **SIEM/XSOAR**.
* Signaler ou mettre en quarantaine les messages lorsque le domaine du nom affiché ≠ le domaine de l'expéditeur.
* Sensibiliser les utilisateurs : copier-coller les textes suspects dans un inspecteur Unicode, survoler les liens, ne jamais faire confiance aux raccourcisseurs d'URL.

## Exemples concrets

* Nom affiché : `Сonfidеntiаl Ꭲiꮯkеt` (`С`, `е`, `а` cyrilliques ; `Ꭲ` cherokee ; `ꮯ` en petite capitale latine).
* Chaîne de domaines : `bestseoservices.com` ➜ répertoire municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ fausse page de connexion Microsoft à l'adresse `mlcorsftpsswddprotcct.approaches.it.com`, protégée par un CAPTCHA OTP personnalisé.
* Usurpation de Spotify : expéditeur `Sρօtifս` avec un lien masqué derrière `redirects.ca`.

Ces échantillons proviennent d'une recherche de Unit 42 (juillet 2025) et montrent comment l'abus de Homoglyph est combiné à la redirection d'URL et au contournement des CAPTCHA afin de contourner l'analyse automatisée.<sup>[[1]](#references)</sup>

## Références

- [1] [L'illusion de Homograph : tout n'est pas ce qu'il semble être](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Base de données des caractères Unicode](https://home.unicode.org/)
- [3] [dnstwist – moteur de permutation de domaines](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
