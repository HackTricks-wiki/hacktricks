# Attaques Homograph / Homoglyph dans le Phishing

## Vue d’ensemble

Une attaque homograph (ou homoglyph) exploite le fait que de nombreux **points de code Unicode issus de scripts non latins sont visuellement identiques ou extrêmement similaires aux caractères ASCII**. En remplaçant un ou plusieurs caractères latins par leurs équivalents ressemblants, un attaquant peut créer :

* Des noms d’affichage, objets ou corps de message qui semblent légitimes à l’œil humain, mais contournent les détections fondées sur des mots-clés.
* Des domaines, sous-domaines ou chemins d’URL qui trompent les victimes et leur font croire qu’elles consultent un site de confiance.<sup>[[1]](#references)</sup>

Comme chaque glyphe est identifié en interne par son **point de code Unicode**, un seul caractère substitué suffit à contourner les comparaisons de chaînes naïves (par exemple, `"Παypal.com"` contre `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Workflow de Phishing typique

1. **Créer le contenu du message** – Remplacer certaines lettres latines de la marque / du mot-clé usurpé par des caractères visuellement indiscernables provenant d’un autre script (grec, cyrillique, arménien, cherokee, etc.).
2. **Enregistrer l’infrastructure de support** – Enregistrer éventuellement un domaine homoglyph et obtenir un certificat TLS (la plupart des CA n’effectuent aucune vérification de similarité visuelle).
3. **Envoyer un email / SMS** – Le message contient des homoglyphs dans un ou plusieurs des emplacements suivants :
* Nom d’affichage de l’expéditeur (par exemple, `Ηеlрdеѕk`)
* Objet (`Urgеnt Аctіon Rеquіrеd`)
* Texte du lien hypertexte ou nom de domaine entièrement qualifié
4. **Chaîne de redirections** – La victime est redirigée via des sites apparemment inoffensifs ou des raccourcisseurs d’URL avant d’atteindre l’hôte malveillant qui récupère les identifiants / distribue des malwares.<sup>[[1]](#references)</sup>

## Plages Unicode fréquemment exploitées

Les exemples suivants sont des blocs Unicode contenant des caractères couramment utilisés pour créer des ressemblances inter-scripts.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Plage | Glyphe d’exemple | Ressemble à |
|--------|-------|------------------|-------------|
| Grec  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Grec  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillique | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillique | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Arménien | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Conseil : utilisez les tables de caractères Unicode pour rechercher les blocs et les points de code.

## Techniques de détection

### 1. Inspection des scripts mixtes

Les emails de Phishing ciblant une organisation anglophone devraient rarement mélanger des caractères issus de plusieurs scripts. Une heuristique simple, mais efficace, consiste à :

1. Parcourir chaque caractère de la chaîne inspectée.
2. Associer le point de code à son nom de script ou à son bloc Unicode.
3. Déclencher une alerte si plusieurs scripts sont présents **ou** si des scripts non latins apparaissent là où ils ne sont pas attendus (nom d’affichage, domaine, objet, URL, etc.).<sup>[[3]](#references)</sup>

Preuve de concept Python :
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
### 2. Punycode Normalisation (domaines)

Les noms de domaine internationalisés (IDN) disposent d’une forme Unicode et d’une forme **Punycode** compatible ASCII, préfixée par `xn--`. Convertissez les noms d’hôte au format IDNA/Punycode avant de les ajouter à une allow-list ou de les comparer, tout en conservant la forme Unicode pour l’affichage.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Dictionnaires / algorithmes d’homoglyphes

Des outils tels que **dnstwist** (`--fuzzers homoglyph`) ou **urlcrazy** peuvent énumérer les permutations de domaines visuellement similaires et sont utiles pour le takedown / monitoring proactif.<sup>[[4]](#references)[[5]](#references)</sup>

## Prévention et mitigation

* Appliquer des politiques DMARC/DKIM/SPF strictes – empêcher le spoofing depuis des domaines non autorisés.
* Implémenter la logique de détection ci-dessus dans les **Secure Email Gateways** et les playbooks **SIEM/XSOAR**.
* Signaler ou mettre en quarantaine les messages dont le domaine du nom affiché ≠ le domaine de l’expéditeur.
* Sensibiliser les utilisateurs : copier-coller le texte suspect dans un inspecteur Unicode, survoler les liens et ne jamais faire confiance aux raccourcisseurs d’URL.

## Exemples concrets

* Nom affiché : `Сonfidеntiаl Ꭲiꮯkеt` (`С`, `е`, `а` cyrilliques ; `Ꭲ` cherokee ; `ꮯ` en petite capitale latine).
* Chaîne de domaines : `bestseoservices.com` ➜ répertoire municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ fausse page de connexion Microsoft sur `mlcorsftpsswddprotcct.approaches.it.com`, protégée par un CAPTCHA OTP personnalisé.
* Usurpation de Spotify : expéditeur `Sρօtifս` avec un lien dissimulé derrière `redirects.ca`.

Ces exemples proviennent d’une étude de Unit 42 (juillet 2025) et montrent comment l’abus d’homoglyphes est combiné à la redirection d’URL et à l’évasion de CAPTCHA pour contourner l’analyse automatisée.<sup>[[1]](#references)</sup>

## References

- [1] [L’illusion des homoglyphes : tout n’est pas ce qu’il semble être](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tableaux des codes de caractères Unicode](https://www.unicode.org/charts/)
- [3] [Norme technique Unicode n° 39 : mécanismes de sécurité Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – moteur de permutation de domaines](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – générateur de fautes de frappe et de variations de domaines](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890 : noms de domaine internationalisés pour les applications (IDNA) : définitions et cadre documentaire](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
