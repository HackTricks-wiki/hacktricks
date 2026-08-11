# Forensics du cache Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Cette page résume comment trier les artefacts du cache de Discord Desktop pour trouver les médias mis en cache localement, les endpoints de webhook et corréler les activités. Le client desktop de Discord utilise Electron, et Electron stocke les données de session, notamment le disk cache, sous `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Où chercher (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Il s'agit des chemins par défaut utilisés par le parser référencé ; Electron permet à une application de remplacer `sessionData`, vérifiez donc le chemin réel du profil lors de l'acquisition.<sup>[[2]](#references)[[4]](#references)</sup>

La disposition `index` + `data_#` + `f_######` correspond au backend blockfile disk-cache de Chromium ; ne le qualifiez pas de Simple Cache sans avoir vérifié le backend, car Chromium documente des implémentations de cache distinctes.<sup>[[5]](#references)</sup>

Structures importantes sur le disque dans `Cache_Data`:
- `index`: index du cache Blockfile utilisé pour localiser les entrées.
- `data_#`: fichiers de blocs de taille fixe pouvant contenir des métadonnées du cache, des en-têtes HTTP et des données de réponse.
- `f_######`: fichiers séparés utilisés pour les données dépassant la limite des fichiers de blocs ; ces fichiers contiennent les données stockées sans les en-têtes des fichiers de blocs.

La suppression de messages, de channels ou de serveurs ne garantit pas la suppression des octets déjà mis en cache localement, mais Chromium peut évincer ou recréer les fichiers du cache à tout moment. Traitez les artefacts restants comme des éléments de preuve opportunistes et utilisez les dates de modification des fichiers uniquement comme de vagues indicateurs d'écriture locale, qui doivent être corrélés avec d'autres données de télémétrie.<sup>[[5]](#references)[[6]](#references)</sup>

## Ce qui peut être récupéré

Selon ce qui a été récupéré et n'a pas encore été évincé, le triage peut permettre de récupérer des pièces jointes, des médias, des URLs et des hashes de fichiers mis en cache ; le cache seul ne prouve pas qu'un élément a été exfiltré.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Pièces jointes et miniatures référencées par des URLs du CDN Discord.
- Images, GIFs et vidéos (par exemple, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` et `.webm`).
- URLs de webhook telles que `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Appels à l'API Discord tels que `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashes SHA-256 des médias récupérés, pour comparaison avec des datasets connus ou des feeds de renseignement.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rapide (manuel)

- Recherchez dans le cache les artefacts à forte valeur indicative. Ces motifs correspondent aux expressions d'URL du parser référencé et servent de filtres de triage, pas d'indicateurs exhaustifs.<sup>[[2]](#references)</sup>
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de pièces jointes/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Appels à l'API Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Triez les entrées mises en cache par date de modification afin d'établir une séquence approximative ; mtime est un indicateur du système de fichiers et ne permet pas à lui seul d'établir quand un objet Discord a été récupéré ou envoyé.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing des entrées f_* (corps HTTP + en-têtes)

Dans la disposition blockfile, les fichiers `f_######` sont des flux de données séparés et ne commencent pas nécessairement par une réponse HTTP complète. Si un fichier acquis contient effectivement des en-têtes HTTP sérialisés suivis de `\r\n\r\n`, séparez-les au premier délimiteur et examinez:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: pour déduire le type de média
- Content-Location ou X-Original-URL: URL distante d'origine pour la prévisualisation/la corrélation
- Content-Encoding: peut être gzip/deflate/br (Brotli).

Les médias peuvent ensuite être extraits en séparant les en-têtes du corps et, si nécessaire, décompressés selon `Content-Encoding` ; le parser référencé gère Brotli, gzip et deflate. La détection par magic bytes est utile lorsque `Content-Type` est absent, mais reste heuristique.<sup>[[2]](#references)</sup>

## DFIR automatisé: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Fonction: analyse récursivement le dossier de cache de Discord, trouve les URLs de webhook/API/pièces jointes, parse les corps `f_*`, extrait éventuellement les médias et produit des rapports HTML et CSV, ainsi qu'une timeline chronologique optionnelle avec des hashes SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Exemple d'utilisation de la CLI:
```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
--cache "$env:APPDATA\discord\Cache\Cache_Data" `
--outdir "C:\IR\discord-cache" `
--output discord_cache_report `
--format both `
--timeline `
--extra `
--carve `
--verbose
```
The CLI définit ces options et noms de sortie :<sup>[[2]](#references)</sup>
- --cache: Chemin vers le répertoire Discord Cache_Data
- --format html|csv|both
- --timeline: Génère une timeline CSV ordonnée (par heure de modification)
- --extra: Analyse également les répertoires frères Code Cache et GPUCache
- --carve: Extrait les médias des octets bruts du cache à l’aide de signatures de médias reconnues (images/vidéo)
- Output: `<output>.html`, `<output>.csv`, éventuellement `<output>_timeline.csv`, ainsi qu’un dossier `<output>_media` contenant les fichiers extraits ou récupérés par carving.

## Conseils pour l’analyste

- Corrélez l’heure de modification (mtime) des fichiers `f_*` et `data_*` avec les périodes d’activité de l’utilisateur ou de l’attaquant et avec une télémétrie indépendante ; mtime ne constitue pas un horodatage définitif de l’événement.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Hachez les médias récupérés (SHA-256) et comparez-les à des jeux de données connus comme malveillants ou liés à l’exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Traitez les URL de webhook extraites comme des identifiants. Ne les invoquez pas simplement pour tester leur disponibilité ; conservez-les de manière sécurisée, coordonnez leur révocation ou leur rotation, et utilisez la télémétrie réseau associée pour effectuer une retro-hunting.<sup>[[7]](#references)</sup>
- La suppression côté serveur ne garantit pas la destruction des octets mis en cache localement. Si l’acquisition est possible, collectez l’intégralité du répertoire `Cache` ainsi que les caches frères associés (`Code Cache`, `GPUCache`) avant leur éviction ou la recréation du cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Suite forensique Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Suite forensique Discord en CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Comment Discord a mis à niveau de manière transparente des millions d’utilisateurs vers une architecture 64 bits](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache disque](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord comme C2 et les preuves mises en cache laissées derrière](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooks Discord – Exécuter un webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
