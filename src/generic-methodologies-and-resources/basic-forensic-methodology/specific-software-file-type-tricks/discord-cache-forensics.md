# Analyse forensique du cache Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Cette page résume comment effectuer un triage des artefacts du cache de Discord Desktop afin de repérer les médias mis en cache localement, les endpoints de webhook et les éléments permettant de corréler l’activité. Le client de bureau Discord utilise Electron, qui stocke les données de session, notamment le cache disque, sous `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Où chercher (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Il s’agit des chemins par défaut utilisés par l’analyseur référencé ; Electron permet à une application de remplacer `sessionData`. Vérifiez donc le chemin réel du profil lors de l’acquisition.<sup>[[2]](#references)[[4]](#references)</sup>

La structure `index` + `data_#` + `f_######` correspond au backend de cache disque blockfile de Chromium. Ne la qualifiez pas de Simple Cache sans avoir vérifié le backend, car Chromium documente plusieurs implémentations de cache distinctes.<sup>[[5]](#references)</sup>

Principales structures sur disque dans `Cache_Data` :
- `index` : index du cache Blockfile utilisé pour localiser les entrées.
- `data_#` : fichiers de blocs de taille fixe pouvant contenir des métadonnées du cache, des en-têtes HTTP et des données de réponse.
- `f_######` : fichiers distincts utilisés pour les données dépassant la limite des fichiers de blocs ; ils contiennent les données stockées sans les en-têtes des fichiers de blocs.

La suppression de messages, de salons ou de serveurs ne garantit pas l’effacement des octets déjà mis en cache localement, mais Chromium peut évincer ou recréer les fichiers de cache à tout moment. Considérez les artefacts subsistants comme des éléments de preuve opportunistes, et n’utilisez les dates de modification des fichiers que comme de vagues indices d’écriture locale, à corréler avec d’autres données de télémétrie.<sup>[[5]](#references)[[6]](#references)</sup>

## Éléments pouvant être récupérés

Selon les données récupérées et pas encore évincées, le triage peut permettre de récupérer des pièces jointes, des médias, des URL et des hachages de fichiers mis en cache ; le cache seul ne prouve pas qu’un élément a été exfiltré.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Pièces jointes et miniatures référencées par des URL du CDN Discord.
- Images, GIF et vidéos (par exemple, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` et `.webm`).
- URL de webhook telles que `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Appels à l’API Discord tels que `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hachages SHA-256 des médias récupérés, à comparer à des jeux de données connus ou à des flux de renseignement.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rapide (manuel)

- Recherchez dans le cache les artefacts présentant un signal fort. Ces motifs reprennent les expressions d’URL de l’analyseur référencé ; ils servent de filtres de triage et ne constituent pas des indicateurs exhaustifs.<sup>[[2]](#references)</sup>
  - Endpoints de webhook :
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL de pièces jointes/CDN :
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Appels à l’API Discord :
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Triez les entrées du cache par date de modification pour établir une séquence approximative ; le mtime est un signal du système de fichiers et ne permet pas à lui seul d’établir quand un objet Discord a été récupéré ou envoyé.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analyse des entrées f_* (corps HTTP + en-têtes)

Dans la structure blockfile, les fichiers `f_######` sont des flux de données distincts et ne commencent pas nécessairement par une réponse HTTP complète. Si un fichier acquis contient des en-têtes HTTP sérialisés suivis de `\r\n\r\n`, séparez-les au premier délimiteur et examinez les éléments suivants :<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type : pour déduire le type de média
- Content-Location ou X-Original-URL : URL distante d’origine, utile pour l’aperçu et la corrélation
- Content-Encoding : peut être gzip/deflate/br (Brotli).

Les médias peuvent ensuite être extraits en séparant les en-têtes du corps et, éventuellement, en décompressant selon `Content-Encoding` ; l’analyseur référencé prend en charge Brotli, gzip et deflate. La détection par signature binaire est utile lorsque `Content-Type` est absent, mais reste heuristique.<sup>[[2]](#references)</sup>

## DFIR automatisé : Discord Forensic Suite (CLI/GUI)

- Dépôt : [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Fonction : analyse récursivement le dossier de cache Discord, recherche les URL de webhook/API/pièces jointes, analyse les corps `f_*`, peut éventuellement extraire les médias, puis génère des rapports HTML et CSV ainsi qu’une chronologie facultative avec des hachages SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Exemple d’utilisation en CLI :

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

La CLI définit les options et noms de sortie suivants :<sup>[[2]](#references)</sup>
- --cache: Chemin vers le répertoire Discord Cache_Data
- --format html|csv|both
- --timeline: Générer une chronologie CSV ordonnée (par date de modification)
- --extra: Analyser également les répertoires frères Code Cache et GPUCache
- --carve: Extraire des médias à partir des octets bruts du cache à l’aide de signatures de médias reconnues (images/vidéos)
- Sortie : `<output>.html`, `<output>.csv`, éventuellement `<output>_timeline.csv`, et un dossier `<output>_media` contenant les fichiers extraits ou récupérés.

## Conseils pour les analystes

- Corrélez la date de modification (mtime) des fichiers `f_*` et `data_*` avec les périodes d’activité de l’utilisateur ou de l’attaquant et avec des données de télémétrie indépendantes ; le mtime ne constitue pas un horodatage d’événement définitif.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calculez le hash des médias récupérés (SHA-256) et comparez-le à des jeux de données connus comme malveillants ou liés à l’exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Traitez les URL de webhook extraites comme des identifiants. Ne les invoquez pas uniquement pour vérifier si elles sont actives ; conservez-les de manière sécurisée, coordonnez leur révocation ou leur rotation, et utilisez les données de télémétrie réseau associées pour la recherche rétrospective des menaces.<sup>[[7]](#references)</sup>
- La suppression côté serveur ne garantit pas que les octets mis en cache localement ont été détruits. Si une acquisition est possible, collectez l’intégralité du répertoire `Cache` ainsi que les caches frères associés (`Code Cache`, `GPUCache`) avant leur éviction ou la recréation du cache.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Suite d’investigation forensique Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI de la suite d’investigation forensique Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Comment Discord a fait passer des millions d’utilisateurs à une architecture 64 bits sans interruption](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache disque](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord comme C2 et les preuves laissées dans le cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooks Discord – Exécuter un webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
