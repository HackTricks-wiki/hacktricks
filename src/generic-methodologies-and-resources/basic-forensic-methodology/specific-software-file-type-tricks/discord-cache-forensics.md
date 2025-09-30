# Forensique du cache Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Cette page résume comment effectuer le triage des artefacts de cache de Discord Desktop pour récupérer des fichiers exfiltrés, des endpoints webhook, et des timelines d'activité. Discord Desktop est une application Electron/Chromium et utilise Chromium Simple Cache sur disque.

## Où chercher (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Structures clés sur disque dans Cache_Data :
- index: Simple Cache index database
- data_#: Fichiers binaires de blocs de cache pouvant contenir plusieurs objets mis en cache
- f_######: Entrées mises en cache individuelles stockées comme fichiers autonomes (souvent des contenus plus volumineux)

Remarque : La suppression de messages/channels/serveurs dans Discord ne purge pas ce cache local. Les éléments mis en cache restent souvent présents et leurs timestamps de fichiers correspondent à l'activité utilisateur, permettant la reconstruction d'une timeline.

## Ce qui peut être récupéré

- Pièces jointes exfiltrées et vignettes récupérées via cdn.discordapp.com/media.discordapp.net
- Images, GIFs, vidéos (ex. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Appels API Discord (https://discord.com/api/vX/…)
- Utile pour corréler beaconing/exfil activity et hacher les médias pour la correspondance d'intel

## Triage rapide (manuel)

- Grep le cache pour des artefacts à fort signal :
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Trier les entrées mises en cache par date de modification pour construire rapidement une timeline (mtime reflète le moment où l'objet a été placé en cache) :
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Les fichiers commençant par f_ contiennent les en-têtes de la réponse HTTP suivis du body. Le bloc d'en-têtes se termine typiquement par \r\n\r\n. En-têtes de réponse utiles :
- Content-Type: Permet d'inférer le type de média
- Content-Location or X-Original-URL: URL distante originale pour corrélation/aperçu
- Content-Encoding: Peut être gzip/deflate/br (Brotli)

Les médias peuvent être extraits en séparant les en-têtes du corps et en décompressant au besoin selon Content-Encoding. Le magic-byte sniffing est utile lorsque Content-Type est absent.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Fonction : Scanne récursivement le dossier de cache de Discord, trouve les URLs webhook/API/attachments, parse les bodies f_*, extrait éventuellement les médias (carving), et produit des rapports timeline en HTML + CSV avec des hashes SHA‑256.

Example CLI usage:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
Options clés:
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: Emit ordered CSV timeline (by modified time)
- --extra: Also scan sibling Code Cache and GPUCache
- --carve: Carve media from raw bytes near regex hits (images/video)
- Sortie: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Conseils pour l'analyste

- Corréler le temps de modification (mtime) des fichiers f_* et data_* avec les fenêtres d'activité user/attacker pour reconstruire une chronologie.
- Calculer le hash des médias récupérés (SHA-256) et les comparer aux jeux de données known-bad ou exfil.
- Les URL de webhook extraites peuvent être testées pour liveness ou rotées ; envisager de les ajouter aux blocklists et aux proxies de retro-hunting.
- Le Cache persiste après un “wiping” côté serveur. Si l'acquisition est possible, collecter l'intégralité du répertoire Cache et les caches voisins liés (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
