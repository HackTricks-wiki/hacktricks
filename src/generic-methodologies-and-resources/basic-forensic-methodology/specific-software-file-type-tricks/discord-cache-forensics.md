# Forense de Cache do Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume como realizar a triagem dos artefatos de cache do Discord Desktop para recuperar arquivos exfiltrados, endpoints de webhook e linhas do tempo de atividade. O Discord Desktop é um app Electron/Chromium e usa Chromium Simple Cache no disco.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Principais estruturas no disco dentro de Cache_Data:
- index: base de dados de índice do Simple Cache
- data_#: arquivos binários de blocos de cache que podem conter múltiplos objetos em cache
- f_######: entradas de cache individuais armazenadas como arquivos independentes (frequentemente corpos maiores)

Observação: Excluir mensagens/canais/servidores no Discord não purga esse cache local. Os itens em cache frequentemente permanecem e os carimbos de data/hora dos arquivos alinham‑se com a atividade do usuário, permitindo reconstrução da linha do tempo.

## What can be recovered

- Anexos exfiltrados e miniaturas buscados via cdn.discordapp.com/media.discordapp.net
- Imagens, GIFs, vídeos (ex.: .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API calls (https://discord.com/api/vX/…)
- Útil para correlacionar beaconing/exfil e para calcular hashes de mídia para correspondência de inteligência

## Quick triage (manual)

- Grep no cache por artefatos de alto sinal:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordene entradas em cache por tempo de modificação para construir uma timeline rápida (mtime reflete quando o objeto chegou ao cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

Arquivos começando com f_ contêm cabeçalhos de resposta HTTP seguidos pelo corpo. O bloco de cabeçalho normalmente termina com \r\n\r\n. Cabeçalhos de resposta úteis incluem:
- Content-Type: Para inferir o tipo de mídia
- Content-Location or X-Original-URL: URL remota original para pré-visualização/correlação
- Content-Encoding: Pode ser gzip/deflate/br (Brotli)

A mídia pode ser extraída separando os cabeçalhos do corpo e, opcionalmente, descomprimindo com base em Content-Encoding. A detecção por magic bytes é útil quando Content-Type está ausente.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Escaneia recursivamente a pasta de cache do Discord, encontra URLs de webhook/API/anexos, analisa corpos f_*, opcionalmente realiza carving de mídia, e gera relatórios de timeline em HTML + CSV com hashes SHA‑256.

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
Key options:
- --cache: Caminho para Cache_Data
- --format html|csv|both
- --timeline: Emitir CSV de timeline ordenado (por hora de modificação)
- --extra: Também escanear caches irmãos Code Cache e GPUCache
- --carve: Carve mídia de bytes brutos próximos a hits de regex (imagens/vídeo)
- Output: HTML report, CSV report, CSV timeline, e uma pasta de mídia com arquivos carved/extracted

## Dicas para analistas

- Correlacione o modified time (mtime) de arquivos f_* e data_* com janelas de atividade do usuário/atacante para reconstruir uma timeline.
- Calcule o hash da mídia recuperada (SHA-256) e compare com conjuntos de dados conhecidos como maliciosos ou de exfiltração.
- URLs de webhook extraídas podem ser testadas quanto à liveness ou rotacionadas; considere adicioná-las a blocklists e retro-hunting proxies.
- O Cache persiste após “wiping” no lado do servidor. Se for possível adquirir, colete todo o diretório Cache e caches irmãos relacionados (Code Cache, GPUCache).

## Referências

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
