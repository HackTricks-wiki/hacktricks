# Forensics do Cache do Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume como fazer a triagem de artefatos do cache do Discord Desktop para recuperar arquivos exfiltrados, endpoints de webhook e linhas do tempo de atividades. O Discord Desktop é um app Electron/Chromium e usa o Chromium Simple Cache no disco.

## Onde procurar (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Principais estruturas no disco dentro de Cache_Data:<sup>[[1]](#references)</sup>
- index: banco de dados de índice do Simple Cache
- data_#: arquivos de bloco de cache binários que podem conter vários objetos em cache
- f_######: entradas individuais em cache armazenadas como arquivos independentes (geralmente corpos maiores)

Observação: excluir mensagens/canais/servidores no Discord não limpa esse cache local. Itens em cache frequentemente permanecem, e os timestamps dos arquivos costumam estar alinhados com a atividade do usuário, permitindo a reconstrução de uma linha do tempo.<sup>[[1]](#references)</sup>

## O que pode ser recuperado

- Anexos exfiltrados e thumbnails obtidos via cdn.discordapp.com/media.discordapp.net
- Imagens, GIFs, vídeos (por exemplo, .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Chamadas à Discord API (https://discord.com/api/vX/…)
- Útil para correlacionar beaconing/atividade de exfiltração e fazer hashing de mídias para comparação com inteligência<sup>[[1]](#references)</sup>

## Triagem rápida (manual)

- Use grep no cache para encontrar artefatos de alto sinal:
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de anexos/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Chamadas à Discord API:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordene as entradas em cache pelo horário de modificação para criar rapidamente uma linha do tempo (mtime reflete quando o objeto entrou no cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisando entradas f_* (corpo HTTP + headers)

Os arquivos que começam com f_ contêm headers da resposta HTTP seguidos pelo corpo. O bloco de headers normalmente termina com \r\n\r\n. Headers de resposta úteis incluem:
- Content-Type: Para inferir o tipo de mídia
- Content-Location ou X-Original-URL: URL remota original para preview/correlação
- Content-Encoding: Pode ser gzip/deflate/br (Brotli)

A mídia pode ser extraída separando os headers do corpo e, opcionalmente, descompactando-a com base em Content-Encoding. A identificação por magic bytes é útil quando Content-Type está ausente.

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Função: Examina recursivamente a pasta de cache do Discord, encontra URLs de webhook/API/anexos, analisa corpos f_*, opcionalmente faz carving de mídias e gera relatórios de linha do tempo em HTML + CSV com hashes SHA‑256.<sup>[[2]](#references)</sup>

Exemplo de uso da CLI:
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
Opções principais:
- --cache: Caminho para Cache_Data
- --format html|csv|both
- --timeline: Emitir uma timeline CSV ordenada (por tempo de modificação)
- --extra: Também verificar os diretórios irmãos Code Cache e GPUCache
- --carve: Extrair mídia de raw bytes próximos a correspondências de regex (imagens/vídeo)
- Output: relatório HTML, relatório CSV, timeline CSV e uma pasta de mídia com arquivos extraídos/carved

## Dicas para analistas

- Correlacione o tempo de modificação (mtime) dos arquivos f_* e data_* com as janelas de atividade do usuário/atacante para reconstruir uma timeline.
- Faça o hash da mídia recuperada (SHA-256) e compare com datasets conhecidos de arquivos maliciosos ou exfiltrados.
- As URLs de webhook extraídas podem ser testadas quanto à disponibilidade ou rotacionadas; considere adicioná-las a blocklists e realizar retro-hunting em proxies.
- O Cache persiste após o “wiping” no lado do servidor. Se a aquisição for possível, colete todo o diretório Cache e os caches irmãos relacionados (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Referências

- [1] [Discord como C2 e as evidências armazenadas em cache deixadas para trás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Executar Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
