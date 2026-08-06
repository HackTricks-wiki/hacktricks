# Forensics do Cache do Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume como fazer a triagem de artefatos do cache do Discord Desktop para recuperar arquivos exfiltrados, endpoints de webhook e linhas do tempo de atividades. O Discord Desktop é um app Electron/Chromium e usa o Chromium Simple Cache no disco.

## Onde procurar (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Principais estruturas em disco dentro de Cache_Data:<sup>[[1]](#references)</sup>
- index: banco de dados de índice do Simple Cache
- data_#: arquivos de bloco de cache binários que podem conter vários objetos em cache
- f_######: entradas individuais em cache armazenadas como arquivos independentes (geralmente corpos maiores)

Observação: excluir mensagens/canais/servidores no Discord não limpa este cache local. Os itens em cache frequentemente permanecem, e os timestamps dos arquivos correspondem à atividade do usuário, permitindo a reconstrução de uma linha do tempo.<sup>[[1]](#references)</sup>

## O que pode ser recuperado

- Anexos exfiltrados e miniaturas obtidas via cdn.discordapp.com/media.discordapp.net
- Imagens, GIFs, vídeos (por exemplo, .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Chamadas à API do Discord (https://discord.com/api/vX/…)
- Útil para correlacionar beaconing/atividade de exfiltração e gerar hashes de mídia para correspondência com informações de inteligência<sup>[[1]](#references)</sup>

## Triagem rápida (manual)

- Faça grep no cache em busca de artefatos de alto valor:
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de anexos/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Chamadas à API do Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordene as entradas em cache por horário de modificação para criar rapidamente uma linha do tempo (mtime reflete quando o objeto entrou no cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analisando entradas f_* (corpo HTTP + headers)

Os arquivos que começam com f_ contêm headers de resposta HTTP seguidos pelo corpo. O bloco de headers normalmente termina com \r\n\r\n. Headers de resposta úteis incluem:
- Content-Type: para inferir o tipo de mídia
- Content-Location ou X-Original-URL: URL remota original para preview/correlação
- Content-Encoding: pode ser gzip/deflate/br (Brotli)

A mídia pode ser extraída separando os headers do corpo e, opcionalmente, descompactando-a com base em Content-Encoding. A identificação por magic bytes é útil quando Content-Type está ausente.

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Função: examina recursivamente a pasta de cache do Discord, encontra URLs de webhook/API/anexos, analisa corpos f_*, opcionalmente extrai mídia e gera relatórios de linha do tempo em HTML + CSV com hashes SHA-256.<sup>[[2]](#references)</sup>

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
- --timeline: Emite uma timeline CSV ordenada (por tempo de modificação)
- --extra: Também verifica Code Cache e GPUCache adjacentes
- --carve: Extrai mídia de bytes brutos próximos a correspondências de regex (imagens/vídeo)
- Saída: relatório HTML, relatório CSV, timeline CSV e uma pasta de mídia com arquivos extraídos/carved

## Dicas para analistas

- Correlacione o tempo de modificação (mtime) dos arquivos f_* e data_* com as janelas de atividade do usuário/atacante para reconstruir uma timeline.
- Faça o hash da mídia recuperada (SHA-256) e compare com datasets conhecidos de conteúdo malicioso ou exfiltrado.
- URLs de webhook extraídas podem ser testadas quanto à disponibilidade ou rotacionadas; considere adicioná-las a blocklists e realizar retro-hunting em proxies.
- O Cache persiste após o “apagamento” no lado do servidor. Se a aquisição for possível, colete todo o diretório Cache e os caches adjacentes relacionados (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Referências

- [1] [Discord como C2 e as evidências armazenadas em cache deixadas para trás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
