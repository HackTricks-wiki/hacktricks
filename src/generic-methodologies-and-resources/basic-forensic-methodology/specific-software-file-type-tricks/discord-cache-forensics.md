# Análise forense do cache do Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume como fazer a triagem de artefatos do cache do Discord Desktop em busca de mídia armazenada localmente, endpoints de webhook e correlação de atividade. O cliente desktop do Discord usa Electron, e o Electron armazena dados da sessão, como o cache em disco, em `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Onde procurar (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Estes são os caminhos padrão usados pelo parser referenciado; o Electron permite que um aplicativo substitua `sessionData`, então confirme o caminho real do perfil durante a aquisição.<sup>[[2]](#references)[[4]](#references)</sup>

A estrutura `index` + `data_#` + `f_######` corresponde ao backend de cache em disco blockfile do Chromium; não a classifique como Simple Cache sem verificar o backend, pois o Chromium documenta implementações de cache distintas.<sup>[[5]](#references)</sup>

Principais estruturas em disco dentro de `Cache_Data`:
- `index`: índice do cache Blockfile usado para localizar entradas.
- `data_#`: arquivos de blocos de tamanho fixo que podem conter metadados do cache, cabeçalhos HTTP e dados de resposta.
- `f_######`: arquivos separados usados para dados maiores que o limite dos arquivos de bloco; contêm os dados armazenados sem os cabeçalhos dos arquivos de bloco.

Excluir mensagens, canais ou servidores não garante a remoção dos bytes já armazenados localmente em cache, mas o Chromium pode remover ou recriar arquivos de cache a qualquer momento. Trate os artefatos restantes como evidências oportunísticas e use os horários de modificação dos arquivos apenas como sinais aproximados de gravação local, que devem ser correlacionados com outras telemetrias.<sup>[[5]](#references)[[6]](#references)</sup>

## O que pode ser recuperado

Dependendo do que foi buscado e ainda não foi removido do cache, a triagem pode recuperar anexos, mídia, URLs e hashes de arquivos em cache; o cache, por si só, não comprova que um item foi exfiltrado.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Anexos e miniaturas referenciados por URLs do Discord CDN.
- Imagens, GIFs e vídeos (por exemplo, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` e `.webm`).
- URLs de webhook, como `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Chamadas à API do Discord, como `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashes SHA-256 de mídia recuperada para comparação com conjuntos de dados conhecidos ou feeds de inteligência.<sup>[[1]](#references)[[2]](#references)</sup>

## Triagem rápida (manual)

- Use grep no cache para encontrar artefatos de alto sinal. Estes padrões correspondem às expressões de URL do parser referenciado e são filtros de triagem, não indicadores exaustivos.<sup>[[2]](#references)</sup>
  - Endpoints de webhook:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URLs de anexos/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Chamadas à API do Discord:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordene as entradas em cache pelo horário de modificação para montar uma sequência aproximada; mtime é um sinal do sistema de arquivos e, por si só, não determina quando um objeto do Discord foi buscado ou enviado.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Análise de entradas f_* (corpo HTTP + cabeçalhos)

Na estrutura blockfile, os arquivos `f_######` são fluxos de dados separados e não há garantia de que comecem com uma resposta HTTP completa. Se um arquivo adquirido contiver cabeçalhos HTTP serializados seguidos por `\r\n\r\n`, divida-o no primeiro delimitador e examine:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: para inferir o tipo de mídia
- Content-Location ou X-Original-URL: URL remota original para pré-visualização/correlação
- Content-Encoding: pode ser gzip/deflate/br (Brotli).

A mídia pode então ser extraída separando os cabeçalhos do corpo e, opcionalmente, descomprimindo-a de acordo com `Content-Encoding`; o parser referenciado lida com Brotli, gzip e deflate. A análise dos bytes mágicos é útil quando `Content-Type` está ausente, mas continua sendo uma heurística.<sup>[[2]](#references)</sup>

## DFIR automatizada: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Função: examina recursivamente a pasta de cache do Discord, encontra URLs de webhook/API/anexos, analisa corpos `f_*`, opcionalmente extrai mídia e gera relatórios HTML e CSV, além de uma linha do tempo cronológica opcional com hashes SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Exemplo de uso da CLI:

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

A CLI define estas opções e nomes de saída:<sup>[[2]](#references)</sup>
- --cache: Caminho para o diretório Discord Cache_Data
- --format html|csv|both
- --timeline: Gera uma linha do tempo CSV ordenada (por hora de modificação)
- --extra: Também verifica Code Cache e GPUCache no mesmo diretório
- --carve: Extrai arquivos de mídia dos bytes brutos do cache usando assinaturas de mídia reconhecidas (imagens/vídeo)
- Saída: `<output>.html`, `<output>.csv`, opcionalmente `<output>_timeline.csv` e uma pasta `<output>_media` com arquivos extraídos ou recuperados.

## Dicas para analistas

- Correlacione a hora de modificação (mtime) dos arquivos `f_*` e `data_*` com períodos de atividade do usuário ou do invasor e telemetria independente; o mtime não é um registro definitivo da hora do evento.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcule o hash da mídia recuperada (SHA-256) e compare com conjuntos de dados de arquivos maliciosos conhecidos ou de exfiltração.<sup>[[1]](#references)[[2]](#references)</sup>
- Trate URLs de webhook extraídas como credenciais. Não as acione apenas para testar se estão ativas; preserve-as com segurança, coordene a revogação ou rotação e use a telemetria de rede relacionada para buscar atividades anteriores.<sup>[[7]](#references)</sup>
- A exclusão no servidor não garante que os bytes armazenados localmente em cache tenham sido destruídos. Se for possível adquirir os dados, colete todo o diretório `Cache` e os caches relacionados no mesmo diretório (`Code Cache`, `GPUCache`) antes que sejam removidos ou recriados.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Como o Discord atualizou perfeitamente milhões de usuários para a arquitetura de 64 bits](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache de disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord como C2 e as evidências em cache deixadas para trás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooks do Discord – Executar webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
