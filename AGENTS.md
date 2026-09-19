# AGENTS.md

Orientações para futuros agentes que trabalham neste repositório.

## Contexto do repositório

Este é o repositório principal do mdBook do HackTricks. O livro relacionado de cloud está em:

`/Users/carlospolop/git/hacktricks-cloud`

Alterações no comportamento compartilhado do tema/pesquisa geralmente precisam ser aplicadas em ambos os repositórios.

## Contrato de carregamento do índice de pesquisa

A interface de pesquisa personalizada está em:

`theme/ht_searcher.js`

Também pode haver uma cópia gerada em:

`book/theme/ht_searcher.js`

Se a produção estiver fazendo deploy do diretório `book/` já compilado, atualize ambas as cópias ou recompile o
livro antes do deploy.

A política de origem do índice de pesquisa é importante e sensível a custos:

- Em hosts públicos, carregue todos os candidatos específicos de cada idioma e de fallback somente de
`HackTricks-wiki/hacktricks-searchindex`. Nunca use como fallback a saída do mdBook da mesma origem;
  disponibilizar o índice grande de `hacktricks.wiki` em produção é caro.
- Em hosts localhost, `.local`/`.internal`, loopback, RFC1918, carrier-grade NAT, link-local ou endereços IPv6
  privados, carregue somente a saída do mdBook da mesma origem para que os deployments locais/de contêineres
  permaneçam autocontidos. Para uma página que não esteja em inglês, tente primeiro o caminho local prefixado
  pelo idioma (por exemplo, `/es/searchindex.js`) e use o índice raiz em inglês somente como fallback.

Para este repositório, o fallback local esperado é:

`/searchindex.js`

Em hosts privados, o índice cloud não está disponível a partir desta origem e não deve disparar um download
remoto. Em hosts públicos, ele deve usar os arquivos remotos `searchindex-cloud-<lang>.js.gz`.

## Publicação do índice de pesquisa

Os workflows que publicam índices de pesquisa compactados e criptografados em
`HackTricks-wiki/hacktricks-searchindex` são:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

O arquivo-fonte gerado é `book/searchindex.js`. Os nomes dos artefatos remotos publicados são:

- `searchindex-v2-en.json.gz` (índice compacto preferencial)
- `searchindex-v2-<lang>.json.gz` (índice compacto preferencial)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

O loader do navegador prioriza o artefato compacto v2 e mantém o artefato `.js.gz` como fallback legado. Ambos
são payloads gzip criptografados com XOR usando a chave definida em `theme/ht_searcher.js`.

O loader deve continuar lazy: a navegação normal pelas páginas não deve criar o search worker nem baixar um
índice até que o visitante abra ou use a pesquisa. As respostas remotas compactadas são persistidas no Cache
Storage por 24 horas por origem para que as páginas subsequentes possam reutilizá-las. Preserve o fallback do
cache obsoleto quando a atualização de uma entrada expirada falhar.

## Compilação e validação

Verificações locais comuns:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Se `mdbook build` falhar, verifique:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Notas de edição

- Prefira `rg` para pesquisas.
- Mantenha a saída `book/` gerada fora dos commits, salvo solicitação explícita. Correções no loader de pesquisa
  são uma exceção quando as páginas já compiladas precisam ser corrigidas imediatamente.
- Ao alterar o comportamento compartilhado do tema, compare e atualize o arquivo correspondente em
`/Users/carlospolop/git/hacktricks-cloud`.
- Não reverta alterações locais não relacionadas.
