# AGENTS.md

Orientações para futuros agentes que trabalham neste repositório.

## Contexto do repositório

Este é o repositório principal do HackTricks mdBook. O livro relacionado à cloud está em:

`/Users/carlospolop/git/hacktricks-cloud`

Alterações no comportamento compartilhado de tema/pesquisa geralmente precisam ser aplicadas em ambos os repositórios.

## Contrato de carregamento do índice de pesquisa

A interface de pesquisa personalizada está em:

`theme/ht_searcher.js`

Também pode haver uma cópia gerada em:

`book/theme/ht_searcher.js`

Se a produção estiver implantando o diretório `book/` já compilado, atualize ambas as cópias ou recompile o
book antes da implantação.

A ordem de carregamento do índice de pesquisa é importante e sensível a custos:

1. Carregue todos os índices de pesquisa específicos de idioma e de fallback do repositório do GitHub:
`HackTricks-wiki/hacktricks-searchindex`
2. Somente se todos os candidatos hospedados no GitHub falharem, use como fallback a saída do mdBook na mesma origem.

Não coloque o fallback local `/searchindex.js` antes de qualquer fallback hospedado no GitHub, como
`searchindex-en.js.gz`. Servir `searchindex.js` de `hacktricks.wiki` em produção é caro.

Para este repositório, o fallback local esperado é:

`/searchindex.js`

O índice da cloud não deve usar um fallback local desta origem. Ele deve depender dos arquivos remotos
`searchindex-cloud-<lang>.js.gz`.

## Publicação do índice de pesquisa

Os workflows que publicam índices de pesquisa comprimidos e criptografados em
`HackTricks-wiki/hacktricks-searchindex` são:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

O arquivo-fonte gerado é `book/searchindex.js`. Os nomes dos artefatos remotos publicados são:

- `searchindex-v2-en.json.gz` (índice compacto preferencial)
- `searchindex-v2-<lang>.json.gz` (índice compacto preferencial)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

O loader do navegador prioriza o artefato compacto v2 e mantém o artefato `.js.gz` como fallback
legado. Ambos são payloads gzip criptografados com XOR usando a chave definida em
`theme/ht_searcher.js`.

## Compilação e validação

Verificações locais comuns:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Se `mdbook build` falhar, verifique:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Observações de edição

- Prefira `rg` para pesquisas.
- Mantenha a saída gerada de `book/` fora dos commits, a menos que solicitado explicitamente. Correções do
  search loader são uma exceção quando as páginas já compiladas precisam ser corrigidas imediatamente.
- Ao alterar o comportamento compartilhado do tema, compare e atualize o arquivo correspondente em
`/Users/carlospolop/git/hacktricks-cloud`.
- Não reverta alterações locais não relacionadas.
