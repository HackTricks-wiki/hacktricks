# GitHub Issues e arquivos de repositório como canal C2

{{#include ../banners/hacktricks-training.md}}

Um repositório privado pode separar o **estado da sessão** da **transferência de payloads**: as issues registram cada host e o estado do handshake, enquanto os arquivos do repositório transportam dados criptografados nas duas direções. Isso vai além de simplesmente consultar o corpo de uma issue em busca de comandos. A implementação observada usa um token de acesso pessoal (PAT) do GitHub para acessar ambas as APIs.<sup>[[1]](#references)</sup> Para um PAT de granularidade fina, criar ou atualizar issues exige permissão de gravação em Issues, e enviar arquivos exige permissão de gravação em Contents. Um PAT clássico, por sua vez, precisa do escopo `repo`. Qualquer pessoa que obtenha um token com privilégios suficientes pode acessar o mesmo canal.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake de issue e arquivo

Um fluxo de trabalho observado usa um ID de host hexadecimal curto e a seguinte máquina de estados. O intervalo exato de IDs, as strings e os prefixos são marcadores do protocolo, não requisitos da API do GitHub.<sup>[[1]](#references)</sup>

1. Na inicialização, consulte as issues abertas e fechadas com `GET /repos/{owner}/{repo}/issues?state=open` (e `state=closed`) para encontrar o estado de sessões anteriores. Crie uma issue aberta intitulada `1[ID]` com o corpo `hel` usando `POST /repos/{owner}/{repo}/issues`.
2. Leia um arquivo do repositório cujo nome comece com `2[ID]`; ele fornece a chave pública RSA do servidor. Gere uma nova chave de sessão de 16 bytes, criptografe-a com RSA e envie o resultado em um arquivo com o prefixo `1[ID]`.
3. Derive o IV subsequente aplicando XOR à chave de sessão e ao IV incorporado. Para cada arquivo trocado, use a chave aleatória de 16 bytes presente no nome do arquivo para criptografar ou descriptografar o conteúdo com AES. O prefixo `2` indica dados do servidor para o host; o prefixo `1` indica dados do host para o servidor. Assim, o nome do arquivo contém informações de roteamento e o material da chave por arquivo, enquanto a issue contém o estado.
4. Leia o próximo arquivo com prefixo `2` e exija que seu conteúdo descriptografado seja igual a `hel`. Envie informações criptografadas do host e, em seguida, altere o corpo da issue para `hey` com `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Só então comece a consultar comandos.

A API Contents do GitHub lê um arquivo por meio de `GET /repos/{owner}/{repo}/contents/{path}` e cria ou substitui um arquivo por meio de `PUT` nesse caminho. Para arquivos de até 1 MB, a resposta JSON padrão inclui o conteúdo codificado em Base64; arquivos entre 1 e 100 MB exigem o tipo de mídia raw para recuperar o conteúdo. O corpo do envio precisa de uma mensagem de commit e do conteúdo do arquivo codificado em Base64; para substituir um arquivo existente, também é necessário o SHA do blob atual. Esses detalhes da API são distintos do protocolo de criptografia acima.<sup>[[2]](#references)[[3]](#references)</sup>

Em um repositório de teste autorizado, a parte de controle por issue pode ser exercitada com a API REST (substitua por um repositório de teste e um PAT de teste). Não coloque um token ativo na URL, no corpo de uma issue ou em um arquivo commitado.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

O mecanismo **não** exige o título da issue, os marcadores `hel`/`hey` ou as escolhas específicas de cifras mostradas aqui; esses elementos identificam uma implementação. A ideia reutilizável é separar o estado mutável do host dos objetos criptografados bidirecionais e vincular ambos a um ID de host.<sup>[[1]](#references)</sup> Para outro transporte via GitHub issue, consulte as [notas do listener personalizado do AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Para uma alternativa usando comentários de issue que rotaciona as credenciais do repositório em vez de transportar o estado da sessão, consulte [Serviços web e resolvedores dead-drop](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Operação FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Endpoints da API REST para issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Endpoints da API REST para o conteúdo do repositório](https://docs.github.com/en/rest/repos/contents)
