# Obtendo a divulgação de informações sensíveis de uma Web

{{#include ../banners/hacktricks-training.md}}

Se em algum momento você encontrar uma **página web que apresente informações sensíveis com base na sua sessão**: talvez ela esteja refletindo cookies, exibindo detalhes de cartões de crédito ou qualquer outra informação sensível, você pode tentar roubá-la.\
Aqui apresento as principais maneiras de tentar fazer isso:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Se você conseguir contornar os headers de CORS, poderá roubar as informações realizando uma requisição Ajax a partir de uma página maliciosa.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Se encontrar uma vulnerabilidade de XSS na página, poderá explorá-la para roubar as informações.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Se não conseguir injetar tags XSS, ainda poderá roubar as informações usando outras tags HTML comuns.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Se não houver proteção contra esse ataque, você poderá induzir o usuário a enviar os dados sensíveis para você (um exemplo [aqui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Referências

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
