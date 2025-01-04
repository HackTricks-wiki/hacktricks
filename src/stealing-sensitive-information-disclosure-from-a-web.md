# Roubo de Divulgação de Informações Sensíveis de um Web

{{#include ./banners/hacktricks-training.md}}

Se em algum momento você encontrar uma **página da web que apresenta informações sensíveis com base na sua sessão**: Talvez esteja refletindo cookies, ou imprimindo detalhes de cartão de crédito ou qualquer outra informação sensível, você pode tentar roubá-la.\
Aqui apresento as principais maneiras que você pode tentar alcançar isso:

- [**CORS bypass**](pentesting-web/cors-bypass.md): Se você conseguir contornar os cabeçalhos CORS, poderá roubar as informações realizando uma solicitação Ajax para uma página maliciosa.
- [**XSS**](pentesting-web/xss-cross-site-scripting/index.html): Se você encontrar uma vulnerabilidade XSS na página, poderá abusar dela para roubar as informações.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/index.html): Se você não conseguir injetar tags XSS, ainda poderá roubar as informações usando outras tags HTML regulares.
- [**Clickjaking**](pentesting-web/clickjacking.md): Se não houver proteção contra esse ataque, você poderá enganar o usuário para enviar os dados sensíveis (um exemplo [aqui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
