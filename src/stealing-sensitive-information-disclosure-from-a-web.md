# Roubo de Informações Sensíveis a partir de uma Web

{{#include ./banners/hacktricks-training.md}}

Se em algum momento você encontrar uma **página da web que apresenta informações sensíveis com base na sua sessão**: Talvez esteja refletindo cookies, ou imprimindo detalhes de cartão de crédito ou qualquer outra informação sensível, você pode tentar roubá-la.\
Aqui apresento as principais maneiras que você pode tentar alcançar isso:

- [**CORS bypass**](pentesting-web/cors-bypass.md): Se você conseguir contornar os cabeçalhos CORS, poderá roubar as informações realizando uma solicitação Ajax para uma página maliciosa.
- [**XSS**](pentesting-web/xss-cross-site-scripting/): Se você encontrar uma vulnerabilidade XSS na página, pode ser capaz de abusar dela para roubar as informações.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Se você não conseguir injetar tags XSS, ainda pode ser capaz de roubar as informações usando outras tags HTML regulares.
- [**Clickjaking**](pentesting-web/clickjacking.md): Se não houver proteção contra esse ataque, você pode ser capaz de enganar o usuário para enviar os dados sensíveis (um exemplo [aqui](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
