# Roubo de Informações Sensíveis de uma Página Web

{{#include ../banners/hacktricks-training.md}}

Se uma **página web exibe informações sensíveis com base na sessão atual**—como cookies, dados da conta ou detalhes de cartão de crédito—um atacante pode tentar exfiltrá-las. As principais técnicas incluem:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Uma configuração incorreta de CORS pode permitir que uma origem maliciosa leia respostas sensíveis por meio de requisições cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Uma vulnerabilidade de XSS na origem-alvo pode permitir que JavaScript injetado leia e exfiltre as informações.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Quando a injeção de script não está disponível, elementos HTML injetados ainda podem capturar conteúdo sensível.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Se as proteções contra framing estiverem ausentes, um atacante pode induzir um usuário a interagir com a página sensível. O estudo de caso vinculado demonstra essa técnica.<sup>[[1]](#references)</sup>

## References

- [1] [Servlet de exemplo do Apache leva à divulgação de informações](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
