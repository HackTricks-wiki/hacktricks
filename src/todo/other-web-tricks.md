# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Várias vezes, o back-end confia no **Host header** para executar determinadas ações. Por exemplo, ele pode usar o valor como o **domínio para enviar um password reset**. Portanto, quando você recebe um email com um link para resetar sua senha, o domínio usado é aquele que você colocou no Host header. Então, você pode solicitar o password reset de outros usuários e alterar o domínio para um domínio controlado por você, a fim de roubar os códigos de password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Observe que talvez nem seja necessário esperar o usuário clicar no link de reset password para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.

### Session booleans

Às vezes, quando você conclui alguma verificação corretamente, o back-end **simplesmente adiciona um booleano com o valor "True" a um atributo de segurança da sua sessão**. Então, um endpoint diferente saberá se você passou nessa verificação com sucesso.\
No entanto, se você **passar na verificação** e sua sessão receber esse valor "True" no atributo de segurança, você pode tentar **acessar outros recursos** que **dependem do mesmo atributo**, mas aos quais você **não deveria ter permissão** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Tente se registrar como um usuário que já existe. Tente também usar caracteres equivalentes (pontos, vários espaços e Unicode).

### Takeover emails

Registre um email e, antes de confirmá-lo, altere o email. Então, se o novo email de confirmação for enviado para o primeiro email registrado, você poderá assumir o controle de qualquer email. Ou, se puder habilitar o segundo email confirmando o primeiro, também poderá assumir o controle de qualquer conta.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Os desenvolvedores podem esquecer de desabilitar várias opções de debugging no ambiente de produção. Por exemplo, o método HTTP `TRACE` foi projetado para fins de diagnóstico. Se estiver habilitado, o web server responderá às requisições que usam o método `TRACE` ecoando na resposta a requisição exata que foi recebida. Esse comportamento geralmente é inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de headers de autenticação internos que podem ser adicionados às requisições por reverse proxies.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Referências

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
