# Outras técnicas Web

{{#include ../banners/hacktricks-training.md}}

### Host header

Várias vezes, o back-end confia no **Host header** para realizar determinadas ações. Por exemplo, ele pode usar seu valor como o **domínio para enviar um reset de senha**. Portanto, quando você recebe um e-mail com um link para resetar sua senha, o domínio utilizado é aquele que você informou no Host header. Assim, você pode solicitar o reset de senha de outros usuários e alterar o domínio para um controlado por você, a fim de roubar seus códigos de reset de senha. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Observe que talvez nem seja necessário esperar o usuário clicar no link de reset de senha para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.

### Booleanos de sessão

Às vezes, quando você conclui corretamente alguma verificação, o back-end **simplesmente adiciona um booleano com o valor "True" a um atributo de segurança da sua sessão**. Então, um endpoint diferente saberá se você passou nessa verificação com sucesso.\
No entanto, se você **passar na verificação** e sua sessão receber esse valor "True" no atributo de segurança, poderá tentar **acessar outros recursos** que **dependem do mesmo atributo**, mas aos quais você **não deveria ter permissão** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funcionalidade de registro

Tente se registrar usando um usuário que já existe. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

### Takeover de e-mails

Registre um e-mail e, antes de confirmá-lo, altere o e-mail. Então, se o novo e-mail de confirmação for enviado para o primeiro e-mail registrado, você poderá realizar o takeover de qualquer e-mail. Ou, se puder ativar o segundo e-mail confirmando o primeiro, também poderá realizar o takeover de qualquer conta.

### Acessar o servicedesk interno de empresas usando atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Método TRACE

Os desenvolvedores podem esquecer de desativar várias opções de debug no ambiente de produção. Por exemplo, o método HTTP `TRACE` foi projetado para fins de diagnóstico. Se estiver habilitado, o servidor Web responderá a solicitações que usem o método `TRACE` ecoando na resposta a solicitação exata que foi recebida. Esse comportamento costuma ser inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de headers de autenticação internos que podem ser adicionados às solicitações por reverse proxies.![Imagem da publicação](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagem da publicação](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Referências

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
