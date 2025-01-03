# Outras Dicas da Web

{{#include ../banners/hacktricks-training.md}}

### Cabeçalho Host

Várias vezes o back-end confia no **Cabeçalho Host** para realizar algumas ações. Por exemplo, ele pode usar seu valor como o **domínio para enviar um reset de senha**. Assim, quando você recebe um e-mail com um link para redefinir sua senha, o domínio utilizado é aquele que você colocou no Cabeçalho Host. Então, você pode solicitar o reset de senha de outros usuários e mudar o domínio para um controlado por você para roubar seus códigos de reset de senha. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Note que é possível que você não precise nem esperar o usuário clicar no link de redefinição de senha para obter o token, pois talvez até mesmo **filtros de spam ou outros dispositivos/bots intermediários cliquem nele para analisá-lo**.

### Booleanos de Sessão

Às vezes, quando você completa alguma verificação corretamente, o back-end **apenas adiciona um booleano com o valor "True" a um atributo de segurança da sua sessão**. Então, um endpoint diferente saberá se você passou com sucesso naquela verificação.\
No entanto, se você **passar a verificação** e sua sessão receber aquele valor "True" no atributo de segurança, você pode tentar **acessar outros recursos** que **dependem do mesmo atributo**, mas que você **não deveria ter permissões** para acessar. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funcionalidade de Registro

Tente se registrar como um usuário já existente. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

### Tomar Contas de E-mail

Registre um e-mail, antes de confirmá-lo, mude o e-mail, então, se o novo e-mail de confirmação for enviado para o primeiro e-mail registrado, você pode tomar qualquer e-mail. Ou se você puder habilitar o segundo e-mail confirmando o primeiro, você também pode tomar qualquer conta.

### Acessar o Servicedesk Interno de Empresas Usando Atlassian

{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Método TRACE

Os desenvolvedores podem esquecer de desativar várias opções de depuração no ambiente de produção. Por exemplo, o método HTTP `TRACE` é projetado para fins de diagnóstico. Se habilitado, o servidor web responderá a solicitações que usam o método `TRACE` ecoando na resposta a exata solicitação que foi recebida. Esse comportamento é frequentemente inofensivo, mas ocasionalmente leva à divulgação de informações, como o nome de cabeçalhos de autenticação internos que podem ser anexados a solicitações por proxies reversos.![Imagem para o post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagem para o post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
