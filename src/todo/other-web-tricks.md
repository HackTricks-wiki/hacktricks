# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Os back ends às vezes confiam no campo HTTP `Host` ao construir links absolutos. Se um e-mail de redefinição de senha usar um host fornecido pelo atacante, solicitar uma redefinição para uma vítima pode enviar um link contendo um token por meio de um domínio controlado pelo atacante. Teste também os campos forwarded-host, o tratamento de Hosts duplicados e os destinos de requisição no formato absoluto em cada salto de proxy.<sup>[[1]](#references)</sup>

> [!WARNING]
> O clique de um usuário pode não ser necessário: **scanners de segurança de e-mail, serviços de pré-visualização ou outros intermediários podem solicitar automaticamente o link controlado pelo atacante**, divulgando o token de redefinição.

## Session booleans

Algumas aplicações registram uma verificação concluída como um booleano na sessão e, depois, permitem que outro endpoint dependa desse sinalizador. Após passar legitimamente na verificação de um recurso, teste se o mesmo sinalizador autoriza incorretamente um usuário, objeto ou workflow diferente. Isso é uma falha de autorização/reutilização de estado de segunda ordem, não apenas um IDOR.<sup>[[2]](#references)</sup>

## Registration functionality

Tente se registrar como um usuário que já existe. Tente também usar caracteres equivalentes (pontos, muitos espaços e Unicode).

## Email-change state confusion

Registre um endereço de e-mail e altere-o antes da confirmação. Verifique se a confirmação do novo endereço é enviada para o endereço antigo ou se confirmar o token antigo ativa o novo endereço. Os tokens de confirmação devem estar vinculados à conta exata, ao endereço pendente, à finalidade e ao estado atual.

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

O método HTTP `TRACE` solicita um loop-back da requisição recebida para fins de diagnóstico. A RFC 9110 exige que os destinatários omitam campos sensíveis, como credenciais e cookies, do conteúdo refletido, mas implementações inseguras ou headers adicionados por intermediários ainda podem divulgar transformações internas da requisição. Os navegadores impedem requisições TRACE geradas por scripts, portanto o ataque histórico de cross-site tracing também depende de uma forma separada de injetar campos protegidos.<sup>[[3]](#references)</sup>![Imagem mostrando uma resposta TRACE](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Imagem da publicação](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Como consegui assumir o controle da conta de qualquer usuário com Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Um vetor de ataque menos conhecido: ataques Second Order IDOR](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, seção 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
