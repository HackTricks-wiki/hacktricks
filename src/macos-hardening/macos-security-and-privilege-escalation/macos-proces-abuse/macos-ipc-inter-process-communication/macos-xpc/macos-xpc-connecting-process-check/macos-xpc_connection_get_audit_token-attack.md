# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para mais informações, consulte a postagem original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este é um resumo:

## Informações Básicas sobre Mensagens Mach

Se você não sabe o que são Mensagens Mach, comece a verificar esta página:

{{#ref}}
../../
{{#endref}}

Por enquanto, lembre-se que ([definição daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mensagens Mach são enviadas através de um _mach port_, que é um canal de comunicação **de um único receptor e múltiplos remetentes** incorporado no kernel mach. **Múltiplos processos podem enviar mensagens** para um mach port, mas em qualquer momento **apenas um único processo pode ler a partir dele**. Assim como descritores de arquivo e sockets, mach ports são alocados e gerenciados pelo kernel e os processos veem apenas um inteiro, que podem usar para indicar ao kernel qual dos seus mach ports desejam usar.

## Conexão XPC

Se você não sabe como uma conexão XPC é estabelecida, verifique:

{{#ref}}
../
{{#endref}}

## Resumo da Vulnerabilidade

O que é interessante saber é que **a abstração do XPC é uma conexão de um para um**, mas é baseada em uma tecnologia que **pode ter múltiplos remetentes, então:**

- Mach ports são de um único receptor, **múltiplos remetentes**.
- O token de auditoria de uma conexão XPC é o token de auditoria **copiado da mensagem recebida mais recentemente**.
- Obter o **token de auditoria** de uma conexão XPC é crítico para muitas **verificações de segurança**.

Embora a situação anterior pareça promissora, existem alguns cenários onde isso não causará problemas ([daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Tokens de auditoria são frequentemente usados para uma verificação de autorização para decidir se aceitam uma conexão. Como isso acontece usando uma mensagem para o serviço, **nenhuma conexão foi estabelecida ainda**. Mais mensagens nesse port serão tratadas apenas como solicitações de conexão adicionais. Portanto, quaisquer **verificações antes de aceitar uma conexão não são vulneráveis** (isso também significa que dentro de `-listener:shouldAcceptNewConnection:` o token de auditoria é seguro). Portanto, estamos **procurando conexões XPC que verificam ações específicas**.
- Manipuladores de eventos XPC são tratados de forma síncrona. Isso significa que o manipulador de eventos para uma mensagem deve ser concluído antes de chamá-lo para a próxima, mesmo em filas de despacho concorrentes. Portanto, dentro de um **manipulador de eventos XPC, o token de auditoria não pode ser sobrescrito** por outras mensagens normais (não de resposta!).

Dois métodos diferentes que podem ser exploráveis:

1. Variante 1:
- **Exploit** **conecta-se** ao serviço **A** e ao serviço **B**
- O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode
- O serviço **A** chama **`xpc_connection_get_audit_token`** enquanto _**não**_ está dentro do **manipulador de eventos** para uma conexão em um **`dispatch_async`**.
- Assim, uma **mensagem diferente** poderia **sobrescrever o Token de Auditoria** porque está sendo despachada assíncronamente fora do manipulador de eventos.
- O exploit passa para **o serviço B o direito de ENVIO para o serviço A**.
- Assim, o svc **B** estará realmente **enviando** as **mensagens** para o serviço **A**.
- O **exploit** tenta **chamar** a **ação privilegiada.** Em um RC, o svc **A** **verifica** a autorização dessa **ação** enquanto **svc B sobrescreveu o Token de Auditoria** (dando ao exploit acesso para chamar a ação privilegiada).
2. Variante 2:
- O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode
- O exploit conecta-se com **o serviço A**, que **envia** ao exploit uma **mensagem esperando uma resposta** em um **port de resposta** específico.
- O exploit envia ao **serviço** B uma mensagem passando **aquele port de resposta**.
- Quando o serviço **B responde**, ele **envia a mensagem para o serviço A**, **enquanto** o **exploit** envia uma **mensagem diferente para o serviço A** tentando **alcançar uma funcionalidade privilegiada** e esperando que a resposta do serviço B sobrescreva o Token de Auditoria no momento perfeito (Condição de Corrida).

## Variante 1: chamando xpc_connection_get_audit_token fora de um manipulador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Cenário:

- Dois serviços mach **`A`** e **`B`** aos quais podemos nos conectar (com base no perfil de sandbox e nas verificações de autorização antes de aceitar a conexão).
- _**A**_ deve ter uma **verificação de autorização** para uma ação específica que **`B`** pode passar (mas nosso aplicativo não pode).
- Por exemplo, se B tiver algumas **entitlements** ou estiver rodando como **root**, isso pode permitir que ele peça a A para realizar uma ação privilegiada.
- Para essa verificação de autorização, **`A`** obtém o token de auditoria de forma assíncrona, por exemplo, chamando `xpc_connection_get_audit_token` de **`dispatch_async`**.

> [!CAUTION]
> Nesse caso, um atacante poderia desencadear uma **Condição de Corrida** fazendo um **exploit** que **pede a A para realizar uma ação** várias vezes enquanto faz **B enviar mensagens para `A`**. Quando a RC é **bem-sucedida**, o **token de auditoria** de **B** será copiado na memória **enquanto** a solicitação do nosso **exploit** está sendo **tratada** por A, dando-lhe **acesso à ação privilegiada que apenas B poderia solicitar**.

Isso aconteceu com **`A`** como `smd` e **`B`** como `diagnosticd`. A função [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) do smb pode ser usada para instalar um novo helper privilegiado (como **root**). Se um **processo rodando como root contatar** **smd**, nenhuma outra verificação será realizada.

Portanto, o serviço **B** é **`diagnosticd`** porque roda como **root** e pode ser usado para **monitorar** um processo, então, uma vez que a monitorização tenha começado, ele **enviará várias mensagens por segundo.**

Para realizar o ataque:

1. Inicie uma **conexão** com o serviço chamado `smd` usando o protocolo XPC padrão.
2. Forme uma **conexão secundária** com `diagnosticd`. Ao contrário do procedimento normal, em vez de criar e enviar dois novos mach ports, o direito de envio do port do cliente é substituído por um duplicado do **direito de envio** associado à conexão `smd`.
3. Como resultado, mensagens XPC podem ser despachadas para `diagnosticd`, mas as respostas de `diagnosticd` são redirecionadas para `smd`. Para `smd`, parece que as mensagens do usuário e de `diagnosticd` estão originando da mesma conexão.

![Imagem representando o processo do exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. O próximo passo envolve instruir `diagnosticd` a iniciar a monitorização de um processo escolhido (potencialmente o próprio do usuário). Simultaneamente, um fluxo de mensagens rotineiras 1004 é enviado para `smd`. A intenção aqui é instalar uma ferramenta com privilégios elevados.
5. Essa ação desencadeia uma condição de corrida dentro da função `handle_bless`. O tempo é crítico: a chamada da função `xpc_connection_get_pid` deve retornar o PID do processo do usuário (já que a ferramenta privilegiada reside no pacote do aplicativo do usuário). No entanto, a função `xpc_connection_get_audit_token`, especificamente dentro da sub-rotina `connection_is_authorized`, deve referenciar o token de auditoria pertencente a `diagnosticd`.

## Variante 2: encaminhamento de resposta

Em um ambiente XPC (Comunicação entre Processos), embora os manipuladores de eventos não sejam executados de forma concorrente, o tratamento de mensagens de resposta tem um comportamento único. Especificamente, existem dois métodos distintos para enviar mensagens que esperam uma resposta:

1. **`xpc_connection_send_message_with_reply`**: Aqui, a mensagem XPC é recebida e processada em uma fila designada.
2. **`xpc_connection_send_message_with_reply_sync`**: Por outro lado, neste método, a mensagem XPC é recebida e processada na fila de despacho atual.

Essa distinção é crucial porque permite a possibilidade de **pacotes de resposta serem analisados de forma concorrente com a execução de um manipulador de eventos XPC**. Notavelmente, enquanto `_xpc_connection_set_creds` implementa bloqueio para proteger contra a sobrescrita parcial do token de auditoria, essa proteção não se estende a todo o objeto de conexão. Consequentemente, isso cria uma vulnerabilidade onde o token de auditoria pode ser substituído durante o intervalo entre a análise de um pacote e a execução de seu manipulador de eventos.

Para explorar essa vulnerabilidade, a seguinte configuração é necessária:

- Dois serviços mach, referidos como **`A`** e **`B`**, ambos os quais podem estabelecer uma conexão.
- O serviço **`A`** deve incluir uma verificação de autorização para uma ação específica que apenas **`B`** pode realizar (o aplicativo do usuário não pode).
- O serviço **`A`** deve enviar uma mensagem que antecipa uma resposta.
- O usuário pode enviar uma mensagem para **`B`** que ele responderá.

O processo de exploração envolve os seguintes passos:

1. Aguarde o serviço **`A`** enviar uma mensagem que espera uma resposta.
2. Em vez de responder diretamente a **`A`**, o port de resposta é sequestrado e usado para enviar uma mensagem ao serviço **`B`**.
3. Subsequentemente, uma mensagem envolvendo a ação proibida é despachada, com a expectativa de que será processada de forma concorrente com a resposta de **`B`**.

Abaixo está uma representação visual do cenário de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de Descoberta

- **Dificuldades em Localizar Instâncias**: A busca por instâncias de uso de `xpc_connection_get_audit_token` foi desafiadora, tanto estaticamente quanto dinamicamente.
- **Metodologia**: Frida foi empregada para interceptar a função `xpc_connection_get_audit_token`, filtrando chamadas que não se originavam de manipuladores de eventos. No entanto, esse método foi limitado ao processo interceptado e exigiu uso ativo.
- **Ferramentas de Análise**: Ferramentas como IDA/Ghidra foram usadas para examinar serviços mach acessíveis, mas o processo foi demorado, complicado por chamadas envolvendo o cache compartilhado do dyld.
- **Limitações de Script**: Tentativas de scriptar a análise para chamadas a `xpc_connection_get_audit_token` a partir de blocos `dispatch_async` foram dificultadas por complexidades na análise de blocos e interações com o cache compartilhado do dyld.

## A correção <a href="#the-fix" id="the-fix"></a>

- **Problemas Reportados**: Um relatório foi enviado à Apple detalhando os problemas gerais e específicos encontrados dentro de `smd`.
- **Resposta da Apple**: A Apple abordou o problema em `smd` substituindo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.
- **Natureza da Correção**: A função `xpc_dictionary_get_audit_token` é considerada segura, pois recupera o token de auditoria diretamente da mensagem mach vinculada à mensagem XPC recebida. No entanto, não faz parte da API pública, semelhante a `xpc_connection_get_audit_token`.
- **Ausência de uma Correção Mais Abrangente**: Permanece incerto por que a Apple não implementou uma correção mais abrangente, como descartar mensagens que não se alinham com o token de auditoria salvo da conexão. A possibilidade de mudanças legítimas no token de auditoria em certos cenários (por exemplo, uso de `setuid`) pode ser um fator.
- **Status Atual**: O problema persiste no iOS 17 e macOS 14, representando um desafio para aqueles que buscam identificá-lo e compreendê-lo.

{{#include ../../../../../../banners/hacktricks-training.md}}
