# Ataque `xpc_connection_get_audit_token` do macOS

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para obter mais informações, consulte o post original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este é um resumo:

## Informações básicas sobre Mach Messages

Se você não sabe o que são Mach Messages, comece consultando esta página:


{{#ref}}
../../
{{#endref}}

Por enquanto, lembre-se de que ([definição disponível aqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
As Mach messages são enviadas por uma _mach port_, que é um canal de comunicação de **um único receiver e múltiplos senders** integrado ao kernel do mach. **Múltiplos processos podem enviar mensagens** para uma mach port, mas, a qualquer momento, **apenas um único processo pode lê-las**. Assim como file descriptors e sockets, as mach ports são alocadas e gerenciadas pelo kernel, e os processos veem apenas um inteiro, que podem usar para indicar ao kernel qual de suas mach ports desejam utilizar.

## XPC Connection

Se você não sabe como uma conexão XPC é estabelecida, consulte:


{{#ref}}
../
{{#endref}}

## Resumo da vulnerabilidade

O que é importante saber é que a **abstração do XPC é uma conexão one-to-one**, mas é baseada em uma tecnologia que **pode ter múltiplos senders, portanto:**

- As mach ports têm um único receiver e **múltiplos senders**.
- O audit token de uma XPC connection é o audit token **copiado da mensagem recebida mais recentemente**.
- Obter o **audit token** de uma XPC connection é essencial para muitas **verificações de segurança**.<sup>[1]</sup>

Embora a situação anterior pareça promissora, há alguns cenários nos quais isso não causará problemas ([a partir daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Os audit tokens são frequentemente usados em uma verificação de autorização para decidir se uma conexão deve ser aceita. Como isso ocorre usando uma mensagem enviada à service port, **a conexão ainda não foi estabelecida**. Mensagens adicionais nessa port serão apenas tratadas como novas solicitações de conexão. Portanto, **as verificações realizadas antes de aceitar uma conexão não são vulneráveis** (isso também significa que, dentro de `-listener:shouldAcceptNewConnection:`, o audit token é seguro). Portanto, estamos **procurando XPC connections que verifiquem ações específicas**.
- Os XPC event handlers são tratados de forma síncrona. Isso significa que o event handler de uma mensagem deve ser concluído antes de ser chamado para a próxima, mesmo em dispatch queues concorrentes. Assim, dentro de um **XPC event handler, o audit token não pode ser sobrescrito** por outras mensagens normais (não reply!).<sup>[1]</sup>

Há dois métodos diferentes pelos quais isso pode ser explorado:

1. Variant1:
- O **exploit** se **conecta** ao service **A** e ao service **B**.
- O service **B** pode chamar uma **funcionalidade privilegiada** no service A que o usuário não pode chamar.
- O service **A** chama **`xpc_connection_get_audit_token`** enquanto _**não**_ está dentro do **event handler** de uma conexão em um **`dispatch_async`**.
- Assim, uma mensagem **diferente** poderia **sobrescrever o Audit Token**, pois está sendo despachada de forma assíncrona, fora do event handler.
- O exploit passa ao **service B o SEND right para o service A**.
- Portanto, o svc **B** estará efetivamente **enviando** as **mensagens** ao service **A**.
- O **exploit** tenta **chamar a ação privilegiada**. Em uma RC, o svc **A** **verifica** a autorização dessa **ação** enquanto o **svc B sobrescreveu o Audit token** (dando ao exploit acesso para chamar a ação privilegiada).
2. Variant 2:
- O service **B** pode chamar uma **funcionalidade privilegiada** no service A que o usuário não pode chamar.
- O exploit se conecta ao **service A**, que **envia** ao exploit uma **mensagem esperando uma resposta** em uma **reply** **port** específica.
- O exploit envia ao **service B** uma mensagem passando **essa reply port**.
- Quando o service **B responde**, ele **envia a mensagem ao service A**, enquanto o **exploit** envia uma **mensagem diferente ao service A**, tentando **alcançar uma funcionalidade privilegiada** e esperando que a resposta do service B sobrescreva o Audit token no momento exato (Race Condition).

## Variant 1: chamando xpc_connection_get_audit_token fora de um event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Cenário:

- Dois mach services, **`A`** e **`B`**, aos quais podemos nos conectar (com base no sandbox profile e nas verificações de autorização realizadas antes de aceitar a conexão).
- _**A**_ deve ter uma **verificação de autorização** para uma ação específica que **B** pode realizar (mas nosso app não pode).
- Por exemplo, se B tiver alguns **entitlements** ou estiver sendo executado como **root**, ele poderá permitir que A execute uma ação privilegiada.
- Para essa verificação de autorização, **A** obtém o audit token de forma assíncrona, por exemplo, chamando `xpc_connection_get_audit_token` a partir de `dispatch_async`.

> [!CAUTION]
> Nesse caso, um atacante poderia acionar uma **Race Condition**, criando um **exploit** que solicita a A que execute uma ação várias vezes enquanto faz com que **B envie mensagens para `A`**. Quando a RC é **bem-sucedida**, o **audit token** de **B** será copiado para a memória **enquanto** a solicitação do nosso **exploit** estiver sendo **tratada** por A, dando a ele **acesso à ação privilegiada que somente B poderia solicitar**.

Isso ocorreu com **`A`** como `smd` e **`B`** como `diagnosticd`. A função [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) do smb pode ser usada para instalar uma nova ferramenta helper privilegiada (como **root**). Se um **processo em execução como root entrar em contato** com o **smd**, nenhuma outra verificação será realizada.

Portanto, o service **B** é o **`diagnosticd`**, pois ele é executado como **root** e pode ser usado para **monitorar** um processo; assim que o monitoramento começa, ele **envia várias mensagens por segundo.**

Para realizar o ataque:

1. Inicie uma **conexão** com o service chamado `smd` usando o protocolo XPC padrão.
2. Estabeleça uma **conexão** secundária com `diagnosticd`. Ao contrário do procedimento normal, em vez de criar e enviar duas novas mach ports, o client port send right é substituído por uma duplicata do **send right** associado à conexão com o `smd`.
3. Como resultado, mensagens XPC podem ser despachadas para `diagnosticd`, mas as respostas de `diagnosticd` são redirecionadas para `smd`. Para o `smd`, parece que as mensagens tanto do usuário quanto do `diagnosticd` estão se originando da mesma conexão.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. O próximo passo envolve instruir o `diagnosticd` a iniciar o monitoramento de um processo escolhido (potencialmente o próprio processo do usuário). Simultaneamente, uma enxurrada de mensagens rotineiras 1004 é enviada ao `smd`. O objetivo é instalar uma ferramenta com privilégios elevados.
5. Essa ação aciona uma race condition dentro da função `handle_bless`. O timing é crítico: a chamada à função `xpc_connection_get_pid` deve retornar o PID do processo do usuário (pois a ferramenta privilegiada está no app bundle do usuário). No entanto, a função `xpc_connection_get_audit_token`, especificamente dentro da sub-rotina `connection_is_authorized`, deve referenciar o audit token pertencente ao `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

Em um ambiente XPC (Cross-Process Communication), embora os event handlers não sejam executados simultaneamente, o tratamento das reply messages possui um comportamento único. Especificamente, existem dois métodos distintos para enviar mensagens que esperam uma resposta:

1. **`xpc_connection_send_message_with_reply`**: aqui, a mensagem XPC é recebida e processada em uma queue designada.
2. **`xpc_connection_send_message_with_reply_sync`**: por outro lado, nesse método, a mensagem XPC é recebida e processada na dispatch queue atual.

Essa distinção é crucial porque permite que **reply packets sejam analisados concorrentemente com a execução de um XPC event handler**. Embora `_xpc_connection_set_creds` implemente locking para proteger contra a sobrescrita parcial do audit token, essa proteção não se estende ao objeto de conexão inteiro. Consequentemente, isso cria uma vulnerabilidade na qual o audit token pode ser substituído durante o intervalo entre a análise de um packet e a execução de seu event handler.

Para explorar essa vulnerabilidade, é necessária a seguinte configuração:

- Dois mach services, chamados **`A`** e **`B`**, ambos capazes de estabelecer uma conexão.
- O service **`A`** deve incluir uma verificação de autorização para uma ação específica que somente **`B`** pode executar (o app do usuário não pode).
- O service **`A`** deve enviar uma mensagem que aguarda uma resposta.
- O usuário pode enviar uma mensagem para **`B`** à qual ele responderá.

O processo de exploração envolve as seguintes etapas:

1. Aguarde o service **`A`** enviar uma mensagem que espera uma resposta.
2. Em vez de responder diretamente a **`A`**, a reply port é sequestrada e usada para enviar uma mensagem ao service **`B`**.
3. Em seguida, uma mensagem envolvendo a ação proibida é despachada, esperando que seja processada concorrentemente com a resposta de **`B`**.<sup>[1]</sup>

Abaixo está uma representação visual do cenário de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de descoberta

- **Dificuldades para localizar instâncias**: foi difícil procurar instâncias de uso de `xpc_connection_get_audit_token`, tanto estaticamente quanto dinamicamente.
- **Metodologia**: o Frida foi usado para hookar a função `xpc_connection_get_audit_token`, filtrando chamadas que não se originavam de event handlers. No entanto, esse método estava limitado ao processo hookado e exigia uso ativo.
- **Ferramentas de análise**: ferramentas como IDA/Ghidra foram usadas para examinar mach services acessíveis, mas o processo era demorado e complicado por chamadas envolvendo o dyld shared cache.
- **Limitações de scripting**: as tentativas de criar scripts para analisar chamadas a `xpc_connection_get_audit_token` a partir de blocos `dispatch_async` foram prejudicadas pelas complexidades na análise de blocos e pelas interações com o dyld shared cache.<sup>[1]</sup>

## A correção <a href="#the-fix" id="the-fix"></a>

- **Problemas reportados**: um relatório foi enviado à Apple detalhando os problemas gerais e específicos encontrados no `smd`.
- **Resposta da Apple**: a Apple corrigiu o problema no `smd`, substituindo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Natureza da correção**: a função `xpc_dictionary_get_audit_token` é considerada segura, pois recupera o audit token diretamente da mach message associada à mensagem XPC recebida. No entanto, ela não faz parte da API pública, assim como `xpc_connection_get_audit_token`.
- **Ausência de uma correção abrangente**: não está claro por que a Apple não implementou uma correção mais abrangente, como descartar mensagens que não correspondam ao audit token salvo da conexão. A possibilidade de alterações legítimas no audit token em determinados cenários (por exemplo, uso de `setuid`) pode ser um fator.
- **Status atual**: o problema persiste no iOS 17 e no macOS 14, representando um desafio para aqueles que tentam identificá-lo e compreendê-lo.<sup>[1]</sup>

## Encontrando code paths vulneráveis na prática (2024–2025)

Ao auditar XPC services para essa classe de bug, concentre-se em autorizações realizadas fora do event handler da mensagem ou concorrentemente com o processamento de replies.

Dicas de triagem estática:
- Procure chamadas a `xpc_connection_get_audit_token` alcançáveis a partir de blocos enfileirados via `dispatch_async`/`dispatch_after` ou outras worker queues executadas fora do message handler.
- Procure helpers de autorização que misturem estado por conexão e por mensagem (por exemplo, buscar o PID de `xpc_connection_get_pid`, mas o audit token de `xpc_connection_get_audit_token`).
- No código NSXPC, verifique se as verificações são realizadas em `-listener:shouldAcceptNewConnection:` ou, para verificações por mensagem, se a implementação usa um audit token por mensagem (por exemplo, o dicionário da mensagem via `xpc_dictionary_get_audit_token` em código de nível inferior).

Dicas de triagem dinâmica:
- Hooke `xpc_connection_get_audit_token` e sinalize invocações cuja user stack não inclua o event-delivery path (por exemplo, `_xpc_connection_mach_event`). Exemplo de Frida hook:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notas:
- No macOS, instrumentar binários protegidos/da Apple pode exigir que o SIP esteja desativado ou um ambiente de desenvolvimento; prefira testar suas próprias builds ou serviços userland.
- Para races de encaminhamento de respostas (Variant 2), monitore a análise concorrente dos pacotes de resposta fazendo fuzzing dos timings de `xpc_connection_send_message_with_reply` em comparação com requisições normais e verificando se o audit token efetivo usado durante a autorização pode ser influenciado.

## Primitivas de exploitation que você provavelmente precisará

- Configuração de múltiplos remetentes (Variant 1): crie conexões com A e B; duplique o send right da client port de A e use-o como a client port de B para que as respostas de B sejam entregues a A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture o direito send-once da solicitação pendente de A (reply port) e, em seguida, envie uma mensagem criada especialmente para B usando essa reply port, para que a resposta de B chegue a A enquanto sua solicitação privilegiada estiver sendo analisada.

Essas técnicas exigem a criação de mensagens mach de baixo nível para o bootstrap do XPC e para os formatos das mensagens; consulte as páginas introdutórias de mach/XPC nesta seção para conhecer os layouts exatos dos pacotes e os flags.

## Ferramentas úteis

- Sniffing/inspeção dinâmica de XPC: gxpc (open-source XPC sniffer) pode ajudar a enumerar conexões e observar o tráfego para validar configurações com vários senders e o timing. Exemplo: `gxpc -p <PID> --whitelist <service-name>`.
- Interposição clássica de dyld para libxpc: faça interpose em `xpc_connection_send_message*` e `xpc_connection_get_audit_token` para registrar os call sites e as stacks durante testes black-box.



## Referências

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
