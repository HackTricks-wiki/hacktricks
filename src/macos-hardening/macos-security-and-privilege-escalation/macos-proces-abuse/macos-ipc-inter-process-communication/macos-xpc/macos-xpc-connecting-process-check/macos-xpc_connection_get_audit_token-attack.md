# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Para obter mais informações, consulte o post original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este é um resumo:<sup>[[1]](#references)</sup>

## Informações básicas sobre Mach Messages

Se você não sabe o que são Mach Messages, comece consultando esta página:


{{#ref}}
../../
{{#endref}}

Por enquanto, lembre-se de que ([definição disponível aqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
As Mach messages são enviadas por uma _mach port_, que é um canal de comunicação de **um único receptor e múltiplos remetentes** integrado ao kernel do mach. **Vários processos podem enviar mensagens** para uma mach port, mas, a qualquer momento, **apenas um processo pode ler dela**. Assim como file descriptors e sockets, as mach ports são alocadas e gerenciadas pelo kernel, e os processos veem apenas um inteiro, que podem usar para indicar ao kernel qual das suas mach ports desejam usar.

## XPC Connection

Se você não sabe como uma XPC connection é estabelecida, consulte:


{{#ref}}
../
{{#endref}}

## Resumo da vulnerabilidade

O que é importante saber é que a **abstração do XPC é uma conexão um-para-um**, mas ela se baseia em uma tecnologia que **pode ter vários remetentes, portanto:**

- Mach ports têm um único receptor e **múltiplos remetentes**.
- O audit token de uma XPC connection é o audit token **copiado da mensagem recebida mais recentemente**.
- Obter o **audit token** de uma XPC connection é fundamental para muitas **verificações de segurança**.<sup>[[1]](#references)</sup>

Embora a situação anterior pareça promissora, há alguns cenários em que isso não causará problemas ([a partir daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Os audit tokens são frequentemente usados em uma verificação de autorização para decidir se uma conexão deve ser aceita. Como isso ocorre usando uma mensagem enviada à service port, **a conexão ainda não foi estabelecida**. Outras mensagens nessa port serão apenas tratadas como solicitações adicionais de conexão. Portanto, **as verificações realizadas antes de aceitar uma conexão não são vulneráveis** (isso também significa que, dentro de `-listener:shouldAcceptNewConnection:`, o audit token é seguro). Portanto, estamos **procurando XPC connections que verifiquem ações específicas**.
- Os XPC event handlers são tratados de forma síncrona. Isso significa que o event handler de uma mensagem precisa ser concluído antes de ser chamado para a próxima, mesmo em filas de dispatch concorrentes. Assim, dentro de um **XPC event handler, o audit token não pode ser sobrescrito** por outras mensagens normais (não reply!).<sup>[[1]](#references)</sup>

Há dois métodos diferentes pelos quais isso pode ser explorado:

1. Variant1:
- O **exploit** se **conecta** ao service **A** e ao service **B**.
- O service **B** pode chamar uma **funcionalidade privilegiada** no service A que o usuário não pode chamar.
- O service **A** chama **`xpc_connection_get_audit_token`** enquanto _**não**_ está dentro do **event handler** de uma conexão em um **`dispatch_async`**.
- Portanto, uma mensagem **diferente** poderia **sobrescrever o Audit Token**, pois está sendo despachada de forma assíncrona fora do event handler.
- O exploit passa ao **service B** o **SEND right para o service A**.
- Assim, o svc **B** estará efetivamente **enviando** as **mensagens** ao **service A**.
- O **exploit** tenta **chamar a ação privilegiada**. Em uma RC, o svc **A** **verifica** a autorização dessa **ação** enquanto o **svc B sobrescreveu o Audit token** (dando ao exploit acesso para chamar a ação privilegiada).
2. Variant 2:
- O service **B** pode chamar uma **funcionalidade privilegiada** no service A que o usuário não pode chamar.
- O exploit se conecta ao **service A**, que **envia** ao exploit uma **mensagem esperando uma resposta** em uma **port de replay** específica.
- O exploit envia ao **service B** uma mensagem passando **essa reply port**.
- Quando o service **B** responde, ele **envia a mensagem ao service A**, enquanto o **exploit** envia uma **mensagem diferente ao service A**, tentando **alcançar uma funcionalidade privilegiada** e esperando que a reply do service B sobrescreva o Audit token no momento exato (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Cenário:

- Dois mach services **`A`** e **`B`** aos quais podemos nos conectar (com base no sandbox profile e nas verificações de autorização antes de aceitar a conexão).
- _**A**_ deve ter uma **verificação de autorização** para uma ação específica que **`B`** pode passar (mas nosso app não pode).
- Por exemplo, se B tiver alguns **entitlements** ou estiver sendo executado como **root**, ele poderá permitir que A execute uma ação privilegiada.
- Para essa verificação de autorização, **A** obtém o audit token de forma assíncrona, por exemplo, chamando `xpc_connection_get_audit_token` a partir de `dispatch_async`.

> [!CAUTION]
> Nesse caso, um atacante poderia acionar uma **Race Condition**, criando um **exploit** que **solicita a A que execute uma ação** várias vezes enquanto faz **B enviar mensagens para `A`**. Quando a RC é **bem-sucedida**, o **audit token** de **B** será copiado na memória **enquanto** a solicitação do nosso **exploit** estiver sendo **tratada** por A, dando a ele **acesso à ação privilegiada que apenas B poderia solicitar**.

Isso aconteceu com **`A`** como `smd` e **`B`** como `diagnosticd`. A função [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) do smb pode ser usada para instalar um novo helper tool privilegiado (como **root**). Se um **processo sendo executado como root entrar em contato** com **smd**, nenhuma outra verificação será realizada.

Portanto, o service **B** é o **`diagnosticd`**, pois ele é executado como **root** e pode ser usado para **monitorar** um processo; assim que o monitoramento começa, ele **enviará várias mensagens por segundo.**

Para executar o ataque:

1. Inicie uma **conexão** com o service chamado `smd` usando o protocolo XPC padrão.
2. Estabeleça uma **conexão** secundária com `diagnosticd`. Ao contrário do procedimento normal, em vez de criar e enviar duas novas mach ports, o client port send right é substituído por um duplicado do **send right** associado à conexão `smd`.
3. Como resultado, as mensagens XPC podem ser despachadas para `diagnosticd`, mas as respostas de `diagnosticd` são redirecionadas para `smd`. Para o `smd`, parece que as mensagens tanto do usuário quanto do `diagnosticd` estão se originando da mesma conexão.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. A próxima etapa envolve instruir o `diagnosticd` a iniciar o monitoramento de um processo escolhido (potencialmente o próprio processo do usuário). Simultaneamente, uma inundação de mensagens 1004 rotineiras é enviada ao `smd`. O objetivo é instalar uma ferramenta com privilégios elevados.
5. Essa ação aciona uma race condition dentro da função `handle_bless`. O timing é crítico: a chamada à função `xpc_connection_get_pid` deve retornar o PID do processo do usuário (pois a ferramenta privilegiada está localizada no app bundle do usuário). No entanto, a função `xpc_connection_get_audit_token`, especificamente dentro da sub-rotina `connection_is_authorized`, deve referenciar o audit token pertencente ao `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Em um ambiente XPC (Cross-Process Communication), embora os event handlers não sejam executados simultaneamente, o tratamento de reply messages possui um comportamento exclusivo. Especificamente, existem dois métodos distintos para enviar mensagens que esperam uma resposta:

1. **`xpc_connection_send_message_with_reply`**: aqui, a mensagem XPC é recebida e processada em uma fila designada.
2. **`xpc_connection_send_message_with_reply_sync`**: por outro lado, nesse método, a mensagem XPC é recebida e processada na fila de dispatch atual.

Essa distinção é crucial porque permite que **reply packets sejam analisados simultaneamente à execução de um XPC event handler**. É importante observar que, embora `_xpc_connection_set_creds` implemente locking para proteger contra a sobrescrita parcial do audit token, essa proteção não se estende ao objeto de conexão inteiro. Consequentemente, isso cria uma vulnerabilidade na qual o audit token pode ser substituído durante o intervalo entre a análise de um packet e a execução do seu event handler.

Para explorar essa vulnerabilidade, é necessária a seguinte configuração:

- Dois mach services, chamados **`A`** e **`B`**, ambos capazes de estabelecer uma conexão.
- O service **`A`** deve incluir uma verificação de autorização para uma ação específica que somente **`B`** pode executar (o app do usuário não pode).
- O service **`A`** deve enviar uma mensagem que espera uma resposta.
- O usuário pode enviar uma mensagem para **`B`**, que responderá a ela.

O processo de exploração envolve as seguintes etapas:

1. Aguarde o service **`A`** enviar uma mensagem que espera uma resposta.
2. Em vez de responder diretamente a **`A`**, a reply port é sequestrada e usada para enviar uma mensagem ao service **`B`**.
3. Em seguida, uma mensagem envolvendo a ação proibida é despachada, esperando-se que seja processada simultaneamente à resposta de **`B`**.<sup>[[1]](#references)</sup>

Abaixo está uma representação visual do cenário de ataque descrito:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de descoberta

- **Dificuldades para localizar instâncias**: procurar instâncias de uso de `xpc_connection_get_audit_token` foi difícil, tanto estaticamente quanto dinamicamente.
- **Metodologia**: o Frida foi usado para fazer hook na função `xpc_connection_get_audit_token`, filtrando chamadas que não se originavam de event handlers. No entanto, esse método era limitado ao processo submetido ao hook e exigia uso ativo.
- **Ferramentas de análise**: ferramentas como IDA/Ghidra foram usadas para examinar mach services acessíveis, mas o processo era demorado e complicado por chamadas envolvendo o dyld shared cache.
- **Limitações de scripting**: as tentativas de criar scripts para analisar chamadas a `xpc_connection_get_audit_token` a partir de blocos `dispatch_async` foram prejudicadas pela complexidade da análise de blocos e das interações com o dyld shared cache.<sup>[[1]](#references)</sup>

## A correção <a href="#the-fix" id="the-fix"></a>

- **Problemas reportados**: um relatório foi enviado à Apple detalhando os problemas gerais e específicos encontrados no `smd`.
- **Resposta da Apple**: a Apple corrigiu o problema no `smd` substituindo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Natureza da correção**: a função `xpc_dictionary_get_audit_token` é considerada segura, pois obtém o audit token diretamente da mach message associada à mensagem XPC recebida. No entanto, ela não faz parte da API pública, assim como `xpc_connection_get_audit_token`.
- **Ausência de uma correção mais ampla**: ainda não está claro por que a Apple não implementou uma correção mais abrangente, como descartar mensagens que não correspondam ao audit token salvo da conexão. A possibilidade de alterações legítimas no audit token em determinados cenários (por exemplo, uso de `setuid`) pode ser um fator.
- **Status atual**: o problema persiste no iOS 17 e no macOS 14, representando um desafio para quem busca identificá-lo e compreendê-lo.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Ao auditar XPC services para essa classe de bug, concentre-se em autorizações realizadas fora do event handler da mensagem ou simultaneamente ao processamento de replies.

Dicas para triagem estática:
- Procure chamadas a `xpc_connection_get_audit_token` alcançáveis a partir de blocos enfileirados via `dispatch_async`/`dispatch_after` ou outras worker queues executadas fora do message handler.
- Procure helpers de autorização que misturem estado por conexão e por mensagem (por exemplo, obter o PID de `xpc_connection_get_pid`, mas o audit token de `xpc_connection_get_audit_token`).
- No código NSXPC, verifique se as verificações são realizadas em `-listener:shouldAcceptNewConnection:` ou, para verificações por mensagem, se a implementação usa um audit token por mensagem (por exemplo, o dicionário da mensagem via `xpc_dictionary_get_audit_token` em código de nível inferior).

Dicas para triagem dinâmica:
- Faça hook de `xpc_connection_get_audit_token` e sinalize invocações cuja user stack não inclua o caminho de entrega de eventos (por exemplo, `_xpc_connection_mach_event`). Exemplo de hook do Frida:
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
- No macOS, instrumentar binários protegidos/da Apple pode exigir que o SIP esteja desativado ou um ambiente de desenvolvimento; prefira testar seus próprios builds ou serviços userland.
- Para races de encaminhamento de respostas (Variant 2), monitore a análise concorrente dos pacotes de resposta fazendo fuzzing dos timings de `xpc_connection_send_message_with_reply` em comparação com requisições normais e verificando se o audit token efetivo usado durante a autorização pode ser influenciado.

## Primitives de exploração que provavelmente serão necessárias

- Configuração com múltiplos senders (Variant 1): crie conexões com A e B; duplique o send right da client port de A e use-o como client port de B para que as respostas de B sejam entregues a A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right from A’s pending request (reply port), then send a crafted message to B using that reply port so B’s reply lands on A while your privileged request is being parsed.

These require low-level mach message crafting for the XPC bootstrap and message formats; consulte as páginas de introdução sobre mach/XPC nesta seção para obter os layouts exatos dos pacotes e as flags.

## Ferramentas úteis

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) pode ajudar a enumerar conexões e observar o tráfego para validar configurações com múltiplos remetentes e o timing. Exemplo: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing para libxpc: faça interpose em `xpc_connection_send_message*` e `xpc_connection_get_audit_token` para registrar os call sites e as stacks durante testes black-box.



## Referências

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
