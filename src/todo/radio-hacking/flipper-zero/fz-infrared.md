# FZ - Infravermelho

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o Infravermelho funciona, consulte:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper usa um receptor de sinal IR digital TSOP, que **permite interceptar sinais de controles remotos IR**. Existem alguns **smartphones**, como os da Xiaomi, que também possuem uma porta IR, mas lembre-se de que **a maioria deles só consegue transmitir** sinais e é **incapaz de recebê-los**.<sup>[[1]](#references)</sup>

O **receptor infravermelho do Flipper é bastante sensível**. Você pode até **capturar o sinal** enquanto permanece **em algum ponto entre** o controle remoto e a TV. Não é necessário apontar o controle remoto diretamente para a porta IR do Flipper. Isso é útil quando alguém está trocando de canal enquanto está perto da TV, e você e o Flipper estão a alguma distância.

Como a **decodificação do sinal infravermelho** ocorre no lado do **software**, o Flipper Zero potencialmente oferece suporte à **recepção e transmissão de quaisquer códigos de controles remotos IR**. No caso de protocolos **desconhecidos** que não puderam ser reconhecidos, ele **grava e reproduz** o sinal bruto exatamente como foi recebido.<sup>[[1]](#references)</sup>

## Ações

### Controles Remotos Universais

O Flipper Zero pode ser usado como um **controle remoto universal para controlar qualquer TV, ar-condicionado ou media center**. Nesse modo, o Flipper executa **brute force** de todos os **códigos conhecidos** de todos os fabricantes compatíveis, **de acordo com o dicionário do cartão SD**. Você não precisa escolher um controle remoto específico para desligar a TV de um restaurante.<sup>[[1]](#references)</sup>

Basta pressionar o botão liga/desliga no modo Controle Remoto Universal, e o Flipper enviará **sequencialmente os comandos "Power Off"** de todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV receber o sinal correspondente, ela reagirá e desligará.

Esse brute force leva tempo. Quanto maior o dicionário, mais tempo será necessário para concluir. Não é possível descobrir qual sinal exatamente a TV reconheceu, pois não há feedback da TV.

### Aprender um Novo Controle Remoto

É possível **capturar um sinal infravermelho** com o Flipper Zero. Se ele **encontrar o sinal no banco de dados**, o Flipper **identificará automaticamente qual é o dispositivo** e permitirá que você interaja com ele.\
Se não encontrar, o Flipper poderá **armazenar** o **sinal** e permitirá **reproduzi-lo**.<sup>[[1]](#references)</sup>

## Referências

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
