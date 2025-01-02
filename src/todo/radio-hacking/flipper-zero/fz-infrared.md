# FZ - Infravermelho

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o Infravermelho funciona, consulte:

{{#ref}}
../infrared.md
{{#endref}}

## Receptor de Sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper usa um receptor de sinal IR digital TSOP, que **permite interceptar sinais de controles remotos IR**. Existem alguns **smartphones** como Xiaomi, que também possuem uma porta IR, mas tenha em mente que **a maioria deles só pode transmitir** sinais e **não consegue recebê-los**.

O **receptor infravermelho do Flipper é bastante sensível**. Você pode até **captar o sinal** enquanto permanece **em algum lugar entre** o controle remoto e a TV. Apontar o controle remoto diretamente para a porta IR do Flipper é desnecessário. Isso é útil quando alguém está trocando de canal enquanto está perto da TV, e tanto você quanto o Flipper estão a uma certa distância.

Como a **decodificação do sinal infravermelho** acontece do lado do **software**, o Flipper Zero potencialmente suporta a **recepção e transmissão de quaisquer códigos remotos IR**. No caso de **protocolos desconhecidos** que não puderam ser reconhecidos - ele **grava e reproduz** o sinal bruto exatamente como recebido.

## Ações

### Controles Remotos Universais

O Flipper Zero pode ser usado como um **controle remoto universal para controlar qualquer TV, ar-condicionado ou centro de mídia**. Neste modo, o Flipper **realiza força bruta** em todos os **códigos conhecidos** de todos os fabricantes suportados **de acordo com o dicionário do cartão SD**. Você não precisa escolher um controle remoto específico para desligar a TV de um restaurante.

Basta pressionar o botão de energia no modo Controle Remoto Universal, e o Flipper **enviará sequencialmente os comandos "Desligar"** de todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV recebe seu sinal, ela reagirá e desligará.

Esse ataque de força bruta leva tempo. Quanto maior o dicionário, mais tempo levará para terminar. É impossível descobrir qual sinal exatamente a TV reconheceu, uma vez que não há feedback da TV.

### Aprender Novo Controle Remoto

É possível **capturar um sinal infravermelho** com o Flipper Zero. Se ele **encontrar o sinal no banco de dados**, o Flipper automaticamente **saberá qual dispositivo é** e permitirá que você interaja com ele.\
Se não encontrar, o Flipper pode **armazenar** o **sinal** e permitirá que você **o reproduza**.

## Referências

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
