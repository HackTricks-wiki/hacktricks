# FZ - Infravermelho

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o infravermelho funciona, consulte:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper Zero usa um receptor IR demodulador para capturar sinais de controles remotos IR comuns. Alguns celulares, incluindo determinados modelos da Xiaomi, têm um transmissor IR, mas a maioria não consegue receber e decodificar sinais de controles remotos.<sup>[[1]](#references)</sup>

O **receptor infravermelho do Flipper é bastante sensível**. Você pode até **capturar o sinal** enquanto está **em algum ponto entre** o controle remoto e a TV. Não é necessário apontar o controle diretamente para a porta IR do Flipper. Isso é útil quando alguém troca de canal perto da TV, enquanto você e o Flipper estão a certa distância.

A decodificação dos protocolos é feita por software. Os protocolos reconhecidos podem ser armazenados como comandos decodificados; protocolos não compatíveis podem ser capturados e reproduzidos como dados brutos de temporização, dentro dos limites de frequência da portadora e de temporização do hardware.<sup>[[1]](#references)</sup>

## Ações

### Controles remotos universais

O modo de controle remoto universal do Flipper Zero percorre comandos conhecidos no banco de dados infravermelho para TVs, equipamentos de áudio, projetores e aparelhos de ar-condicionado compatíveis. Não há garantia de que controle todos os dispositivos, e ele deve ser usado apenas em equipamentos que você possui ou está autorizado a testar.<sup>[[1]](#references)</sup>

Basta pressionar o botão liga/desliga no modo Universal Remote, e o Flipper enviará **sequencialmente comandos "Power Off"** para todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV recebe o sinal, ela responde e desliga.

Esse brute-force leva tempo. Quanto maior o dicionário, mais tempo levará para concluir. Não é possível descobrir qual sinal a TV reconheceu, pois ela não fornece feedback.

### Aprender um novo controle remoto

O Flipper Zero pode **capturar um sinal infravermelho**. Se reconhecer o protocolo e o comando, armazena uma representação decodificada; caso contrário, pode armazenar os dados brutos de temporização para reprodução posterior.<sup>[[1]](#references)</sup>

## References

- [1] [Assumindo o controle de TVs com a porta infravermelha do Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
