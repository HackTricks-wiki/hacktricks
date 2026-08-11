# FZ - Infravermelho

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como o infravermelho funciona, consulte:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper Zero usa um receptor IR demodulador para capturar sinais de controles remotos IR comuns. Alguns telefones, incluindo determinados modelos da Xiaomi, possuem um transmissor IR, mas a maioria não consegue receber e decodificar sinais de controles remotos.<sup>[[1]](#references)</sup>

O **receptor infravermelho do Flipper é bastante sensível**. Você pode até **capturar o sinal** enquanto permanece **em algum ponto entre** o controle remoto e a TV. Não é necessário apontar o controle remoto diretamente para a porta IR do Flipper. Isso é útil quando alguém está trocando de canal próximo à TV, enquanto você e o Flipper estão a alguma distância.

A decodificação do protocolo ocorre no software. Protocolos reconhecidos podem ser armazenados como comandos decodificados; protocolos não suportados podem ser capturados e reproduzidos como dados brutos de temporização, dentro dos limites de frequência da portadora e de temporização do hardware.<sup>[[1]](#references)</sup>

## Ações

### Controles Remotos Universais

O modo de controle remoto universal do Flipper Zero percorre comandos conhecidos do banco de dados infravermelho para TVs, equipamentos de áudio, projetores e aparelhos de ar-condicionado compatíveis. Não há garantia de que ele controlará todos os dispositivos, e deve ser usado apenas em equipamentos que você possui ou está autorizado a testar.<sup>[[1]](#references)</sup>

Basta pressionar o botão de ligar/desligar no modo de Controle Remoto Universal, e o Flipper **enviará sequencialmente comandos de "Desligar"** para todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV receber o sinal correspondente, ela reagirá e desligará.

Esse brute-force leva tempo. Quanto maior o dicionário, mais tempo será necessário para concluir. Não é possível descobrir exatamente qual sinal a TV reconheceu, pois não há feedback da TV.

### Aprender Novo Controle Remoto

O Flipper Zero pode **capturar um sinal infravermelho**. Se reconhecer o protocolo e o comando, ele armazena uma representação decodificada; caso contrário, pode armazenar os dados brutos de temporização para reprodução posterior.<sup>[[1]](#references)</sup>

## References

- [1] [Assumindo o controle de TVs com a porta infravermelha do Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
