# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#kfpn7" id="kfpn7"></a>

O Flipper Zero pode **receber e transmitir frequências de rádio na faixa de 300-928 MHz** com seu módulo integrado, que pode ler, salvar e emular controles remotos. Esses controles são usados para interação com portões, barreiras, fechaduras de rádio, interruptores de controle remoto, campainhas sem fio, luzes inteligentes e muito mais. O Flipper Zero pode ajudar você a descobrir se sua segurança foi comprometida.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

O Flipper Zero possui um módulo integrado sub-1 GHz baseado em um chip [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) e uma antena de rádio (o alcance máximo é de 50 metros). Tanto o chip CC1101 quanto a antena foram projetados para operar nas bandas de 300-348 MHz, 387-464 MHz e 779-928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Ações

### Frequency Analyser

> [!TIP]
> Como descobrir qual frequência o controle remoto está usando

Durante a análise, o Flipper Zero verifica a intensidade dos sinais (RSSI) em todas as frequências disponíveis na configuração de frequência. O Flipper Zero exibe a frequência com o maior valor de RSSI, com intensidade de sinal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Para determinar a frequência do controle remoto, faça o seguinte:

1. Coloque o controle remoto bem próximo ao lado esquerdo do Flipper Zero.
2. Acesse **Main Menu** **→ Sub-GHz**.
3. Selecione **Frequency Analyzer** e mantenha pressionado o botão do controle remoto que deseja analisar.
4. Verifique o valor da frequência na tela.

### Read

> [!TIP]
> Encontre informações sobre a frequência usada (também é outra forma de descobrir qual frequência é usada)

A opção **Read** **escuta na frequência configurada** na modulação indicada: 433.92 AM por padrão. Se **algo for encontrado** durante a leitura, **as informações serão exibidas** na tela. Essas informações podem ser usadas para replicar o sinal no futuro.<sup>[[1]](#references)</sup>

Enquanto o Read está em uso, é possível pressionar o **botão esquerdo** e **configurá-lo**.\
No momento, ele possui **4 modulações** (AM270, AM650, FM328 e FM476) e **várias frequências relevantes** armazenadas:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Você pode definir **qualquer uma que seja do seu interesse**. No entanto, se **não tiver certeza de qual frequência** pode ser a usada pelo seu controle remoto, **ative Hopping** (desativado por padrão) e pressione o botão várias vezes até que o Flipper a capture e forneça as informações necessárias para definir a frequência.

> [!CAUTION]
> Alternar entre frequências leva algum tempo; portanto, sinais transmitidos durante a alternância podem ser perdidos. Para obter uma melhor recepção de sinal, defina uma frequência fixa determinada pelo Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Roube (e reproduza) um sinal na frequência configurada

A opção **Read Raw** **grava sinais** enviados na frequência monitorada. Isso pode ser usado para **roubar** um sinal e **repeti-lo**.

Por padrão, o **Read Raw também está em 433.92 em AM650**, mas, se com a opção Read você descobrir que o sinal de seu interesse está em uma **frequência/modulação diferente, também poderá alterá-la** pressionando o botão esquerdo (enquanto estiver dentro da opção Read Raw).

### Brute-Force

Se você conhece o protocolo usado, por exemplo, pelo portão da garagem, é possível g**erar todos os códigos e enviá-los com o Flipper Zero.** Este é um exemplo que oferece suporte aos tipos comuns e gerais de garagens: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Adicione sinais a partir de uma lista configurada de protocolos

#### List of [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Estático |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Estático |
| Nice Flo 24bit_433                                             | 433.92 | Estático |
| CAME 12bit_433                                                 | 433.92 | Estático |
| CAME 24bit_433                                                 | 433.92 | Estático |
| Linear_300                                                     | 300.00 | Estático |
| CAME TWEE                                                      | 433.92 | Estático |
| Gate TX_433                                                    | 433.92 | Estático |
| DoorHan_315                                                    | 315.00 | Dinâmico |
| DoorHan_433                                                    | 433.92 | Dinâmico |
| LiftMaster_315                                                 | 315.00 | Dinâmico |
| LiftMaster_390                                                 | 390.00 | Dinâmico |
| Security+2.0_310                                               | 310.00 | Dinâmico |
| Security+2.0_315                                               | 315.00 | Dinâmico |
| Security+2.0_390                                               | 390.00 | Dinâmico |

### Fornecedores Sub-GHz compatíveis

Consulte a lista em [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequências compatíveis por região

Consulte a lista em [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Obtenha os dBms das frequências salvas

## Referências

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
