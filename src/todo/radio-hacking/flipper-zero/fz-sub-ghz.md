# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#introduction" id="introduction"></a>

O Flipper Zero pode **receber e transmitir frequências de rádio na faixa de 300-928 MHz** com seu módulo integrado, sujeito às restrições de frequência da região configurada. Ele pode ler, salvar e emular controles remotos compatíveis usados em portões, barreiras, fechaduras de rádio, interruptores, campainhas sem fio, luzes inteligentes e outros dispositivos.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

O Flipper Zero possui um módulo integrado abaixo de 1 GHz baseado em um transceptor CC1101 e uma antena de rádio. O alcance real depende da frequência, da antena, do ambiente e do transmissor; a Flipper documenta até aproximadamente 50 metros em condições favoráveis. O hardware cobre 300-348 MHz, 387-464 MHz e 779-928 MHz, enquanto o firmware e as regras regionais restringem ainda mais a transmissão.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Ações

### Analisador de frequência

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
> Encontrar informações sobre a frequência usada (também é uma forma de descobrir qual frequência é usada)

A opção **Read** escuta na frequência e na modulação configuradas (433.92 MHz AM por padrão). Quando reconhece um sinal compatível, a tela exibe informações que podem ser salvas e reproduzidas posteriormente.<sup>[[1]](#references)</sup>

Enquanto o Read está em uso, é possível pressionar o **botão esquerdo** e **configurá-lo**.\
No momento, ele possui **4 modulações** (AM270, AM650, FM328 e FM476) e **várias frequências relevantes** armazenadas:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Você pode selecionar qualquer frequência permitida. Se não tiver certeza de qual frequência o controle remoto usa, defina **Hopping como ON** (desativado por padrão) e pressione o botão do controle remoto várias vezes até que o Flipper capture o sinal e informe a frequência.

> [!CAUTION]
> Alternar entre frequências leva algum tempo; portanto, sinais transmitidos no momento da alternância podem ser perdidos. Para obter uma recepção de sinal melhor, defina uma frequência fixa determinada pelo Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Capturar (e reproduzir) um sinal na frequência configurada

A opção **Read Raw** grava os sinais enviados na frequência selecionada. Isso pode ser usado para capturar e reproduzir um sinal durante testes autorizados.<sup>[[1]](#references)</sup>

Por padrão, o **Read Raw também usa 433.92 MHz com AM650**. Se a opção Read encontrar um sinal em uma frequência ou modulação diferente, pressione Left dentro do Read Raw para alterar essas configurações.

### Brute-Force

Se você souber qual protocolo um dispositivo, como uma porta de garagem, utiliza, pode ser possível **gerar códigos candidatos e transmiti-los com o Flipper Zero**. O projeto `flipperzero-bruteforce` oferece suporte a vários protocolos comuns de códigos estáticos.<sup>[[3]](#references)</sup>

### Adicionar manualmente

> [!TIP]
> Adicionar sinais a partir de uma lista configurada de protocolos

#### Lista de protocolos compatíveis <a href="#id-3iglu" id="id-3iglu"></a>

O menu Add Manually disponibiliza as predefinições de protocolos documentadas pelo Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Vendors Sub-GHz compatíveis

Consulte a lista de vendors compatíveis do Flipper Zero.<sup>[[5]](#references)</sup>

### Frequências compatíveis por região

Consulte a lista oficial de frequências regionais antes de transmitir.<sup>[[6]](#references)</sup>

### Teste

> [!TIP]
> Obter os dBms das frequências salvas

## References

- [1] [Sub-GHz - Documentação do usuário do Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Folha de dados do Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Adicionar um controle remoto criado manualmente](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Vendors Sub-GHz compatíveis](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Frequências Sub-GHz regionais](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
