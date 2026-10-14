# Rádio

{{#include ../../banners/hacktricks-training.md}}

Para trabalhos específicos de cada protocolo após identificar o sinal, consulte [testes de RFID/NFC, sub-GHz, infravermelho, BLE e LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) é um analisador de sinais digitais gratuito para GNU/Linux e macOS, projetado para extrair informações de sinais de rádio desconhecidos. Ele oferece suporte a dispositivos SDR por meio do SoapySDR e fornece ferramentas de demodulação e análise em tempo real para FSK, PSK, ASK, vídeo analógico, sinais em rajadas e canais de voz analógicos.<sup>[[1]](#references)</sup>

### Configuração básica

Após a instalação, há algumas opções de configuração que você pode considerar.\
Nas configurações (o segundo botão de aba), selecione um **dispositivo SDR** ou um arquivo de entrada, a frequência a sintonizar e a taxa de amostragem. Uma taxa de até 2,56 Msps pode ser viável se o computador tiver suporte.

![Configurações do SigDigger mostrando as opções de dispositivo SDR, arquivo de entrada, frequência e taxa de amostragem](<../../images/image (245).png>)

Em comportamento da GUI, recomenda-se ativar algumas opções, se o seu computador oferecer suporte:

![SigDigger - Configuração básica: em comportamento da GUI, recomenda-se ativar algumas opções, se o seu computador oferecer suporte](<../../images/image (472).png>)

> [!TIP]
> Se você perceber que o computador não está capturando os sinais, tente desativar o OpenGL e reduzir a taxa de amostragem.

### Usos

- Para **capturar um trecho de um sinal e analisá-lo**, mantenha o botão "Push to capture" pressionado pelo tempo necessário.

![Configuração básica - Usos: para capturar um trecho de um sinal e analisá-lo, mantenha o botão "Push to capture" pressionado pelo tempo necessário](<../../images/image (960).png>)

- O **Tuner** do SigDigger ajuda a **capturar sinais melhores** (mas também pode degradá-los). O ideal é começar em 0 e **aumentar gradualmente até** que o **ruído** introduzido seja **maior** do que a **melhora do sinal** necessária.

![Controle do Tuner do SigDigger ajustado para melhorar o sinal de rádio capturado](<../../images/image (1099).png>)

### Sincronizar com um canal de rádio

Com o [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronize com o canal que deseja ouvir, configure a opção "Baseband audio preview", ajuste a largura de banda para obter todas as informações transmitidas e, em seguida, ajuste o Tuner até o nível imediatamente anterior ao ponto em que o ruído começa a aumentar de verdade:<sup>[[1]](#references)</sup>

![Canal de rádio sincronizado no SigDigger com a opção Baseband audio preview e a largura de banda configuradas](<../../images/image (585).png>)

## Truques interessantes

- Quando um dispositivo envia informações em rajadas, geralmente **a primeira parte é um preâmbulo**. Portanto, **não** se **preocupe** se **não encontrar informações** nessa parte **ou se houver alguns erros**.
- Em quadros de informação, geralmente é possível **encontrar vários quadros alinhados entre si**:

![Sincronizar com um canal de rádio - Truques interessantes: em quadros de informação, geralmente é possível encontrar vários quadros alinhados entre si](<../../images/image (1076).png>)

![Sincronizar com um canal de rádio - Truques interessantes: em quadros de informação, geralmente é possível encontrar vários quadros alinhados entre si](<../../images/image (597).png>)

- **Depois de recuperar as transições de nível, talvez seja necessário decodificá-las.** Na codificação Manchester, uma direção de transição representa `0` e a direção oposta representa `1`; a polaridade exata depende da convenção usada.
- Um preâmbulo pode conter uma sequência do mesmo nível amostrado, mesmo quando a carga útil usa codificação Manchester. Portanto, identifique o limite do quadro antes de decodificar.

### Descobrir o tipo de modulação com IQ

Há três formas de armazenar informações em sinais: modulando a **amplitude**, a **frequência** ou a **fase**.\
Ao analisar um sinal, há várias maneiras de tentar identificar qual delas está sendo usada para armazenar informações (veja mais opções abaixo), mas uma boa abordagem é verificar o gráfico IQ.

![Gráfico IQ do SigDigger usado para identificar se um sinal utiliza modulação de amplitude, frequência ou fase](<../../images/image (788).png>)

- **Detectar AM**: se o gráfico IQ mostrar, por exemplo, **dois círculos** (provavelmente um em 0 e outro em uma amplitude diferente), isso pode indicar um sinal AM. No gráfico IQ, a distância entre o 0 e o círculo corresponde à amplitude do sinal, facilitando a visualização das diferentes amplitudes usadas.
- **Detectar PM**: como na imagem anterior, se você encontrar círculos pequenos sem relação entre si, provavelmente está sendo usada uma modulação de fase. No gráfico IQ, o ângulo entre o ponto e o ponto 0,0 corresponde à fase do sinal, o que significa que são usadas quatro fases diferentes.
  - Observe que, se a informação estiver na mudança de fase, e não na fase em si, você não verá fases diferentes claramente distintas.
- **Detectar FM**: o gráfico IQ não tem um campo para identificar frequências (a distância do centro representa a amplitude e o ângulo representa a fase).\
  Portanto, para identificar FM, você deve ver **basicamente apenas um círculo** nesse gráfico.\
  Além disso, um desvio de frequência altera a velocidade de rotação ao redor do círculo IQ. Assim, no SigDigger, uma mudança na velocidade ou na direção da rotação pode indicar FM.

## Exemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrir AM

#### Verificar o envelope

Ao inspecionar dados AM com o [**SigDigger**](https://github.com/BatchDrake/SigDigger), o **envelope** do sinal pode revelar níveis de amplitude distintos. O sinal de exemplo envia informações como pulsos modulados em amplitude; um pulso se parece com isto:<sup>[[1]](#references)</sup>

![Envelope de um sinal AM no SigDigger com níveis de amplitude dos pulsos bem definidos](<../../images/image (590).png>)

Este é o aspecto de uma parte do símbolo com a forma de onda:

![Descobrir AM - Verificar o envelope: este é o aspecto de uma parte do símbolo com a forma de onda](<../../images/image (734).png>)

#### Verificar o histograma

Você pode **selecionar todo o sinal** que contém informações, selecionar o modo **Amplitude** e **Selection** e clicar em **Histogram.** É possível observar que só aparecem dois níveis bem definidos.

![Histograma de amplitude do SigDigger mostrando dois níveis bem definidos para o sinal AM selecionado](<../../images/image (264).png>)

Por exemplo, se você selecionar Frequency em vez de Amplitude nesse sinal AM, encontrará apenas uma frequência (não faz sentido a informação modulada em frequência usar apenas uma frequência).

![Histograma de frequência do SigDigger para o sinal AM mostrando uma frequência](<../../images/image (732).png>)

Se encontrar muitas frequências, o sinal provavelmente não será FM; a frequência do sinal pode simplesmente ter sido alterada pelo canal.

#### Com IQ

Neste exemplo, é possível ver um **círculo grande**, mas também **muitos pontos no centro**.

![Verificar o histograma - Com IQ: neste exemplo, é possível ver um círculo grande, mas também muitos pontos no centro](<../../images/image (222).png>)

### Obter a taxa de símbolos

#### Com um símbolo

Selecione o menor intervalo que contenha claramente um símbolo e verifique **Selection freq**. Neste exemplo, o valor é 1,013 kHz, aproximadamente 1 kHz.

![Obter a taxa de símbolos - Com um símbolo: selecione o menor intervalo que contenha claramente um símbolo e verifique "Selection freq". Neste exemplo, o valor é 1,013 kHz (ou seja, 1 kHz).](<../../images/image (78).png>)

#### Com um grupo de símbolos

Você também pode indicar o número de símbolos que vai selecionar, e o SigDigger calculará a frequência de um símbolo (provavelmente, quanto mais símbolos forem selecionados, melhor). Neste caso, selecionei 10 símbolos e o valor de "Selection freq" é 1,004 kHz:

![Cálculo da taxa de símbolos no SigDigger usando um grupo selecionado de dez símbolos](<../../images/image (1008).png>)

### Obter bits

Depois de identificar AM e estimar a **taxa de símbolos**, selecione a região do sinal, configure a amostragem de amplitude e os níveis de decisão, escolha **Gardner clock recovery** e pressione **Sample**:

![Painel Get Bits do SigDigger configurado para amostragem AM, taxa de símbolos e recuperação de clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa que, se você selecionou intervalos anteriormente para encontrar a taxa de símbolos, essa taxa será usada.
- **Manual** significa que será usada a taxa de símbolos indicada.
- Em **Fixed interval selection**, você indica o número de intervalos a selecionar, e o SigDigger calcula a taxa de símbolos a partir deles.
- **Gardner clock recovery** é uma opção padrão útil, mas ainda requer uma taxa de símbolos aproximada.

Ao pressionar Sample, isto aparece:

![Com um grupo de símbolos - Obter bits: isto aparece ao pressionar Sample](<../../images/image (644).png>)

Agora, para o SigDigger entender **onde está a faixa** do nível que contém as informações, clique no **nível mais baixo** e mantenha o botão pressionado até chegar ao nível mais alto:

![Seleção da faixa de níveis no SigDigger, do nível de menor amplitude ao nível mais alto](<../../images/image (439).png>)

Se, por exemplo, houvesse **quatro níveis de amplitude diferentes**, seria necessário configurar **Bits per symbol** como 2 e selecionar do nível mais baixo ao mais alto.

Por fim, **aumentando** o **Zoom** e **alterando o Row size**, você pode ver os bits (e pode selecionar todos e copiá-los para obter a sequência completa):

![Com um grupo de símbolos - Obter bits: por fim, aumente o Zoom e altere o Row size para ver os bits (você pode selecionar todos e copiá-los para obter a sequência completa)](<../../images/image (276).png>)

Se o sinal tiver mais de 1 bit por símbolo (por exemplo, 2), o SigDigger **não tem como saber qual símbolo corresponde** a 00, 01, 10 ou 11. Portanto, ele usará **tons de cinza** diferentes para representá-los (e, ao copiar os bits, usará **números de 0 a 3**, que você precisará interpretar).

Para codificações de linha como **Manchester**, converta cada par de transições válido (`01` ou `10`) em um bit de dados, de acordo com a convenção usada pelo protocolo.

## Exemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrir FM

#### Verificar as frequências e a forma de onda

Exemplo de sinal que envia informações moduladas em FM:

![Descobrir FM - Verificar as frequências e a forma de onda: exemplo de sinal que envia informações moduladas em FM](<../../images/image (725).png>)

O espectro mostra claramente **duas frequências**, embora possa ser difícil distingui-las na forma de onda no domínio do tempo:

![Forma de onda FM no SigDigger em que é difícil distinguir diretamente as duas frequências](<../../images/image (717).png>)

Isso acontece porque a captura está centralizada entre as duas frequências, então seus desvios de frequência são aproximadamente opostos:

![Captura FM no SigDigger mostrando as duas frequências com desvios aproximadamente opostos](<../../images/image (942).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra**, você poderá ver facilmente as duas frequências diferentes:

![Descobrir FM - Verificar as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as duas frequências diferentes](<../../images/image (422).png>)

![Descobrir FM - Verificar as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as duas frequências diferentes](<../../images/image (488).png>)

#### Verificar o histograma

Ao verificar o histograma de frequência do sinal com informações, é fácil ver dois sinais diferentes:

![Verificar as frequências e a forma de onda - Verificar o histograma: ao verificar o histograma de frequência do sinal com informações, é fácil ver dois sinais diferentes](<../../images/image (871).png>)

Neste caso, se você verificar o **histograma de amplitude**, encontrará **apenas uma amplitude**, então **não pode ser AM** (se encontrar muitas amplitudes, pode ser porque o sinal perdeu potência ao longo do canal):

![Histograma de amplitude do SigDigger para um sinal FM mostrando um único nível de amplitude](<../../images/image (817).png>)

Este seria o histograma de fase (que deixa bem claro que o sinal não é modulado em fase):

![Verificar as frequências e a forma de onda - Verificar o histograma: este seria o histograma de fase, que deixa bem claro que o sinal não é modulado em fase](<../../images/image (996).png>)

#### Com IQ

O gráfico IQ não tem um campo para identificar frequências (a distância do centro representa a amplitude e o ângulo representa a fase).\
Portanto, para identificar FM, você deve ver **basicamente apenas um círculo** nesse gráfico.\
Além disso, um desvio de frequência altera a velocidade de rotação ao redor do círculo IQ. Assim, no SigDigger, uma mudança na velocidade ou na direção da rotação pode indicar FM:

![Gráfico IQ do SigDigger no qual FM aparece como mudanças na velocidade de rotação ao redor do círculo](<../../images/image (81).png>)

### Obter a taxa de símbolos

Você pode usar **a mesma técnica usada no exemplo de AM** para obter a taxa de símbolos depois de encontrar as frequências que os representam.

### Obter bits

Você pode usar **a mesma técnica usada no exemplo de AM** para obter os bits depois de **identificar que o sinal é modulado em frequência** e determinar a **taxa de símbolos**.

## References

- [1] [SigDigger - Analisador de sinais digitais gratuito para GNU/Linux e macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
