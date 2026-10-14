# Rádio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) é um analisador de sinais digitais gratuito para GNU/Linux e macOS, projetado para extrair informações de sinais de rádio desconhecidos. Ele oferece suporte a dispositivos SDR por meio do SoapySDR e fornece ferramentas de demodulação e análise em tempo real para FSK, PSK, ASK, vídeo analógico, sinais em rajadas e canais de voz analógica.<sup>[[1]](#references)</sup>

### Configuração básica

Após a instalação, há algumas configurações que você pode considerar.\
Nas configurações (o segundo botão de aba), selecione um **dispositivo SDR** ou um arquivo de entrada, a frequência a sintonizar e a taxa de amostragem. Uma taxa de até 2.56 Msps pode ser prática se o host oferecer suporte.

![Configurações do SigDigger mostrando as opções de dispositivo SDR, arquivo de entrada, frequência e taxa de amostragem](<../../images/image (245).png>)

No comportamento da GUI, é recomendável ativar algumas opções se o seu PC oferecer suporte:

![SigDigger - Configuração básica: no comportamento da GUI, é recomendável ativar algumas opções se o seu PC oferecer suporte](<../../images/image (472).png>)

> [!TIP]
> Se você perceber que seu PC não está capturando os sinais, tente desativar o OpenGL e reduzir a taxa de amostragem.

### Usos

- Para **capturar um trecho do sinal e analisá-lo**, mantenha pressionado o botão "Push to capture" pelo tempo necessário.

![Configuração básica - Usos: para capturar um trecho do sinal e analisá-lo, mantenha pressionado o botão "Push to capture" pelo tempo necessário](<../../images/image (960).png>)

- O **Tuner** do SigDigger ajuda a **capturar sinais melhores** (mas também pode degradá-los). O ideal é começar em 0 e **aumentar o valor até** perceber que o **ruído** introduzido é **maior** do que a **melhoria do sinal** necessária.

![Controle do tuner do SigDigger ajustado para melhorar o sinal de rádio capturado](<../../images/image (1099).png>)

### Sincronizar com o canal de rádio

Com o [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronize com o canal que deseja ouvir, configure a opção "Baseband audio preview", ajuste a largura de banda para obter todas as informações transmitidas e, em seguida, ajuste o Tuner até o nível anterior ao aumento significativo do ruído:<sup>[[1]](#references)</sup>

![Canal de rádio sincronizado no SigDigger com a prévia de áudio em banda base e a largura de banda configuradas](<../../images/image (585).png>)

## Truques interessantes

- Quando um dispositivo envia rajadas de informações, normalmente **a primeira parte será um preâmbulo**. Portanto, **não** se **preocupe** se **não encontrar informações** nessa parte **ou se houver alguns erros**.
- Em quadros de informação, normalmente você deve **encontrar diferentes quadros bem alinhados entre si**:

![Sincronizar com o canal de rádio - Truques interessantes: em quadros de informação, normalmente você deve encontrar diferentes quadros bem alinhados entre si](<../../images/image (1076).png>)

![Sincronizar com o canal de rádio - Truques interessantes: em quadros de informação, normalmente você deve encontrar diferentes quadros bem alinhados entre si](<../../images/image (597).png>)

- **Após recuperar as transições de nível, talvez seja necessário decodificá-las.** Na codificação Manchester, uma direção de transição representa `0` e a direção oposta representa `1`; a polaridade exata depende da convenção usada.
- Um preâmbulo pode conter uma sequência do mesmo nível amostrado, mesmo quando o payload usa codificação Manchester. Portanto, identifique o limite do quadro antes de decodificar.

### Identificar o tipo de modulação com IQ

Há 3 maneiras de armazenar informações em sinais: modulando a **amplitude**, a **frequência** ou a **fase**.\
Ao analisar um sinal, há diferentes maneiras de tentar descobrir qual método é usado para armazenar as informações (veja mais opções abaixo), mas uma boa maneira é verificar o gráfico IQ.

![Gráfico IQ do SigDigger usado para identificar se um sinal utiliza modulação de amplitude, frequência ou fase](<../../images/image (788).png>)

- **Detectar AM**: se o gráfico IQ mostrar, por exemplo, **2 círculos** (provavelmente um em 0 e outro em uma amplitude diferente), isso pode indicar um sinal AM. Isso ocorre porque, no gráfico IQ, a distância entre o 0 e o círculo representa a amplitude do sinal, facilitando a visualização das diferentes amplitudes usadas.
- **Detectar PM**: como na imagem anterior, se você encontrar pequenos círculos sem relação entre si, isso provavelmente indica o uso de modulação de fase. Isso ocorre porque, no gráfico IQ, o ângulo entre o ponto e o 0,0 representa a fase do sinal, o que significa que são usadas 4 fases diferentes.
  - Observe que, se a informação estiver no fato de uma fase mudar, e não na própria fase, você não verá fases diferentes claramente diferenciadas.
- **Detectar FM**: o IQ não tem um campo para identificar frequências (a distância do centro representa a amplitude e o ângulo representa a fase).\
  Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** nesse gráfico.\
  Além disso, um deslocamento de frequência altera a velocidade de rotação ao redor do círculo IQ. Portanto, no SigDigger, uma mudança na velocidade ou na direção da rotação pode indicar FM.

## Exemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar AM

#### Verificar o envelope

Ao inspecionar dados AM com o [**SigDigger**](https://github.com/BatchDrake/SigDigger), o **envelope** do sinal pode revelar níveis de amplitude distintos. O sinal de exemplo transmite informações como pulsos modulados em amplitude; um pulso se parece com isto:<sup>[[1]](#references)</sup>

![Envelope do sinal AM no SigDigger com níveis de amplitude de pulso bem definidos](<../../images/image (590).png>)

E esta é a aparência de parte do símbolo na forma de onda:

![Identificar AM - Verificar o envelope: esta é a aparência de parte do símbolo na forma de onda](<../../images/image (734).png>)

#### Verificar o histograma

Você pode **selecionar todo o sinal** onde as informações estão localizadas, selecionar o modo **Amplitude** e **Selection** e clicar em **Histogram**. É possível observar que só aparecem 2 níveis bem definidos.

![Histograma de amplitude do SigDigger mostrando dois níveis bem definidos para o sinal AM selecionado](<../../images/image (264).png>)

Por exemplo, se você selecionar Frequency em vez de Amplitude neste sinal AM, encontrará apenas 1 frequência (não faz sentido que informações moduladas em frequência usem apenas 1 frequência).

![Histograma de frequência do SigDigger para o sinal AM mostrando uma única frequência](<../../images/image (732).png>)

Se você encontrar muitas frequências, provavelmente não se trata de FM; a frequência do sinal pode simplesmente ter sido alterada pelo canal.

#### Com IQ

Neste exemplo, você pode ver que há um **círculo grande**, mas também **muitos pontos no centro**.

![Verificar o histograma - Com IQ: neste exemplo, você pode ver que há um círculo grande, mas também muitos pontos no centro](<../../images/image (222).png>)

### Obter a taxa de símbolos

#### Com um símbolo

Selecione o menor intervalo que contenha claramente um símbolo e verifique **Selection freq**. Neste exemplo, é 1.013 kHz, aproximadamente 1 kHz.

![Obter a taxa de símbolos - Com um símbolo: selecione o menor intervalo que contenha claramente um símbolo e verifique "Selection freq". Neste exemplo, é 1.013 kHz (ou seja, 1 kHz).](<../../images/image (78).png>)

#### Com um grupo de símbolos

Você também pode indicar o número de símbolos que vai selecionar, e o SigDigger calculará a frequência de 1 símbolo (provavelmente, quanto mais símbolos forem selecionados, melhor). Neste caso, selecionei 10 símbolos e a "Selection freq" é 1.004 kHz:

![Cálculo da taxa de símbolos no SigDigger usando um grupo selecionado de dez símbolos](<../../images/image (1008).png>)

### Obter os bits

Após identificar AM e estimar a **taxa de símbolos**, selecione a região do sinal, configure a amostragem de amplitude e os níveis de decisão, escolha **Gardner clock recovery** e pressione **Sample**:

![Painel Get Bits do SigDigger configurado para amostragem AM, taxa de símbolos e recuperação de clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa que, se você selecionou intervalos anteriormente para encontrar a taxa de símbolos, essa taxa será usada.
- **Manual** significa que será usada a taxa de símbolos indicada.
- Em **Fixed interval selection**, você indica o número de intervalos a selecionar, e a taxa de símbolos é calculada com base nisso.
- **Gardner clock recovery** é uma opção padrão útil, mas ainda exige uma taxa de símbolos aproximada.

Ao pressionar Sample, isto aparece:

![Com um grupo de símbolos - Obter os bits: isto aparece ao pressionar Sample](<../../images/image (644).png>)

Agora, para fazer o SigDigger entender **qual é a faixa** de níveis que contém as informações, você precisa clicar no **nível mais baixo** e manter o botão pressionado até o nível mais alto:

![Seleção da faixa de níveis no SigDigger, do nível de menor amplitude ao nível mais alto](<../../images/image (439).png>)

Se houvesse, por exemplo, **4 níveis diferentes de amplitude**, seria necessário configurar **Bits per symbol como 2** e selecionar do nível mais baixo ao mais alto.

Por fim, **aumentando** o **Zoom** e **alterando o Row size**, você pode ver os bits (e pode selecionar tudo e copiar para obter todos os bits):

![Com um grupo de símbolos - Obter os bits: por fim, aumente o Zoom e altere o Row size para ver os bits (você pode selecionar tudo e copiar para obter todos os bits)](<../../images/image (276).png>)

Se o sinal tiver mais de 1 bit por símbolo (por exemplo, 2), o SigDigger **não tem como saber qual símbolo corresponde a** 00, 01, 10 ou 11. Portanto, ele usará diferentes **tons de cinza** para representar cada símbolo (e, ao copiar os bits, usará **números de 0 a 3**, que você precisará tratar).

Para codificações de linha como **Manchester**, converta cada par de transições válido (`01` ou `10`) em um bit de dados, de acordo com a convenção usada pelo protocolo.

## Exemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar FM

#### Verificar as frequências e a forma de onda

Exemplo de sinal que transmite informações moduladas em FM:

![Identificar FM - Verificar as frequências e a forma de onda: exemplo de sinal que transmite informações moduladas em FM](<../../images/image (725).png>)

O espectro mostra claramente **duas frequências**, embora possa ser difícil distingui-las na forma de onda no domínio do tempo:

![Forma de onda FM no SigDigger em que as duas frequências são difíceis de distinguir diretamente](<../../images/image (717).png>)

Isso acontece porque a captura está centralizada entre as duas frequências, então seus deslocamentos de frequência são aproximadamente opostos:

![Captura FM no SigDigger mostrando as duas frequências como valores aproximadamente opostos](<../../images/image (942).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra**, você poderá ver facilmente as 2 frequências diferentes:

![Identificar FM - Verificar as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as 2 frequências diferentes](<../../images/image (422).png>)

![Identificar FM - Verificar as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as 2 frequências diferentes](<../../images/image (488).png>)

#### Verificar o histograma

Ao verificar o histograma de frequência do sinal com informações, você pode ver facilmente 2 sinais diferentes:

![Verificar as frequências e a forma de onda - Verificar o histograma: ao verificar o histograma de frequência do sinal com informações, você pode ver facilmente 2 sinais diferentes](<../../images/image (871).png>)

Neste caso, se você verificar o **histograma de amplitude**, encontrará **apenas uma amplitude**, portanto, **não pode ser AM** (se encontrar muitas amplitudes, pode ser porque o sinal perdeu potência ao longo do canal):

![Histograma de amplitude do SigDigger para sinal FM mostrando um único nível de amplitude](<../../images/image (817).png>)

E este seria o histograma de fase (que deixa muito claro que o sinal não é modulado em fase):

![Verificar as frequências e a forma de onda - Verificar o histograma: este seria o histograma de fase, que deixa muito claro que o sinal não é modulado em fase](<../../images/image (996).png>)

#### Com IQ

O IQ não tem um campo para identificar frequências (a distância do centro representa a amplitude e o ângulo representa a fase).\
Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** nesse gráfico.\
Além disso, um deslocamento de frequência altera a velocidade de rotação ao redor do círculo IQ. Portanto, no SigDigger, uma mudança na velocidade ou na direção da rotação pode indicar FM:

![Gráfico IQ do SigDigger em que a FM aparece como mudanças na velocidade de rotação ao redor do círculo](<../../images/image (81).png>)

### Obter a taxa de símbolos

Você pode usar **a mesma técnica usada no exemplo de AM** para obter a taxa de símbolos depois de encontrar as frequências que carregam os símbolos.

### Obter os bits

Você pode usar **a mesma técnica usada no exemplo de AM** para obter os bits depois de **identificar que o sinal é modulado em frequência** e encontrar a **taxa de símbolos**.

## References

- [1] [SigDigger - Analisador de sinais digitais gratuito para GNU/Linux e macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
