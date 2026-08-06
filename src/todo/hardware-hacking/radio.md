# Rádio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)é um analisador de sinais digitais gratuito para GNU/Linux e macOS, desenvolvido para extrair informações de sinais de rádio desconhecidos. Ele oferece suporte a vários dispositivos SDR por meio do SoapySDR e permite a demodulação ajustável de sinais FSK, PSK e ASK, a decodificação de vídeo analógico, a análise de sinais em rajadas e a escuta de canais de voz analógicos (tudo em tempo real).<sup>[[1]](#references)</sup>

### Configuração básica

Após a instalação, há algumas coisas que você pode considerar configurar.\
Nas configurações (o segundo botão de aba), você pode selecionar o **dispositivo SDR** ou **selecionar um arquivo** para ler, além de escolher a frequência a ser sintonizada e a taxa de amostragem (recomenda-se até 2.56Msps se o seu PC oferecer suporte).

![Configurações do SigDigger mostrando as opções de dispositivo SDR, arquivo de entrada, frequência e taxa de amostragem](<../../images/image (245).png>)

Em comportamento da GUI, recomenda-se habilitar algumas opções se o seu PC oferecer suporte:

![SigDigger - Configuração básica: em comportamento da GUI, recomenda-se habilitar algumas opções se o seu PC oferecer suporte](<../../images/image (472).png>)

> [!TIP]
> Se você perceber que o seu PC não está capturando nada, tente desabilitar o OpenGL e reduzir a taxa de amostragem.

### Usos

- Para **capturar parte de um sinal e analisá-lo**, mantenha o botão "Push to capture" pressionado pelo tempo necessário.

![Configuração básica - Usos: para capturar parte de um sinal e analisá-lo, mantenha o botão "Push to capture" pressionado pelo tempo necessário](<../../images/image (960).png>)

- O **Tuner** do SigDigger ajuda a **capturar sinais melhores** (mas também pode degradá-los). O ideal é começar com 0 e **continuar aumentando até** perceber que o **ruído** introduzido é **maior** que a **melhoria necessária no sinal**.

![Controle do tuner do SigDigger ajustado para melhorar o sinal de rádio capturado](<../../images/image (1099).png>)

### Sincronização com um canal de rádio

Com o [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronize com o canal que deseja ouvir, configure a opção "Baseband audio preview", configure a largura de banda para obter todas as informações enviadas e, em seguida, ajuste o Tuner para o nível anterior ao início do aumento significativo do ruído:<sup>[[1]](#references)</sup>

![Canal de rádio sincronizado no SigDigger, com pré-visualização de áudio de banda base e largura de banda configurada](<../../images/image (585).png>)

## Truques interessantes

- Quando um dispositivo envia rajadas de informações, normalmente a **primeira parte será um preâmbulo**, então você **não precisa se preocupar** se **não encontrar informações** nessa parte **ou se houver alguns erros** nela.
- Em frames de informações, normalmente você deve **encontrar diferentes frames bem alinhados entre si**:

![Sincronização com um canal de rádio - Truques interessantes: em frames de informações, normalmente você deve encontrar diferentes frames bem alinhados entre si](<../../images/image (1076).png>)

![Sincronização com um canal de rádio - Truques interessantes: em frames de informações, normalmente você deve encontrar diferentes frames bem alinhados entre si](<../../images/image (597).png>)

- **Após recuperar os bits, talvez seja necessário processá-los de alguma forma**. Por exemplo, na codificação Manchester, um subida+descida será 1 ou 0, e uma descida+subida será o outro valor. Assim, pares de 1s e 0s (subidas e descidas) formarão um 1 ou 0 real.
- Mesmo que um sinal esteja usando codificação Manchester (é impossível encontrar mais de dois 0s ou 1s consecutivos), você pode **encontrar vários 1s ou 0s juntos no preâmbulo**!

### Descobrindo o tipo de modulação com IQ

Há 3 maneiras de armazenar informações em sinais: modulando a **amplitude**, a **frequência** ou a **fase**.\
Ao verificar um sinal, há diferentes maneiras de tentar descobrir qual delas está sendo usada para armazenar informações (veja mais formas abaixo), mas uma boa opção é verificar o gráfico IQ.

![Gráfico IQ do SigDigger usado para identificar se um sinal usa modulação de amplitude, frequência ou fase](<../../images/image (788).png>)

- **Detectando AM**: Se no gráfico IQ aparecerem, por exemplo, **2 círculos** (provavelmente um em 0 e outro em uma amplitude diferente), isso pode significar que se trata de um sinal AM. Isso ocorre porque, no gráfico IQ, a distância entre o 0 e o círculo representa a amplitude do sinal, facilitando a visualização das diferentes amplitudes utilizadas.
- **Detectando PM**: Como na imagem anterior, se você encontrar pequenos círculos não relacionados entre si, isso provavelmente significa que uma modulação de fase está sendo usada. Isso ocorre porque, no gráfico IQ, o ângulo entre o ponto e 0,0 representa a fase do sinal; portanto, isso significa que 4 fases diferentes são usadas.
- Observe que, se a informação estiver escondida no fato de que uma fase foi alterada, e não na própria fase, você não verá fases diferentes claramente separadas.
- **Detectando FM**: O IQ não possui um campo para identificar frequências (a distância até o centro representa a amplitude e o ângulo representa a fase).\
Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** nesse gráfico.\
Além disso, uma frequência diferente é "representada" no gráfico IQ por uma **aceleração da velocidade ao longo do círculo** (assim, no SysDigger, ao selecionar o sinal, o gráfico IQ é preenchido; se você encontrar uma aceleração ou uma mudança de direção no círculo criado, isso pode significar que se trata de FM):

## Exemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrindo AM

#### Verificando o envelope

Verificando informações AM com o [**SigDigger** ](https://github.com/BatchDrake/SigDigger)e observando apenas o **envelope**, você pode ver diferentes níveis claros de amplitude. O sinal usado envia pulsos com informações em AM; esta é a aparência de um pulso:<sup>[[1]](#references)</sup>

![Envelope de sinal AM no SigDigger com níveis claros de amplitude dos pulsos](<../../images/image (590).png>)

E esta é a aparência de parte do símbolo com a forma de onda:

![Descobrindo AM - Verificando o envelope: esta é a aparência de parte do símbolo com a forma de onda](<../../images/image (734).png>)

#### Verificando o histograma

Você pode **selecionar todo o sinal** onde as informações estão localizadas, selecionar o modo **Amplitude** e **Selection** e clicar em **Histogram.** Você poderá observar que apenas 2 níveis claros são encontrados.

![Histograma de amplitude do SigDigger mostrando dois níveis claros para o sinal AM selecionado](<../../images/image (264).png>)

Por exemplo, se você selecionar Frequency em vez de Amplitude neste sinal AM, encontrará apenas 1 frequência (não há como uma informação modulada em frequência usar apenas 1 frequência).

![Histograma de frequência do SigDigger para o sinal AM mostrando uma frequência](<../../images/image (732).png>)

Se você encontrar muitas frequências, provavelmente isso não será FM; a frequência do sinal pode ter sido apenas modificada por causa do canal.

#### Com IQ

Neste exemplo, você pode ver que há um **círculo grande**, mas também **muitos pontos no centro**.

![Verificando o histograma - Com IQ: neste exemplo, você pode ver que há um círculo grande, mas também muitos pontos no centro](<../../images/image (222).png>)

### Obtendo a taxa de símbolos

#### Com um símbolo

Selecione o menor símbolo que conseguir encontrar (assim você terá certeza de que é apenas 1) e verifique "Selection freq". Neste caso, seria 1.013kHz (ou seja, 1kHz).

![Obtendo a taxa de símbolos - Com um símbolo: selecione o menor símbolo que conseguir encontrar (assim você terá certeza de que é apenas 1) e verifique "Selection freq". Neste caso, seria 1.013kHz (ou seja, 1kHz)](<../../images/image (78).png>)

#### Com um grupo de símbolos

Você também pode indicar o número de símbolos que selecionará, e o SigDigger calculará a frequência de 1 símbolo (quanto mais símbolos forem selecionados, provavelmente melhor). Neste cenário, selecionei 10 símbolos e a "Selection freq" é 1.004 Khz:

![Cálculo da taxa de símbolos no SigDigger usando um grupo selecionado de dez símbolos](<../../images/image (1008).png>)

### Obtendo os bits

Depois de descobrir que este é um sinal **modulado em AM** e a **taxa de símbolos** (e sabendo que, neste caso, algo para cima significa 1 e algo para baixo significa 0), é muito fácil **obter os bits** codificados no sinal. Portanto, selecione o sinal com informações, configure a amostragem e a decisão e pressione sample (verifique se **Amplitude** está selecionado, se a **taxa de símbolos** descoberta está configurada e se **Gadner clock recovery** está selecionado):

![Painel Get Bits do SigDigger configurado para amostragem AM, taxa de símbolos e recuperação de clock Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa que, se você selecionou anteriormente intervalos para encontrar a taxa de símbolos, essa taxa será usada.
- **Manual** significa que a taxa de símbolos indicada será usada.
- Em **Fixed interval selection**, você indica o número de intervalos que devem ser selecionados, e ele calcula a taxa de símbolos a partir disso.
- **Gadner clock recovery** geralmente é a melhor opção, mas ainda é necessário indicar uma taxa de símbolos aproximada.

Ao pressionar sample, isto aparece:

![Com um grupo de símbolos - Obtendo os bits: isto aparece ao pressionar sample](<../../images/image (644).png>)

Agora, para fazer o SigDigger entender **qual é o intervalo** do nível que carrega as informações, você precisa clicar no **nível inferior** e manter o clique até o maior nível:

![Seleção do intervalo de níveis do SigDigger, do nível de menor amplitude até o nível superior](<../../images/image (439).png>)

Se, por exemplo, houvesse **4 níveis diferentes de amplitude**, você deveria ter configurado **Bits per symbol como 2** e selecionado do menor ao maior.

Por fim, **aumentando** o **Zoom** e **alterando o Row size**, você poderá ver os bits (e selecionar todos e copiar para obter todos os bits):

![Com um grupo de símbolos - Obtendo os bits: por fim, aumentando o Zoom e alterando o Row size, você poderá ver os bits](<../../images/image (276).png>)

Se o sinal tiver mais de 1 bit por símbolo (por exemplo, 2), o SigDigger **não tem como saber qual símbolo é** 00, 01, 10 ou 11; portanto, ele usará diferentes **tons de cinza** para representar cada um (e, se você copiar os bits, usará **números de 0 a 3**, que você precisará tratar).

Além disso, use **codificações** como **Manchester**: uma subida+descida pode ser **1 ou 0**, e uma descida+subida pode ser 1 ou 0. Nesses casos, você precisa **tratar as subidas (1) e descidas (0) obtidas** para substituir os pares 01 ou 10 por 0s ou 1s.

## Exemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrindo FM

#### Verificando as frequências e a forma de onda

Exemplo de sinal enviando informações moduladas em FM:

![Descobrindo FM - Verificando as frequências e a forma de onda: exemplo de sinal enviando informações moduladas em FM](<../../images/image (725).png>)

Na imagem anterior, você pode observar claramente que **2 frequências são usadas**, mas, se você **observar** a **forma de onda**, talvez n**ão consiga identificar corretamente as 2 frequências diferentes**:

![Forma de onda FM do SigDigger em que as duas frequências são difíceis de distinguir diretamente](<../../images/image (717).png>)

Isso ocorre porque capturei o sinal em ambas as frequências; portanto, uma é aproximadamente o negativo da outra:

![Captura FM do SigDigger mostrando as duas frequências como aproximadamente negativas uma da outra](<../../images/image (942).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra**, você poderá ver facilmente as 2 frequências diferentes:

![Descobrindo FM - Verificando as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as 2 frequências diferentes](<../../images/image (422).png>)

![Descobrindo FM - Verificando as frequências e a forma de onda: se a frequência sincronizada estiver mais próxima de uma frequência do que da outra, você poderá ver facilmente as 2 frequências diferentes](<../../images/image (488).png>)

#### Verificando o histograma

Ao verificar o histograma de frequência do sinal com informações, você poderá ver facilmente 2 sinais diferentes:

![Verificando as frequências e a forma de onda - Verificando o histograma: ao verificar o histograma de frequência do sinal com informações, você poderá ver facilmente 2 sinais diferentes](<../../images/image (871).png>)

Neste caso, se você verificar o **histograma de amplitude**, encontrará **apenas uma amplitude**, portanto, ele **não pode ser AM** (se você encontrar muitas amplitudes, talvez seja porque o sinal perdeu potência ao longo do canal):

![Histograma de amplitude do SigDigger para um sinal FM mostrando um único nível de amplitude](<../../images/image (817).png>)

E este seria o histograma de fase (que deixa muito claro que o sinal não é modulado em fase):

![Verificando as frequências e a forma de onda - Verificando o histograma: este seria o histograma de fase, que deixa muito claro que o sinal não é modulado em fase](<../../images/image (996).png>)

#### Com IQ

O IQ não possui um campo para identificar frequências (a distância até o centro representa a amplitude e o ângulo representa a fase).\
Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** nesse gráfico.\
Além disso, uma frequência diferente é "representada" no gráfico IQ por uma **aceleração da velocidade ao longo do círculo** (assim, no SysDigger, ao selecionar o sinal, o gráfico IQ é preenchido; se você encontrar uma aceleração ou uma mudança de direção no círculo criado, isso pode significar que se trata de FM):

![Gráfico IQ do SigDigger em que FM aparece como mudanças de aceleração ao redor do círculo](<../../images/image (81).png>)

### Obtendo a taxa de símbolos

Você pode usar a **mesma técnica usada no exemplo de AM** para obter a taxa de símbolos depois de encontrar as frequências que carregam os símbolos.

### Obtendo os bits

Você pode usar a **mesma técnica usada no exemplo de AM** para obter os bits depois de **descobrir que o sinal é modulado em frequência** e obter a **taxa de símbolos**.

## Referências

- [1] [SigDigger - Analisador de sinais digitais gratuito para GNU/Linux e macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
