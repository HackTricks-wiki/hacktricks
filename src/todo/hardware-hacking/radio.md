# Rádio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)é um analisador de sinal digital gratuito para GNU/Linux e macOS, projetado para extrair informações de sinais de rádio desconhecidos. Ele suporta uma variedade de dispositivos SDR através do SoapySDR e permite a demodulação ajustável de sinais FSK, PSK e ASK, decodifica vídeo analógico, analisa sinais intermitentes e escuta canais de voz analógicos (tudo em tempo real).

### Configuração Básica

Após a instalação, há algumas coisas que você pode considerar configurar.\
Nas configurações (o segundo botão da aba) você pode selecionar o **dispositivo SDR** ou **selecionar um arquivo** para ler e qual frequência sintonizar e a taxa de amostragem (recomendado até 2.56Msps se seu PC suportar)\\

![](<../../images/image (245).png>)

No comportamento da GUI, é recomendado habilitar algumas coisas se seu PC suportar:

![](<../../images/image (472).png>)

> [!NOTE]
> Se você perceber que seu PC não está capturando as coisas, tente desabilitar o OpenGL e diminuir a taxa de amostragem.

### Usos

- Para **capturar algum tempo de um sinal e analisá-lo**, mantenha o botão "Push to capture" pressionado pelo tempo que precisar.

![](<../../images/image (960).png>)

- O **Tuner** do SigDigger ajuda a **capturar melhores sinais** (mas também pode degradá-los). Idealmente, comece com 0 e continue **aumentando até** encontrar o **ruído** introduzido que é **maior** do que a **melhoria do sinal** que você precisa).

![](<../../images/image (1099).png>)

### Sincronizar com o canal de rádio

Com [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronize com o canal que você deseja ouvir, configure a opção "Baseband audio preview", configure a largura de banda para obter todas as informações sendo enviadas e, em seguida, ajuste o Tuner para o nível antes que o ruído comece a aumentar realmente:

![](<../../images/image (585).png>)

## Truques Interessantes

- Quando um dispositivo está enviando explosões de informações, geralmente a **primeira parte será um preâmbulo**, então você **não** precisa **se preocupar** se você **não encontrar informações** lá **ou se houver alguns erros**.
- Em quadros de informações, você geralmente deve **encontrar diferentes quadros bem alinhados entre si**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Após recuperar os bits, você pode precisar processá-los de alguma forma**. Por exemplo, na codificação Manchester, um up+down será 1 ou 0 e um down+up será o outro. Assim, pares de 1s e 0s (ups e downs) serão um 1 real ou um 0 real.
- Mesmo que um sinal esteja usando codificação Manchester (é impossível encontrar mais de dois 0s ou 1s em sequência), você pode **encontrar vários 1s ou 0s juntos no preâmbulo**!

### Descobrindo o tipo de modulação com IQ

Existem 3 maneiras de armazenar informações em sinais: Modulando a **amplitude**, **frequência** ou **fase**.\
Se você está verificando um sinal, existem diferentes maneiras de tentar descobrir o que está sendo usado para armazenar informações (encontre mais maneiras abaixo), mas uma boa é verificar o gráfico IQ.

![](<../../images/image (788).png>)

- **Detectando AM**: Se no gráfico IQ aparecem, por exemplo, **2 círculos** (provavelmente um em 0 e outro em uma amplitude diferente), isso pode significar que este é um sinal AM. Isso ocorre porque no gráfico IQ a distância entre o 0 e o círculo é a amplitude do sinal, então é fácil visualizar diferentes amplitudes sendo usadas.
- **Detectando PM**: Como na imagem anterior, se você encontrar pequenos círculos não relacionados entre si, isso provavelmente significa que uma modulação de fase está sendo usada. Isso ocorre porque no gráfico IQ, o ângulo entre o ponto e o 0,0 é a fase do sinal, então isso significa que 4 fases diferentes estão sendo usadas.
- Note que se a informação estiver oculta no fato de que uma fase é alterada e não na fase em si, você não verá diferentes fases claramente diferenciadas.
- **Detectando FM**: IQ não tem um campo para identificar frequências (a distância ao centro é amplitude e o ângulo é fase).\
Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** neste gráfico.\
Além disso, uma frequência diferente é "representada" pelo gráfico IQ por uma **aceleração de velocidade ao longo do círculo** (então, no SysDigger, selecionando o sinal, o gráfico IQ é populado; se você encontrar uma aceleração ou mudança de direção no círculo criado, isso pode significar que isso é FM):

## Exemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrindo AM

#### Verificando o envelope

Verificando informações AM com [**SigDigger** ](https://github.com/BatchDrake/SigDigger)e apenas olhando para o **envelope**, você pode ver diferentes níveis de amplitude claros. O sinal utilizado está enviando pulsos com informações em AM, assim é como um pulso se parece:

![](<../../images/image (590).png>)

E assim é como parte do símbolo se parece com a forma de onda:

![](<../../images/image (734).png>)

#### Verificando o Histograma

Você pode **selecionar todo o sinal** onde as informações estão localizadas, selecionar o modo **Amplitude** e **Seleção** e clicar em **Histograma.** Você pode observar que 2 níveis claros são encontrados

![](<../../images/image (264).png>)

Por exemplo, se você selecionar Frequência em vez de Amplitude neste sinal AM, você encontra apenas 1 frequência (não há como a informação modulada em frequência estar usando apenas 1 frequência).

![](<../../images/image (732).png>)

Se você encontrar muitas frequências, isso provavelmente não será um FM; provavelmente a frequência do sinal foi apenas modificada por causa do canal.

#### Com IQ

Neste exemplo, você pode ver como há um **grande círculo**, mas também **muitos pontos no centro.**

![](<../../images/image (222).png>)

### Obter Taxa de Símbolos

#### Com um símbolo

Selecione o menor símbolo que você pode encontrar (para ter certeza de que é apenas 1) e verifique a "Frequência de Seleção". Neste caso, seria 1.013kHz (ou seja, 1kHz).

![](<../../images/image (78).png>)

#### Com um grupo de símbolos

Você também pode indicar o número de símbolos que você vai selecionar e o SigDigger calculará a frequência de 1 símbolo (quanto mais símbolos selecionados, melhor provavelmente). Neste cenário, selecionei 10 símbolos e a "Frequência de Seleção" é 1.004 Khz:

![](<../../images/image (1008).png>)

### Obter Bits

Tendo encontrado que este é um sinal **modulado em AM** e a **taxa de símbolos** (e sabendo que neste caso algo up significa 1 e algo down significa 0), é muito fácil **obter os bits** codificados no sinal. Então, selecione o sinal com informações e configure a amostragem e a decisão e pressione amostra (verifique se **Amplitude** está selecionado, a **Taxa de Símbolos** descoberta está configurada e a **recuperação de clock de Gardner** está selecionada):

![](<../../images/image (965).png>)

- **Sincronizar com intervalos de seleção** significa que se você selecionou anteriormente intervalos para encontrar a taxa de símbolos, essa taxa de símbolos será usada.
- **Manual** significa que a taxa de símbolos indicada será usada.
- Na **Seleção de intervalo fixo**, você indica o número de intervalos que devem ser selecionados e ele calcula a taxa de símbolos a partir disso.
- **Recuperação de clock de Gardner** é geralmente a melhor opção, mas você ainda precisa indicar alguma taxa de símbolos aproximada.

Pressionando amostra, isso aparece:

![](<../../images/image (644).png>)

Agora, para fazer o SigDigger entender **onde está o intervalo** do nível que carrega informações, você precisa clicar no **nível mais baixo** e manter pressionado até o maior nível:

![](<../../images/image (439).png>)

Se houvesse, por exemplo, **4 níveis diferentes de amplitude**, você precisaria configurar os **Bits por símbolo para 2** e selecionar do menor para o maior.

Finalmente, **aumentando** o **Zoom** e **mudando o tamanho da linha**, você pode ver os bits (e pode selecionar tudo e copiar para obter todos os bits):

![](<../../images/image (276).png>)

Se o sinal tiver mais de 1 bit por símbolo (por exemplo, 2), o SigDigger **não tem como saber qual símbolo é** 00, 01, 10, 11, então ele usará diferentes **escalas de cinza** para representar cada um (e se você copiar os bits, ele usará **números de 0 a 3**, você precisará tratá-los).

Além disso, use **codificações** como **Manchester**, e **up+down** pode ser **1 ou 0** e um down+up pode ser um 1 ou 0. Nesses casos, você precisa **tratar os ups obtidos (1) e downs (0)** para substituir os pares de 01 ou 10 por 0s ou 1s.

## Exemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descobrindo FM

#### Verificando as frequências e a forma de onda

Exemplo de sinal enviando informações moduladas em FM:

![](<../../images/image (725).png>)

Na imagem anterior, você pode observar muito bem que **2 frequências estão sendo usadas**, mas se você **observar** a **forma de onda**, pode **não ser capaz de identificar corretamente as 2 diferentes frequências**:

![](<../../images/image (717).png>)

Isso ocorre porque capturei o sinal em ambas as frequências, portanto uma é aproximadamente a outra em negativo:

![](<../../images/image (942).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra**, você pode ver facilmente as 2 diferentes frequências:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Verificando o histograma

Verificando o histograma de frequência do sinal com informações, você pode facilmente ver 2 sinais diferentes:

![](<../../images/image (871).png>)

Neste caso, se você verificar o **histograma de Amplitude**, encontrará **apenas uma amplitude**, então **não pode ser AM** (se você encontrar muitas amplitudes, pode ser porque o sinal perdeu potência ao longo do canal):

![](<../../images/image (817).png>)

E este seria o histograma de fase (que deixa muito claro que o sinal não está modulado em fase):

![](<../../images/image (996).png>)

#### Com IQ

IQ não tem um campo para identificar frequências (a distância ao centro é amplitude e o ângulo é fase).\
Portanto, para identificar FM, você deve **ver basicamente apenas um círculo** neste gráfico.\
Além disso, uma frequência diferente é "representada" pelo gráfico IQ por uma **aceleração de velocidade ao longo do círculo** (então, no SysDigger, selecionando o sinal, o gráfico IQ é populado; se você encontrar uma aceleração ou mudança de direção no círculo criado, isso pode significar que isso é FM):

![](<../../images/image (81).png>)

### Obter Taxa de Símbolos

Você pode usar a **mesma técnica que a utilizada no exemplo de AM** para obter a taxa de símbolos uma vez que você tenha encontrado as frequências que carregam símbolos.

### Obter Bits

Você pode usar a **mesma técnica que a utilizada no exemplo de AM** para obter os bits uma vez que você tenha **descoberto que o sinal está modulado em frequência** e a **taxa de símbolos**.

{{#include ../../banners/hacktricks-training.md}}
