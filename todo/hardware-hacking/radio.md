# Rádio

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)é um analisador de sinal digital gratuito para GNU/Linux e macOS, projetado para extrair informações de sinais de rádio desconhecidos. Ele suporta uma variedade de dispositivos SDR através do SoapySDR e permite a demodulação ajustável de sinais FSK, PSK e ASK, decodificação de vídeo analógico, análise de sinais intermitentes e escuta de canais de voz analógicos (tudo em tempo real).

### Configuração básica

Depois de instalar, há algumas coisas que você pode considerar configurar.\
Nas configurações (o segundo botão da guia) você pode selecionar o **dispositivo SDR** ou **selecionar um arquivo** para ler e qual frequência sintonizar e a taxa de amostragem (recomendado até 2,56Msps se o seu PC suportar).

![](<../../.gitbook/assets/image (655) (1).png>)

No comportamento da GUI, é recomendável habilitar algumas coisas se o seu PC suportar:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Se você perceber que seu PC não está capturando coisas, tente desativar o OpenGL e diminuir a taxa de amostragem.
{% endhint %}

### Usos

* Apenas para **capturar algum tempo de um sinal e analisá-lo**, mantenha o botão "Push to capture" pelo tempo que precisar.

![](<../../.gitbook/assets/image (631).png>)

* O **Sintonizador** do SigDigger ajuda a **capturar sinais melhores** (mas também pode degradá-los). Idealmente, comece com 0 e continue **aumentando até** encontrar o **ruído** introduzido é **maior** do que a **melhoria do sinal** que você precisa).

![](<../../.gitbook/assets/image (658).png>)

### Sincronizar com o canal de rádio

Com [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincronize com o canal que você deseja ouvir, configure a opção "Baseband audio preview", configure a largura de banda para obter todas as informações sendo enviadas e, em seguida, defina o Sintonizador para o nível antes que o ruído realmente comece a aumentar:

![](<../../.gitbook/assets/image (389).png>)

## Truques interessantes

* Quando um dispositivo está enviando rajadas de informações, geralmente a **primeira parte será um preâmbulo** para que você **não precise se preocupar** se **não encontrar informações** lá **ou se houver alguns erros**.
* Em quadros de informação, você geralmente deve **encontrar diferentes quadros bem alinhados entre eles**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Depois de recuperar os bits, você pode precisar processá-los de alguma forma**. Por exemplo, na codificação Manchester, um up+down será um 1 ou 0 e um down+up será o outro. Portanto, pares de
## Exemplo de FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Descobrindo FM

#### Verificando as frequências e a forma de onda

Exemplo de sinal enviando informações moduladas em FM:

![](<../../.gitbook/assets/image (661) (1).png>)

Na imagem anterior, você pode observar que **2 frequências são usadas**, mas se você **observar** a **forma de onda**, pode **não ser capaz de identificar corretamente as 2 frequências diferentes**:

![](<../../.gitbook/assets/image (653).png>)

Isso ocorre porque eu capturei o sinal em ambas as frequências, portanto uma é aproximadamente a outra em negativo:

![](<../../.gitbook/assets/image (656).png>)

Se a frequência sincronizada estiver **mais próxima de uma frequência do que da outra**, você pode facilmente ver as 2 frequências diferentes:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Verificando o histograma

Verificando o histograma de frequência do sinal com informações, você pode facilmente ver 2 sinais diferentes:

![](<../../.gitbook/assets/image (657).png>)

Neste caso, se você verificar o **histograma de amplitude**, encontrará **apenas uma amplitude**, portanto, **não pode ser AM** (se você encontrar muitas amplitudes, pode ser porque o sinal perdeu potência ao longo do canal):

![](<../../.gitbook/assets/image (646).png>)

E este seria o histograma de fase (o que torna muito claro que o sinal não está modulado em fase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Com IQ

IQ não tem um campo para identificar frequências (a distância do centro é a amplitude e o ângulo é a fase).\
Portanto, para identificar FM, você deve **apenas ver basicamente um círculo** neste gráfico.\
Além disso, uma frequência diferente é "representada" pelo gráfico IQ por uma **aceleração de velocidade em todo o círculo** (então, no SysDigger, selecionando o sinal, o gráfico IQ é preenchido, se você encontrar uma aceleração ou mudança de direção no círculo criado, pode significar que isso é FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Obter taxa de símbolos

Você pode usar a **mesma técnica usada no exemplo AM** para obter a taxa de símbolos assim que encontrar as frequências que carregam símbolos.

### Obter bits

Você pode usar a **mesma técnica usada no exemplo AM** para obter os bits assim que **encontrar o sinal modulado em frequência** e a **taxa de símbolos**. 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
