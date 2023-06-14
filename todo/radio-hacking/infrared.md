# Infravermelho

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Como o Infravermelho Funciona <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do infravermelho varia de **0,7 a 1000 mícrons**. Os controles remotos usam um sinal de infravermelho para transmissão de dados e operam na faixa de comprimento de onda de 0,75 a 1,4 mícrons. Um microcontrolador no controle remoto faz com que um LED infravermelho pisque com uma frequência específica, transformando o sinal digital em um sinal de infravermelho.

Para receber sinais de infravermelho, é usado um **fotoreceptor**. Ele **converte a luz infravermelha em pulsos de tensão**, que já são **sinais digitais**. Geralmente, há um **filtro de luz escura dentro do receptor**, que permite passar **apenas o comprimento de onda desejado** e corta o ruído.

### Variedade de Protocolos de Infravermelho <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos de infravermelho diferem em 3 fatores:

* codificação de bits
* estrutura de dados
* frequência do portador - geralmente na faixa de 36 a 38 kHz

#### Formas de Codificação de Bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificação de Distância de Pulso**

Os bits são codificados pela modulação da duração do espaço entre os pulsos. A largura do próprio pulso é constante.

<figure><img src="../../.gitbook/assets/image (16) (3).png" alt=""><figcaption></figcaption></figure>

**2. Codificação de Largura de Pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após a explosão do pulso é constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de Fase**

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre a explosão do pulso e o espaço. "Espaço para explosão de pulso" denota lógica "0", "explosão de pulso para espaço" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outros exóticos**

{% hint style="info" %}
Existem protocolos de infravermelho que estão **tentando se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, o mais famoso **não significa o mais comum**. Em meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.

Os fabricantes adoram usar seus próprios protocolos de infravermelho exclusivos, mesmo dentro da mesma faixa de dispositivos (por exemplo, TV-boxes). Portanto, controles remotos de diferentes empresas e às vezes de modelos diferentes da mesma empresa, não conseguem trabalhar com outros dispositivos do mesmo tipo.
{% endhint %}

### Explorando um Sinal de Infravermelho

A maneira mais confiável de ver como o sinal de infravermelho do controle remoto se parece é usar um osciloscópio. Ele não demodula nem inverte o sinal recebido, ele é apenas exibido "como está". Isso é útil para testes e depuração. Mostrarei o sinal esperado no exemplo do protocolo NEC de infravermelho.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Geralmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e fundo. Existem também protocolos sem preâmbulo, por exemplo, Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são determinados pelo protocolo específico.

O **protocolo NEC de infravermelho** contém um comando curto e um código de repetição, que é enviado enquanto o botão é pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando NEC**, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, pelo qual o dispositivo entende o que precisa ser executado. Os bytes de endereço e número de comando são duplicados com valores inversos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para a lógica "0" e "1", a NEC usa a Codificação de Distância de Pulso: primeiro, uma explosão de pulso é transmitida, após a qual há uma pausa, cujo comprimento define o valor do bit.

### Condicionadores de Ar

Ao contrário de outros controles remotos, **os condicionadores de ar não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão
