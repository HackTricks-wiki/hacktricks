# Infravermelho

{{#include ../../banners/hacktricks-training.md}}

## Como funciona o infravermelho <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR varia de **0,7 a 1000 mícrons**. Os controles remotos domésticos usam um sinal IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75..1,4 mícrons. Um microcontrolador no controle remoto faz um LED infravermelho piscar em uma frequência específica, convertendo o sinal digital em um sinal IR.

Para receber sinais IR, utiliza-se um **fotorreceptor**. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Normalmente, há um **filtro de luz escura dentro do receptor**, que permite a passagem **somente do comprimento de onda desejado** e elimina o ruído.<sup>[[1]](#references)</sup>

### Variedade de protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:<sup>[[1]](#references)</sup>

- codificação de bits
- estrutura dos dados
- frequência da portadora — geralmente na faixa de 36..38 kHz

#### Formas de codificação de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Os bits são codificados modulando a duração do espaço entre os pulsos. A largura do próprio pulso é constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após o burst do pulso é constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre o burst do pulso e o espaço. "Espaço para burst do pulso" indica a lógica "0", enquanto "burst do pulso para espaço" indica a lógica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinação das anteriores e outras exóticas**

> [!TIP]
> Existem protocolos IR que **tentam se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, **mais famoso não significa mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.
>
> Os fabricantes adoram usar seus próprios protocolos IR exclusivos, até mesmo dentro da mesma categoria de dispositivos (por exemplo, TV boxes). Portanto, controles remotos de empresas diferentes e, às vezes, de modelos diferentes da mesma empresa, não conseguem funcionar com outros dispositivos do mesmo tipo.

### Explorando um sinal IR

A maneira mais confiável de ver como é o sinal IR de um controle remoto é usar um osciloscópio. Ele não demodula nem inverte o sinal recebido; apenas o exibe "como está". Isso é útil para testes e debugging. Vou mostrar o sinal esperado usando o protocolo IR NEC como exemplo.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o sinal de fundo. Também existem protocolos sem preâmbulo, como o Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, que é enviado enquanto o botão está pressionado. Tanto o comando quanto o código de repetição possuem o mesmo preâmbulo no início.

O **comando** NEC, além do preâmbulo, consiste em um byte de endereço e um byte de número do comando, pelos quais o dispositivo entende o que precisa ser executado. Os bytes de endereço e de número do comando são duplicados com valores invertidos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** possui um "1" após o preâmbulo, que é um bit de parada.

Para a **lógica "0" e "1"**, o NEC usa Pulse Distance Encoding: primeiro, um burst de pulso é transmitido, seguido por uma pausa cuja duração define o valor do bit.

### Ar-condicionados

Ao contrário de outros controles remotos, **os ar-condicionados não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado, para garantir que o **aparelho de ar-condicionado e o controle remoto estejam sincronizados**.\
Isso evita que um aparelho configurado para 20 ºC seja aumentado para 21 ºC com um controle remoto e, depois, quando outro controle remoto, que ainda tem a temperatura configurada como 20 ºC, for usado para aumentar mais a temperatura, ela seja "aumentada" para 21 ºC (e não para 22 ºC, supondo que esteja em 21 ºC).<sup>[[1]](#references)</sup>

---

## Attacks e pesquisa ofensiva <a href="#attacks" id="attacks"></a>

Você pode atacar o infravermelho com o Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Tomada de controle de Smart-TV / Set-top Box (EvilScreen)

Trabalhos acadêmicos recentes (EvilScreen, 2022) demonstraram que **controles remotos multicanal que combinam infravermelho com Bluetooth ou Wi-Fi podem ser usados para sequestrar completamente Smart-TVs modernas**. O ataque encadeia códigos de serviço IR com privilégios elevados a pacotes Bluetooth autenticados, contornando o isolamento entre canais e permitindo o lançamento arbitrário de aplicativos, a ativação do microfone ou a restauração das configurações de fábrica sem acesso físico. Oito TVs populares de diferentes fabricantes — incluindo um modelo Samsung que afirmava estar em conformidade com a ISO/IEC 27001 — foram confirmadas como vulneráveis. A mitigação exige correções de firmware dos fabricantes ou a desativação completa dos receptores IR não utilizados.<sup>[[2]](#references)</sup>

### Exfiltração de dados de redes isoladas via LEDs IR (família aIR-Jumper)

As câmeras de segurança normalmente incluem **LEDs IR para visão noturna**. O protótipo aIR-Jumper demonstrou que malware controlando esses LEDs poderia **exfiltrar secrets através de janelas** para uma câmera externa a até **20 bit/s por câmera de vigilância**, ao longo de dezenas de metros. Na direção inversa, os pesquisadores demonstraram infiltração a mais de **100 bit/s**, em distâncias de centenas de metros a quilômetros.<sup>[[3]](#references)</sup> Como a luz está fora do espectro visível, os operadores podem não percebê-la. As contramedidas incluem:

* Blindar fisicamente ou remover os LEDs IR em áreas sensíveis
* Monitorar o duty cycle dos LEDs da câmera e a integridade do firmware
* Implantar filtros IR-cut em janelas e câmeras de vigilância

Um atacante também pode usar projetores IR potentes para **infiltrar** comandos na rede, transmitindo dados de volta para câmeras inseguras.

### Brute-force de longo alcance e protocolos estendidos com Flipper Zero 1.0

O firmware 1.0 (setembro de 2024) expandiu a biblioteca de universal-remotes e adicionou o carregamento dinâmico de arquivos de recursos infravermelhos a partir de microSD.<sup>[[4]](#references)</sup> As funções de aprendizado e de controle remoto universal podem reproduzir ou tentar comandos conhecidos contra TVs e ar-condicionados próximos. O alcance depende muito do emissor, da óptica, da luz ambiente e do receptor; hardware IR externo pode ampliá-lo, mas não se deve presumir uma distância fixa.

---

## Ferramentas e exemplos práticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil com modos de aprendizado, replay e dictionary-bruteforce (veja acima).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analisador/transmissor DIY barato. Combine com a biblioteca `Arduino-IRremote` (a v4.x oferece suporte a mais de 40 protocolos).
* **Analisadores lógicos** (Saleae/FX2) – capturam temporizações brutas quando o protocolo é desconhecido.
* **Smartphones com IR-blaster** (por exemplo, Xiaomi) – teste rápido em campo, mas com alcance limitado.

### Software

* **`Arduino-IRremote`** – biblioteca C++ mantida ativamente:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decodificadores com GUI que importam capturas brutas, identificam automaticamente o protocolo e geram código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – recebem e injetam IR pela linha de comando:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Medidas defensivas <a href="#defense" id="defense"></a>

* Desative ou cubra os receptores IR em dispositivos instalados em espaços públicos quando não forem necessários.
* Exija *pairing* ou verificações criptográficas entre Smart-TVs e controles remotos; isole os códigos de “serviço” privilegiados.
* Instale filtros IR-cut ou detectores de onda contínua ao redor de áreas classificadas para interromper covert channels ópticos.
* Monitore a integridade do firmware de câmeras/dispositivos IoT que exponham LEDs IR controláveis.

## References

- [1] [Postagem de blog sobre o Infrared do Flipper Zero](https://blog.flipperzero.one/infrared/)
- [2] [Ataque EvilScreen: sequestro de Smart TV via imitação de controle remoto multicanal (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: exfiltração/infiltração covert em redes isoladas via câmeras de segurança e infravermelho (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog do Flipper Zero - Firmware 1.0 lançado](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentação de uso e protocolos](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
