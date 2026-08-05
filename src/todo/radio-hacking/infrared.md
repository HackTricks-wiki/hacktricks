# Infravermelho

{{#include ../../banners/hacktricks-training.md}}

## Como funciona o Infravermelho <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível aos seres humanos**. O comprimento de onda do IR varia de **0,7 a 1000 microns**. Os controles remotos domésticos usam um sinal IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75..1,4 microns. Um microcontrolador no controle remoto faz um LED infravermelho piscar com uma frequência específica, convertendo o sinal digital em um sinal IR.<sup>[[1]](#references)</sup>

Para receber sinais IR, usa-se um **fotoreceptor**. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Normalmente, há um **filtro de luz escura dentro do receptor**, que permite a passagem **apenas do comprimento de onda desejado** e elimina o ruído.

### Variedade de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:

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

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre o burst do pulso e o espaço. "Espaço para burst do pulso" representa a lógica "0", enquanto "burst do pulso para espaço" representa a lógica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outros métodos exóticos**

> [!TIP]
> Existem protocolos IR que **tentam se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, ser o mais famoso **não significa ser o mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.
>
> Os fabricantes adoram usar seus próprios protocolos IR exclusivos, até mesmo dentro da mesma categoria de dispositivos (por exemplo, TV boxes). Portanto, controles remotos de empresas diferentes e, às vezes, de modelos diferentes da mesma empresa, não conseguem funcionar com outros dispositivos do mesmo tipo.

### Explorando um sinal IR

A maneira mais confiável de ver como é o sinal IR de um controle remoto é usar um osciloscópio. Ele não demodula nem inverte o sinal recebido; apenas o exibe "como está". Isso é útil para testes e debugging. Mostrarei o sinal esperado usando o protocolo IR NEC como exemplo.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o background. Também existem protocolos sem preâmbulo, como o Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação dos bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, enviado enquanto o botão está pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando** NEC, além do preâmbulo, consiste em um byte de endereço e um byte de número do comando, pelos quais o dispositivo entende o que precisa ser executado. Os bytes de endereço e de número do comando são duplicados com valores invertidos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** possui um "1" após o preâmbulo, que corresponde a um bit de parada.

Para a **lógica "0" e "1"**, o NEC usa Pulse Distance Encoding: primeiro, um burst de pulso é transmitido, seguido por uma pausa cuja duração define o valor do bit.

### Ar-condicionados

Ao contrário de outros controles remotos, os **ar-condicionados não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado, para garantir que o **ar-condicionado e o controle remoto estejam sincronizados**.\
Isso evita que um aparelho configurado para 20ºC seja ajustado para 21ºC com um controle remoto e, depois, quando outro controle remoto, que ainda indica 20ºC, for usado para aumentar mais a temperatura, ela seja "aumentada" para 21ºC (e não para 22ºC, supondo que esteja em 21ºC).

---

## Ataques e Pesquisa Ofensiva <a href="#attacks" id="attacks"></a>

Você pode atacar Infrared com o Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Tomada de controle de Smart-TV / Set-top Box (EvilScreen)

Trabalhos acadêmicos recentes (EvilScreen, 2022) demonstraram que **controles remotos multicanal que combinam Infrared com Bluetooth ou Wi-Fi podem ser abusados para sequestrar completamente Smart-TVs modernas**. O ataque encadeia códigos de serviço IR com altos privilégios a pacotes Bluetooth autenticados, contornando o isolamento entre canais e permitindo o lançamento arbitrário de aplicativos, a ativação do microfone ou a restauração das configurações de fábrica sem acesso físico. Oito TVs populares de diferentes fornecedores — incluindo um modelo Samsung que alegava conformidade com a ISO/IEC 27001 — foram confirmadas como vulneráveis. A mitigação exige correções de firmware dos fornecedores ou a desativação completa dos receptores IR não utilizados.<sup>[[2]](#references)</sup>

### Exfiltração de dados de redes isoladas via LEDs IR (família aIR-Jumper)

Câmeras de segurança, roteadores e até dispositivos USB maliciosos geralmente incluem **LEDs IR de visão noturna**. Pesquisas mostram que malware pode modular esses LEDs (<10–20 kbit/s com OOK simples) para **exfiltrar secrets através de paredes e janelas** para uma câmera externa posicionada a dezenas de metros. Como a luz está fora do espectro visível, os operadores raramente percebem. Contramedidas:

* Proteger fisicamente ou remover LEDs IR em áreas sensíveis
* Monitorar o duty cycle dos LEDs da câmera e a integridade do firmware
* Implantar filtros IR-cut em janelas e câmeras de vigilância

Um atacante também pode usar projetores IR potentes para **infiltrar** comandos na rede, transmitindo dados para câmeras inseguras por meio de flashes.

### Brute-Force de Longo Alcance e Protocolos Estendidos com Flipper Zero 1.0

O firmware 1.0 (setembro de 2024) adicionou **dezenas de protocolos IR extras e módulos amplificadores externos opcionais**. Combinado ao modo de brute-force de controle remoto universal, um Flipper pode desativar ou reconfigurar a maioria das TVs/ACs públicas a até 30 m usando um diodo de alta potência.

---

## Ferramentas e Exemplos Práticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil com modos de aprendizado, replay e dictionary-bruteforce (veja acima).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analisador/transmissor DIY barato. Combine com a biblioteca `Arduino-IRremote` (v4.x suporta mais de 40 protocolos).
* **Analisadores lógicos** (Saleae/FX2) – capturam temporizações brutas quando o protocolo é desconhecido.
* **Smartphones com IR-blaster** (por exemplo, Xiaomi) – teste rápido em campo, mas com alcance limitado.

### Software

* **`Arduino-IRremote`** – biblioteca C++ mantida ativamente:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decoders GUI que importam capturas brutas, identificam automaticamente o protocolo e geram código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – recebem e injetam IR pela linha de comando:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Medidas Defensivas <a href="#defense" id="defense"></a>

* Desative ou cubra os receptores IR de dispositivos instalados em espaços públicos quando não forem necessários.
* Imponha *pairing* ou verificações criptográficas entre Smart-TVs e controles remotos; isole os códigos de “serviço” privilegiados.
* Implante filtros IR-cut ou detectores de onda contínua ao redor de áreas classificadas para interromper canais ópticos ocultos.
* Monitore a integridade do firmware de câmeras/dispositivos IoT que exponham LEDs IR controláveis.

## Referências

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
