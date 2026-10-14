# Infravermelho

{{#include ../../banners/hacktricks-training.md}}

## Como funciona o infravermelho <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR vai de **0.7 a 1000 microns**. Os controles remotos domésticos usam um sinal IR para transmitir dados e operam na faixa de comprimento de onda de 0.75..1.4 microns. Um microcontrolador no controle remoto faz um LED infravermelho piscar em uma frequência específica, transformando o sinal digital em um sinal IR.

Para receber sinais IR, usa-se um **fotoreceptor**. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Normalmente, há um **filtro de luz escura dentro do receptor**, que deixa passar **apenas o comprimento de onda desejado** e elimina o ruído.<sup>[[1]](#references)</sup>

### Variedade de protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:<sup>[[1]](#references)</sup>

- codificação de bits
- estrutura dos dados
- frequência da portadora — geralmente na faixa de 36..38 kHz

#### Métodos de codificação de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificação por distância entre pulsos**

Os bits são codificados modulando a duração do espaço entre os pulsos. A largura do próprio pulso é constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codificação por largura de pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após a sequência de pulsos é constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de fase**

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre a sequência de pulsos e o espaço. "Espaço para sequência de pulsos" representa a lógica "0"; "sequência de pulsos para espaço" representa a lógica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos métodos anteriores e de outros métodos exóticos**

> [!TIP]
> Existem protocolos IR que **tentam se tornar universais** para vários tipos de dispositivos. Os mais conhecidos são RC5 e NEC. Infelizmente, ser o mais conhecido **não significa ser o mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.
>
> Os fabricantes adoram usar seus próprios protocolos IR exclusivos, até mesmo na mesma categoria de dispositivos (por exemplo, TV boxes). Portanto, controles remotos de empresas diferentes e, às vezes, de modelos diferentes da mesma empresa não conseguem funcionar com outros dispositivos do mesmo tipo.

### Analisando um sinal IR

A maneira mais confiável de ver como é o sinal IR do controle remoto é usar um osciloscópio. Ele não demodula nem inverte o sinal recebido; apenas o exibe "como está". Isso é útil para testes e depuração. Vou mostrar o sinal esperado usando como exemplo o protocolo IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o ruído de fundo. Também existem protocolos sem preâmbulo, como o Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são definidos pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, enviado enquanto o botão está pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando** NEC, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, que informa ao dispositivo o que deve ser executado. Os bytes de endereço e de número de comando são duplicados com valores invertidos para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para a **lógica "0" e "1"**, o NEC usa codificação por distância entre pulsos: primeiro, é transmitida uma sequência de pulsos, seguida por uma pausa cuja duração define o valor do bit.

### Ar-condicionados

Ao contrário de outros controles remotos, **os controles de ar-condicionado não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado, para garantir que o **aparelho de ar-condicionado e o controle remoto estejam sincronizados**.\
Isso evita que um aparelho configurado para 20ºC seja ajustado para 21ºC com um controle remoto e, depois, quando outro controle remoto, que ainda está configurado para 20ºC, for usado para aumentar a temperatura, ela seja "aumentada" para 21ºC (em vez de 22ºC, supondo que esteja em 21ºC).<sup>[[1]](#references)</sup>

---

## Ataques e pesquisa ofensiva <a href="#attacks" id="attacks"></a>

É possível atacar o infravermelho com o Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Sequestro de Smart-TV / Set-top Box (EvilScreen)

Pesquisas acadêmicas recentes (EvilScreen, 2022) demonstraram que **controles remotos multicanal que combinam infravermelho com Bluetooth ou Wi-Fi podem ser explorados para sequestrar totalmente smart TVs modernas**. O ataque encadeia códigos de serviço IR de alto privilégio com pacotes Bluetooth autenticados, contornando o isolamento entre canais e permitindo iniciar aplicativos arbitrários, ativar o microfone ou restaurar as configurações de fábrica sem acesso físico. Oito TVs convencionais de diferentes fabricantes — incluindo um modelo da Samsung que alegava conformidade com a ISO/IEC 27001 — foram confirmadas como vulneráveis. A mitigação exige correções de firmware dos fabricantes ou a desativação completa dos receptores IR não utilizados.<sup>[[2]](#references)</sup>

### Exfiltração de dados por air gap usando LEDs IR (família aIR-Jumper)

Câmeras de segurança geralmente incluem **LEDs IR para visão noturna**. O protótipo aIR-Jumper demonstrou que um malware que controlasse esses LEDs poderia **exfiltrar segredos através de janelas** para uma câmera externa, a até **20 bit/s por câmera de vigilância**, ao longo de dezenas de metros. Na direção inversa, os pesquisadores demonstraram infiltração a mais de **100 bit/s**, em distâncias que vão de centenas de metros a quilômetros.<sup>[[3]](#references)</sup> Como a luz está fora do espectro visível, os operadores podem não percebê-la. As contramedidas incluem:

* Blindar ou remover fisicamente os LEDs IR em áreas sensíveis
* Monitorar o ciclo de trabalho dos LEDs das câmeras e a integridade do firmware
* Instalar filtros de corte de IR em janelas e câmeras de vigilância

Um atacante também pode usar projetores IR potentes para **infiltrar** comandos na rede, transmitindo dados de volta para câmeras inseguras.

### Força bruta a longa distância e protocolos estendidos com Flipper Zero 1.0

O firmware 1.0 (setembro de 2024) expandiu a biblioteca de controles remotos universais e adicionou o carregamento dinâmico de arquivos de recursos infravermelhos a partir de um microSD.<sup>[[4]](#references)</sup> As funções de aprendizado e controle remoto universal podem reproduzir ou testar comandos conhecidos em TVs e aparelhos de ar-condicionado próximos. O alcance depende muito do emissor, da óptica, da luz ambiente e do receptor; o hardware IR externo pode ampliá-lo, mas não se deve presumir uma distância fixa.

---

## Ferramentas e exemplos práticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil com modos de aprendizado, reprodução e força bruta com dicionário (veja acima).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analisador/transmissor DIY de baixo custo. Combine com a biblioteca `Arduino-IRremote` (a v4.x oferece suporte a mais de 40 protocolos).
* **Analisadores lógicos** (Saleae/FX2) – capturam temporizações brutas quando o protocolo é desconhecido.
* **Smartphones com emissor IR** (por exemplo, Xiaomi) – úteis para testes rápidos em campo, mas com alcance limitado.

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
* **LIRC / ir-keytable (Linux)** – receber e injetar sinais IR pela linha de comando:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Medidas defensivas <a href="#defense" id="defense"></a>

* Desative ou cubra os receptores IR em dispositivos instalados em espaços públicos quando não forem necessários.
* Exija *emparelhamento* ou verificações criptográficas entre smart TVs e controles remotos; isole os códigos privilegiados de “serviço”.
* Instale filtros IR-cut ou detectores de onda contínua em torno de áreas classificadas para interromper canais ópticos encobertos.
* Monitore a integridade do firmware de câmeras/dispositivos IoT com LEDs IR controláveis.

## References

- [1] [Publicação do blog do Flipper Zero sobre infravermelho](https://blog.flipperzero.one/infrared/)
- [2] [Ataque EvilScreen: sequestro de smart TVs por imitação de controle remoto multicanal (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: exfiltração/infiltração encoberta em air-gap por meio de câmeras de segurança e infravermelho (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog do Flipper Zero - Firmware 1.0 lançado](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - documentação de uso e protocolo](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
