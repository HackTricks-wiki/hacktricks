# Infravermelho

{{#include ../../banners/hacktricks-training.md}}

## Como o Infravermelho Funciona <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR varia de **0,7 a 1000 micrômetros**. Os controles remotos domésticos usam um sinal IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75 a 1,4 micrômetros. Um microcontrolador no controle remoto faz um LED infravermelho piscar com uma frequência específica, convertendo o sinal digital em um sinal IR.

Para receber sinais IR, um **fotoreceptor** é utilizado. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Normalmente, há um **filtro de luz escura dentro do receptor**, que permite **apenas a passagem do comprimento de onda desejado** e elimina o ruído.

### Variedade de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Os protocolos IR diferem em 3 fatores:

- codificação de bits
- estrutura de dados
- frequência portadora — frequentemente na faixa de 36 a 38 kHz

#### Formas de codificação de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificação por Distância de Pulso**

Os bits são codificados modulando a duração do espaço entre os pulsos. A largura do pulso em si é constante.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Codificação por Largura de Pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após o pulso é constante.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de Fase**

Também é conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre o pulso e o espaço. "Espaço para pulso" denota lógica "0", "pulso para espaço" denota lógica "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outras exóticas**

> [!TIP]
> Existem protocolos IR que estão **tentando se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, o mais famoso **não significa o mais comum**. No meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.
>
> Os fabricantes adoram usar seus próprios protocolos IR únicos, mesmo dentro da mesma gama de dispositivos (por exemplo, caixas de TV). Portanto, controles remotos de diferentes empresas e, às vezes, de diferentes modelos da mesma empresa, não conseguem funcionar com outros dispositivos do mesmo tipo.

### Explorando um sinal IR

A maneira mais confiável de ver como o sinal IR do controle remoto se parece é usar um osciloscópio. Ele não demodula ou inverte o sinal recebido, ele é apenas exibido "como está". Isso é útil para testes e depuração. Vou mostrar o sinal esperado com o exemplo do protocolo IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Normalmente, há um preâmbulo no início de um pacote codificado. Isso permite que o receptor determine o nível de ganho e o fundo. Existem também protocolos sem preâmbulo, por exemplo, Sharp.

Em seguida, os dados são transmitidos. A estrutura, o preâmbulo e o método de codificação de bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, que é enviado enquanto o botão é pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando NEC**, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, pelos quais o dispositivo entende o que precisa ser realizado. Os bytes de endereço e número de comando são duplicados com valores inversos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para **lógica "0" e "1"**, o NEC usa Codificação por Distância de Pulso: primeiro, um pulso é transmitido após o qual há uma pausa, cujo comprimento define o valor do bit.

### Ar Condicionado

Diferente de outros controles remotos, **os ar condicionados não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado para garantir que a **máquina de ar condicionado e o controle remoto estejam sincronizados**.\
Isso evitará que uma máquina configurada para 20ºC seja aumentada para 21ºC com um controle remoto, e então, quando outro controle remoto, que ainda tem a temperatura como 20ºC, for usado para aumentar mais a temperatura, ela "aumentará" para 21ºC (e não para 22ºC pensando que está em 21ºC).

---

## Ataques & Pesquisa Ofensiva <a href="#attacks" id="attacks"></a>

Você pode atacar o Infravermelho com Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Tomada de Controle de Smart-TV / Set-top Box (EvilScreen)

Trabalhos acadêmicos recentes (EvilScreen, 2022) demonstraram que **controles remotos multicanal que combinam Infravermelho com Bluetooth ou Wi-Fi podem ser abusados para sequestrar completamente TVs inteligentes modernas**. O ataque encadeia códigos de serviço IR de alta privilégio com pacotes Bluetooth autenticados, contornando a isolação de canais e permitindo lançamentos arbitrários de aplicativos, ativação de microfone ou reset de fábrica sem acesso físico. Oito TVs populares de diferentes fornecedores — incluindo um modelo Samsung que afirma conformidade com ISO/IEC 27001 — foram confirmadas como vulneráveis. A mitigação requer correções de firmware do fornecedor ou desativação completa de receptores IR não utilizados.

### Exfiltração de Dados Air-Gapped via LEDs IR (família aIR-Jumper)

Câmeras de segurança, roteadores ou até mesmo pen drives maliciosos frequentemente incluem **LEDs IR de visão noturna**. Pesquisas mostram que malware pode modular esses LEDs (<10–20 kbit/s com OOK simples) para **exfiltrar segredos através de paredes e janelas** para uma câmera externa colocada a dezenas de metros de distância. Como a luz está fora do espectro visível, os operadores raramente notam. Medidas de contra-ataque:

* Proteger fisicamente ou remover LEDs IR em áreas sensíveis
* Monitorar o ciclo de trabalho do LED da câmera e a integridade do firmware
* Implantar filtros de corte IR em janelas e câmeras de vigilância

Um atacante também pode usar projetores IR fortes para **infiltrar** comandos na rede piscando dados de volta para câmeras inseguras.

### Força Bruta de Longo Alcance & Protocolos Estendidos com Flipper Zero 1.0

O firmware 1.0 (setembro de 2024) adicionou **dezenas de protocolos IR extras e módulos amplificadores externos opcionais**. Combinado com o modo de força bruta de controle remoto universal, um Flipper pode desativar ou reconfigurar a maioria das TVs/ACs públicas a até 30 m usando um diodo de alta potência.

---

## Ferramentas & Exemplos Práticos <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – transceptor portátil com modos de aprendizado, reprodução e força bruta de dicionário (veja acima).
* **Arduino / ESP32** + LED IR / receptor TSOP38xx – analisador/transmissor DIY barato. Combine com a biblioteca `Arduino-IRremote` (v4.x suporta >40 protocolos).
* **Analisadores lógicos** (Saleae/FX2) – capturar temporizações brutas quando o protocolo é desconhecido.
* **Smartphones com IR-blaster** (por exemplo, Xiaomi) – teste rápido em campo, mas com alcance limitado.

### Software

* **`Arduino-IRremote`** – biblioteca C++ ativamente mantida:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – decodificadores GUI que importam capturas brutas e auto-identificam o protocolo + geram código Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – receber e injetar IR a partir da linha de comando:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Medidas Defensivas <a href="#defense" id="defense"></a>

* Desativar ou cobrir receptores IR em dispositivos implantados em espaços públicos quando não forem necessários.
* Impor *pareamento* ou verificações criptográficas entre smart-TVs e controles remotos; isolar códigos de “serviço” privilegiados.
* Implantar filtros de corte IR ou detectores de onda contínua em áreas classificadas para quebrar canais ópticos encobertos.
* Monitorar a integridade do firmware de câmeras/aparelhos IoT que expõem LEDs IR controláveis.

## Referências

- [Postagem no blog do Flipper Zero sobre Infravermelho](https://blog.flipperzero.one/infrared/)
- EvilScreen: Sequestro de Smart TV via imitação de controle remoto (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
