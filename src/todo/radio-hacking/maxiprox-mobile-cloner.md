# Construindo um Clonador Móvel HID MaxiProx 125 kHz Portátil

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Transformar um leitor HID MaxiProx 5375 de longo alcance 125 kHz alimentado pela rede em um clonador de crachás portátil, alimentado por bateria, que silenciosamente coleta cartões de proximidade durante avaliações de segurança física.

A conversão abordada aqui é baseada na série de pesquisa “Let’s Clone a Cloner – Part 3: Putting It All Together” da TrustedSec e combina considerações mecânicas, elétricas e de RF para que o dispositivo final possa ser colocado em uma mochila e usado imediatamente no local.

> [!warning]
> Manipular equipamentos alimentados pela rede e bancos de potência de íon de lítio pode ser perigoso. Verifique cada conexão **antes** de energizar o circuito e mantenha as antenas, coaxiais e planos de terra exatamente como estavam no design de fábrica para evitar desajuste do leitor.

## Lista de Materiais (BOM)

* Leitor HID MaxiProx 5375 (ou qualquer leitor HID Prox® de longo alcance de 12 V)
* Ferramenta ESP RFID v2.2 (sniffer/logger Wiegand baseado em ESP32)
* Módulo de gatilho USB-PD (Power-Delivery) capaz de negociar 12 V @ ≥3 A
* Banco de potência USB-C de 100 W (saídas 12 V PD profile)
* Fio de conexão de silicone 26 AWG – vermelho/branco
* Interruptor SPST de montagem em painel (para o interruptor de desligamento do beeper)
* Capô de segurança / protetor de acidente NKK AT4072
* Ferro de solda, trançado de solda e bomba de dessoldagem
* Ferramentas manuais classificadas em ABS: serra de vaivém, faca utilitária, limas planas e meia-redonda
* Brocas de 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Fita dupla face 3 M VHB & abraçadeiras

## 1. Sub-sistema de Energia

1. Dessolde e remova a placa filha do conversor buck de fábrica usada para gerar 5 V para a PCB lógica.
2. Monte um gatilho USB-PD ao lado da Ferramenta ESP RFID e direcione o receptáculo USB-C do gatilho para o exterior do invólucro.
3. O gatilho PD negocia 12 V do banco de potência e alimenta diretamente o MaxiProx (o leitor espera nativamente 10–14 V). Um barramento secundário de 5 V é retirado da placa ESP para alimentar quaisquer acessórios.
4. O pacote de bateria de 100 W é posicionado em contato com o suporte interno para que **não** haja cabos de energia pendurados na antena de ferrite, preservando o desempenho de RF.

## 2. Interruptor de Desligamento do Beeper – Operação Silenciosa

1. Localize os dois pads do alto-falante na placa lógica do MaxiProx.
2. Limpe *ambos* os pads, depois ressolde apenas o pad **negativo**.
3. Solde fios 26 AWG (branco = negativo, vermelho = positivo) nos pads do beeper e direcione-os através de um slot recém-cortado para um interruptor SPST de montagem em painel.
4. Quando o interruptor está aberto, o circuito do beeper é interrompido e o leitor opera em completo silêncio – ideal para coleta discreta de crachás.
5. Coloque um capô de segurança NKK AT4072 com mola sobre o interruptor. Aumente cuidadosamente o diâmetro com uma serra de vaivém / lima até que se encaixe sobre o corpo do interruptor. O protetor evita ativação acidental dentro de uma mochila.

## 3. Invólucro & Trabalho Mecânico

• Use cortadores de flush e depois uma faca & lima para *remover* o “bump-out” interno de ABS para que a grande bateria USB-C fique plana sobre o suporte.
• Esculpa dois canais paralelos na parede do invólucro para o cabo USB-C; isso fixa a bateria no lugar e elimina movimento/vibração.
• Crie uma abertura retangular para o botão de **energia** da bateria:
1. Cole um estêncil de papel sobre a localização.
2. Fure buracos piloto de 1/16″ em todos os quatro cantos.
3. Aumente com uma broca de 1/8″.
4. Una os buracos com uma serra de vaivém; finalize as bordas com uma lima.
✱ Um Dremel rotativo foi *evitado* – a broca de alta velocidade derrete ABS grosso e deixa uma borda feia.

## 4. Montagem Final

1. Reinstale a placa lógica do MaxiProx e ressolde o pigtail SMA ao pad de terra da PCB do leitor.
2. Monte a Ferramenta ESP RFID e o gatilho USB-PD usando 3 M VHB.
3. Organize toda a fiação com abraçadeiras, mantendo os fios de energia **longe** do laço da antena.
4. Aperte os parafusos do invólucro até que a bateria esteja levemente comprimida; a fricção interna evita que o pacote se mova quando o dispositivo recua após cada leitura de cartão.

## 5. Testes de Alcance & Blindagem

* Usando um cartão de teste **Pupa** de 125 kHz, o clonador portátil obteve leituras consistentes a **≈ 8 cm** no ar livre – idêntico à operação alimentada pela rede.
* Colocar o leitor dentro de uma caixa de dinheiro de metal de parede fina (para simular uma mesa de lobby de banco) reduziu o alcance para ≤ 2 cm, confirmando que invólucros metálicos substanciais atuam como escudos de RF eficazes.

## Fluxo de Uso

1. Carregue a bateria USB-C, conecte-a e acione o interruptor principal de energia.
2. (Opcional) Abra a proteção do beeper e ative o feedback audível ao testar em bancada; feche antes do uso discreto em campo.
3. Passe pelo portador do crachá alvo – o MaxiProx energizará o cartão e a Ferramenta ESP RFID capturará o fluxo Wiegand.
4. Descarregue as credenciais capturadas via Wi-Fi ou USB-UART e reproduza/clonifique conforme necessário.

## Solução de Problemas

| Sintoma | Causa Provável | Solução |
|---------|----------------|---------|
| O leitor reinicia quando o cartão é apresentado | O gatilho PD negociou 9 V em vez de 12 V | Verifique os jumpers do gatilho / tente um cabo USB-C de maior potência |
| Sem alcance de leitura | Bateria ou fiação em cima da antena | Redirecione os cabos & mantenha 2 cm de folga ao redor do laço de ferrite |
| O beeper ainda apita | Interruptor ligado no fio positivo em vez do negativo | Mova o interruptor de desligamento para quebrar o traço do alto-falante **negativo** |

## Referências

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
