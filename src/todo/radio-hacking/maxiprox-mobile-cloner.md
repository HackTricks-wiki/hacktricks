# Construindo um clonador móvel HID MaxiProx 125 kHz portátil

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Transformar um leitor HID MaxiProx 5375 de longo alcance, alimentado pela rede elétrica, em um clonador de crachás portátil e alimentado por bateria, capaz de coletar silenciosamente cartões de proximidade durante avaliações de segurança física.

A conversão apresentada aqui baseia-se na série de pesquisas “Let’s Clone a Cloner – Part 3: Putting It All Together”, da TrustedSec, e combina considerações mecânicas, elétricas e de RF para que o dispositivo final possa ser transportado em uma mochila e usado imediatamente no local.<sup>[[1]](#references)</sup>

> [!warning]
> Manipular equipamentos alimentados pela rede elétrica e power-banks de íons de lítio pode ser perigoso. Verifique todas as conexões **antes** de energizar o circuito e mantenha as antenas, o coaxial e os planos de aterramento exatamente como estavam no projeto de fábrica para evitar a desafinação do leitor.

## Lista de materiais (BOM)

* Leitor HID MaxiProx 5375 (ou qualquer leitor de longo alcance HID Prox® de 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand baseado em ESP32)
* Módulo trigger USB-PD (Power-Delivery) capaz de negociar 12 V a ≥3 A
* Power-bank USB-C de 100 W (fornece perfil PD de 12 V)
* Fio de conexão de silicone de 26 AWG – vermelho/branco
* Interruptor tipo toggle SPST para montagem em painel (para o kill-switch do beeper)
* Proteção de interruptor / tampa à prova de acidentes NKK AT4072
* Ferro de solda, malha dessoldadora e sugador de solda
* Ferramentas manuais compatíveis com ABS: serra de ponta, estilete, limas plana e meia-cana
* Brocas de 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Fita dupla face 3 M VHB e abraçadeiras

## 1. Subsistema de alimentação

1. Dessolde e remova a daughter-board do conversor buck de fábrica usada para gerar 5 V para a PCB de lógica.
2. Monte um trigger USB-PD ao lado do ESP RFID Tool e direcione o receptáculo USB-C do trigger para a parte externa do gabinete.
3. O trigger PD negocia 12 V com o power-bank e os fornece diretamente ao MaxiProx (o leitor espera nativamente de 10 a 14 V). Um trilho secundário de 5 V é obtido da placa ESP para alimentar quaisquer acessórios.
4. A bateria de 100 W é posicionada rente ao suporte interno, de modo que **não haja** cabos de alimentação atravessados sobre a antena de ferrite, preservando o desempenho de RF.

## 2. Beeper Kill-Switch – Operação silenciosa

1. Localize os dois pads do alto-falante na placa de lógica do MaxiProx.
2. Remova completamente a solda de *ambos* os pads e, em seguida, solde novamente apenas o pad **negativo**.
3. Solde fios de 26 AWG (branco = negativo, vermelho = positivo) aos pads do beeper e passe-os por uma abertura recém-cortada até um interruptor SPST de montagem em painel.
4. Quando o interruptor está aberto, o circuito do beeper é interrompido e o leitor opera em completo silêncio – ideal para a coleta discreta de crachás.
5. Instale uma tampa de segurança com mola NKK AT4072 sobre o toggle. Aumente cuidadosamente o diâmetro do orifício com uma serra de ponta / lima até que ela se encaixe no corpo do interruptor. A proteção evita a ativação acidental dentro da mochila.

## 3. Gabinete e trabalho mecânico

• Use um alicate de corte rente, depois um estilete e uma lima, para *remover* a “saliência” interna de ABS, permitindo que a bateria USB-C grande fique plana sobre o suporte.
• Escave dois canais paralelos na parede do gabinete para o cabo USB-C; isso trava a bateria no lugar e elimina movimentos/vibrações.
• Crie uma abertura retangular para o botão de **alimentação** da bateria:
1. Prenda um molde de papel sobre o local.
2. Faça furos-piloto de 1/16″ nos quatro cantos.
3. Aumente-os com uma broca de 1/8″.
4. Una os furos com uma serra de ponta; finalize as bordas com uma lima.
✱  Um Dremel rotativo foi *evitado* – a broca de alta velocidade derrete o ABS espesso e deixa uma borda irregular.

## 4. Montagem final

1. Reinstale a placa de lógica do MaxiProx e solde novamente o pigtail SMA ao pad de aterramento da PCB do leitor.
2. Fixe o ESP RFID Tool e o trigger USB-PD usando fita 3 M VHB.
3. Organize toda a fiação com abraçadeiras, mantendo os cabos de alimentação **bem afastados** do loop da antena.
4. Aperte os parafusos do gabinete até que a bateria fique levemente comprimida; a fricção interna impede que o pack se desloque quando o dispositivo recua após cada leitura de cartão.

## 5. Testes de alcance e blindagem

* Usando um cartão de teste **Pupa** de 125 kHz, o clonador portátil obteve leituras consistentes a **≈ 8 cm** ao ar livre – idênticas às da operação alimentada pela rede elétrica.<sup>[[1]](#references)</sup>
* Colocar o leitor dentro de uma caixa metálica de paredes finas (para simular um balcão de banco) reduziu o alcance para ≤ 2 cm, confirmando que gabinetes metálicos substanciais funcionam como blindagens eficazes contra RF.<sup>[[1]](#references)</sup>

## Fluxo de uso

1. Carregue a bateria USB-C, conecte-a e acione o interruptor principal.
2. (Opcional) Abra a proteção do beeper e habilite o feedback sonoro durante os testes de bancada; feche-a antes do uso discreto em campo.
3. Passe próximo ao portador do crachá-alvo – o MaxiProx energizará o cartão e o ESP RFID Tool capturará o fluxo Wiegand.
4. Extraia as credenciais capturadas por Wi-Fi ou USB-UART e faça o replay/clone conforme necessário.

## Solução de problemas

| Sintoma | Causa provável | Correção |
|---------|----------------|----------|
| O leitor reinicia quando o cartão é apresentado | O trigger PD negociou 9 V em vez de 12 V | Verifique os jumpers do trigger / tente um cabo USB-C de maior potência |
| Nenhum alcance de leitura | A bateria ou a fiação está *sobre* a antena | Redirecione os cabos e mantenha 2 cm de distância ao redor do loop de ferrite |
| O beeper ainda emite bipes | O interruptor foi conectado ao cabo positivo em vez do negativo | Mova o kill-switch para interromper o traço do alto-falante **negativo** |

## Referências

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
