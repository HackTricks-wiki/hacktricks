# Construindo um clonador móvel portátil HID MaxiProx de 125 kHz

{{#include ../../banners/hacktricks-training.md}}

## Objetivo
Transformar um leitor de longo alcance HID MaxiProx 5375, alimentado pela rede elétrica e operando a 125 kHz, em um clonador de crachás portátil, alimentado por bateria, que coleta silenciosamente cartões de proximidade durante avaliações de segurança física.

A conversão descrita aqui se baseia na série de pesquisas da TrustedSec “Let’s Clone a Cloner – Part 3: Putting It All Together” e combina aspectos mecânicos, elétricos e de RF para que o dispositivo final possa ser levado em uma mochila e usado imediatamente no local.<sup>[[1]](#references)</sup>

> [!warning]
> Manipular equipamentos alimentados pela rede elétrica e baterias externas de íon-lítio pode ser perigoso. Verifique todas as conexões **antes** de energizar o circuito e mantenha as antenas, o cabo coaxial e os planos de terra exatamente como no projeto de fábrica para evitar desafinar o leitor.

## Lista de materiais (BOM)

* Leitor HID MaxiProx 5375 (ou qualquer leitor de longo alcance HID Prox® de 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand baseado em ESP32)
* Módulo de trigger USB-PD (Power-Delivery) capaz de negociar 12 V a ≥3 A
* Bateria externa USB-C de 100 W (com perfil de saída PD de 12 V)
* Fio de ligação de 26 AWG com isolamento de silicone – vermelho/branco
* Interruptor SPST de painel (para o interruptor de corte do sinal sonoro)
* Capa de proteção NKK AT4072 para interruptor / tampa antiactivação acidental
* Ferro de solda, malha dessoldadora e sugador de solda
* Ferramentas manuais compatíveis com ABS: serra de ponta, estilete, limas planas e semicirculares
* Brocas de 1/16″ (1,5 mm) e 1/8″ (3 mm)
* Fita dupla face 3 M VHB e abraçadeiras

## 1. Subsistema de alimentação

1. Dessolde e remova a placa filha do conversor buck de fábrica, usada para gerar 5 V para a placa lógica.
2. Instale um trigger USB-PD ao lado do ESP RFID Tool e direcione o conector USB-C do trigger para a parte externa do invólucro.
3. O trigger PD negocia 12 V com a bateria externa e fornece essa tensão diretamente ao MaxiProx (o leitor foi projetado para operar com 10–14 V). Uma linha secundária de 5 V é obtida da placa ESP para alimentar quaisquer acessórios.
4. Posicione a bateria de 100 W rente ao espaçador interno, sem deixar **nenhum** cabo de alimentação atravessado sobre a antena de ferrite, preservando o desempenho de RF.

## 2. Interruptor de corte do sinal sonoro – operação silenciosa

1. Localize os dois pontos de solda do alto-falante na placa lógica do MaxiProx.
2. Remova a solda de *ambos* os pontos e, em seguida, solde novamente apenas o ponto **negativo**.
3. Solde fios de 26 AWG (branco = negativo, vermelho = positivo) aos pontos do sinal sonoro e passe-os por uma abertura recém-cortada até um interruptor SPST de painel.
4. Com o interruptor aberto, o circuito do sinal sonoro fica interrompido e o leitor opera em silêncio total – ideal para coletar crachás de forma encoberta.
5. Instale uma tampa de segurança com mola NKK AT4072 sobre o interruptor. Aumente cuidadosamente o furo com uma serra de ponta / lima até que a tampa encaixe sobre o corpo do interruptor. A proteção evita a ativação acidental dentro de uma mochila.

## 3. Invólucro e trabalho mecânico

• Use um alicate de corte rente e, em seguida, um estilete e uma lima para *remover* a “saliência” interna de ABS, permitindo que a grande bateria USB-C fique plana sobre o espaçador.
• Faça dois canais paralelos na parede do invólucro para o cabo USB-C; isso fixa a bateria no lugar e elimina movimentos/vibrações.
• Faça uma abertura retangular para o botão de **alimentação** da bateria:
  1. Cole um molde de papel sobre o local.
  2. Faça furos-guia de 1/16″ nos quatro cantos.
  3. Aumente os furos usando uma broca de 1/8″.
  4. Una os furos com uma serra de ponta; finalize as bordas com uma lima.  
  ✱  Uma ferramenta rotativa Dremel foi *evitada* – a broca de alta velocidade derrete o ABS espesso e deixa uma borda irregular.

## 4. Montagem final

1. Reinstale a placa lógica do MaxiProx e solde novamente o rabicho SMA ao ponto de terra da placa de circuito impresso do leitor.
2. Fixe o ESP RFID Tool e o trigger USB-PD com fita 3 M VHB.
3. Prenda toda a fiação com abraçadeiras, mantendo os cabos de alimentação **longe** da espira da antena.
4. Aperte os parafusos do invólucro até que a bateria fique levemente comprimida; o atrito interno impede que ela se desloque quando o dispositivo recua após cada leitura de cartão.

## 5. Testes de alcance e blindagem

* Usando um cartão de teste **Pupa** de 125 kHz, o clonador portátil realizou leituras consistentes a **≈ 8 cm** ao ar livre – igual ao funcionamento com alimentação da rede elétrica.<sup>[[1]](#references)</sup>
* Colocar o leitor dentro de uma caixa metálica de paredes finas (para simular uma mesa de recepção de banco) reduziu o alcance para ≤ 2 cm, confirmando que invólucros metálicos substanciais funcionam como blindagens de RF eficazes.<sup>[[1]](#references)</sup>

## Fluxo de uso

1. Carregue a bateria USB-C, conecte-a e acione o interruptor principal.
2. (Opcional) Abra a proteção do sinal sonoro e habilite o retorno audível durante testes em bancada; feche-a antes do uso encoberto em campo.
3. Passe perto da pessoa que porta o crachá-alvo – o MaxiProx energizará o cartão e o ESP RFID Tool capturará o fluxo Wiegand.
4. Exporte as credenciais capturadas por Wi-Fi ou USB-UART e reproduza/clonе conforme necessário.

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---------|--------------|------|
| O leitor reinicia quando um cartão é apresentado | O trigger PD negociou 9 V em vez de 12 V | Verifique os jumpers do trigger / experimente um cabo USB-C de maior potência |
| Sem alcance de leitura | A bateria ou a fiação está *sobre* a antena | Redirecione os cabos e mantenha 2 cm de distância ao redor da espira de ferrite |
| O sinal sonoro ainda apita | O interruptor está ligado ao condutor positivo, e não ao negativo | Mude o interruptor de corte para interromper a trilha **negativa** do alto-falante |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}