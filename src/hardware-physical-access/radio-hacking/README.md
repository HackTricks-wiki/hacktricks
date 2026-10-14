# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Os testes de segurança de rádio examinam como um dispositivo transmite, recebe e interpreta sinais sem fio. Um rádio definido por software (SDR) pode ajudar a localizar um sinal, gravar amostras em fase/quadratura (I/Q) e testar a demodulação e a decodificação sem depender de hardware específico para cada protocolo.<sup>[[1]](#references)</sup>

Um fluxo de trabalho prático consiste em identificar a faixa de frequência e a largura do canal, capturar várias ações conhecidas do dispositivo, comparar os sinais resultantes e, então, determinar a modulação e a estrutura dos pacotes. Teste replay ou transmissão apenas em um ambiente isolado e em frequências e equipamentos para os quais você tenha autorização. As páginas desta seção abordam RFID, NFC, rádio sub-GHz, infravermelho, BLE e ferramentas relacionadas.<sup>[[1]](#references)</sup>

## Encontre a interface relevante

- Para um crachá de acesso ou chave de contato, comece por [tipos e ataques a tags RFID/NFC](pentesting-rfid.md), [fluxos de trabalho do Proxmark3](proxmark-3.md) ou [chaves iButton e 1-Wire](ibutton.md). O [guia do Flipper Zero](flipper-zero/README.md) contém links para ações específicas da interface.
- Para um sinal de controle remoto, use [RF sub-GHz e códigos rolling code](sub-ghz-rf.md) ou [protocolos e ataques de infravermelho](infrared.md).
- Para dispositivos e sensores próximos, use [testes de advertising, GATT e mesh em BLE](pentesting-ble-bluetooth-low-energy.md) ou [segurança LPWAN/LoRaWAN](low-power-wide-area-network.md).
- Para sinais de RF capturados ou desconhecidos, use [análise de sinais com SigDigger](../hardware-hacking/radio.md#sigdigger) ou o [framework FISSURE](fissure-the-rf-framework.md).

## References

- [1] [Great Scott Gadgets - Rádio definido por software com HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
