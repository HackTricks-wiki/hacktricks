# Hacking de Rádio

{{#include ../../banners/hacktricks-training.md}}

Os testes de segurança de rádio examinam como um dispositivo transmite, recebe e interpreta sinais sem fio. Um software-defined radio (SDR) pode ajudar a localizar um sinal, gravar amostras em fase/quadratura (I/Q) e testar a demodulação e a decodificação sem depender de hardware específico do protocolo.<sup>[[1]](#references)</sup>

Um fluxo de trabalho prático consiste em identificar a banda de frequência e a largura do canal, capturar várias ações conhecidas do dispositivo, comparar os sinais resultantes e, em seguida, determinar a modulação e a estrutura dos pacotes. Teste replay ou transmissão somente em um ambiente isolado e em frequências e equipamentos para os quais você tenha autorização. As páginas desta seção abrangem RFID, NFC, rádio sub-GHz, infravermelho, BLE e ferramentas relacionadas.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - Rádio definido por software com HackRF](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
