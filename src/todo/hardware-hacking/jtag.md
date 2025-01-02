# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)é uma ferramenta que pode ser usada com um Raspberry PI ou um Arduino para tentar encontrar os pinos JTAG de um chip desconhecido.\
No **Arduino**, conecte os **pinos de 2 a 11 a 10 pinos que potencialmente pertencem a um JTAG**. Carregue o programa no Arduino e ele tentará forçar todos os pinos para descobrir se algum pino pertence ao JTAG e qual é cada um.\
No **Raspberry PI**, você pode usar apenas **pinos de 1 a 6** (6 pinos, então você irá mais devagar testando cada pino JTAG potencial).

### Arduino

No Arduino, após conectar os cabos (pino 2 a 11 aos pinos JTAG e GND do Arduino ao GND da placa base), **carregue o programa JTAGenum no Arduino** e no Monitor Serial envie um **`h`** (comando para ajuda) e você deve ver a ajuda:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Configure **"Sem final de linha" e 115200baud**.\
Envie o comando s para começar a escanear:

![](<../../images/image (774).png>)

Se você estiver contatando um JTAG, encontrará uma ou várias **linhas começando com FOUND!** indicando os pinos do JTAG.

{{#include ../../banners/hacktricks-training.md}}
