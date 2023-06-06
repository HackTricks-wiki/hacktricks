# JTAGenum

[JTAGenum](https://github.com/cyphunk/JTAGenum) é uma ferramenta que pode ser usada com um Raspberry PI ou um Arduino para tentar encontrar os pinos JTAG de um chip desconhecido.\
No **Arduino**, conecte os **pinos de 2 a 11 a 10 pinos potencialmente pertencentes a um JTAG**. Carregue o programa no Arduino e ele tentará forçar todos os pinos para descobrir se algum deles pertence ao JTAG e qual é cada um.\
No **Raspberry PI**, você só pode usar **pinos de 1 a 6** (6 pinos, então você irá mais devagar testando cada pino JTAG potencial).

## Arduino

No Arduino, após conectar os cabos (pino 2 a 11 aos pinos JTAG e GND do Arduino à base), **carregue o programa JTAGenum no Arduino** e no Monitor Serial envie um **`h`** (comando para ajuda) e você deverá ver a ajuda:

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

Configure **"No line ending" e 115200baud**.\
Envie o comando s para iniciar a varredura:

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

Se você estiver conectado a um JTAG, encontrará uma ou várias **linhas começando por FOUND!** indicando os pinos do JTAG.
