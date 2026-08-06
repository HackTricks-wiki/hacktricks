# Análise de Pcap de Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Verificar BSSIDs

Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, pode começar investigando todos os SSIDs da captura com _Wireless --> WLAN Traffic_:

![Análise de Pcap de Wifi - Verificar BSSIDs: quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, pode começar investigando todos os SSIDs da captura com Wireless --...](<../../../images/image (106).png>)

![Análise de Pcap de Wifi - Verificar BSSIDs: quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, pode começar investigando todos os SSIDs da captura com Wireless --...](<../../../images/image (492).png>)

### Brute Force

Uma das colunas dessa tela indica se **alguma autenticação foi encontrada dentro do pcap**. Se esse for o caso, você pode tentar fazer Brute force usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por exemplo, ele recuperará a senha WPA que protege uma PSK (pre-shared key), necessária para descriptografar o tráfego posteriormente.

## Dados em Beacons / Side Channel

Se você suspeitar que **dados estão sendo vazados dentro dos beacons de uma rede WiFi**, poderá verificar os beacons da rede usando um filtro como o seguinte: `wlan contains <NAMEofNETWORK>`, ou `wlan.ssid == "NAMEofNETWORK"` e procurar strings suspeitas dentro dos pacotes filtrados.

## Encontrar Endereços MAC Desconhecidos em uma Rede WiFi

O link a seguir será útil para encontrar as **máquinas que enviam dados dentro de uma rede WiFi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece **endereços MAC, poderá removê-los da saída** adicionando verificações como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Depois de detectar **endereços MAC desconhecidos** se comunicando dentro da rede, você poderá usar **filtros** como o seguinte: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar o tráfego correspondente. Observe que os filtros ftp/http/ssh/telnet são úteis se você tiver descriptografado o tráfego.

## Descriptografar o Tráfego

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Encontrar Endereços MAC Desconhecidos em uma Rede WiFi - Descriptografar o Tráfego: Depois de detectar endereços MAC desconhecidos se comunicando dentro da rede, você poderá usar filtros como o seguinte:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
