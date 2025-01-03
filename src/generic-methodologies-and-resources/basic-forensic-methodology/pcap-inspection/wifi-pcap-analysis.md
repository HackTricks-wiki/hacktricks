# Análise de Pcap Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Verificar BSSIDs

Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, você pode começar a investigar todos os SSIDs da captura com _Wireless --> WLAN Traffic_:

![](<../../../images/image (106).png>)

![](<../../../images/image (492).png>)

### Força Bruta

Uma das colunas daquela tela indica se **qualquer autenticação foi encontrada dentro do pcap**. Se esse for o caso, você pode tentar forçar a autenticação usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por exemplo, ele irá recuperar a senha WPA que protege um PSK (chave pré-compartilhada), que será necessária para descriptografar o tráfego mais tarde.

## Dados em Beacons / Canal Lateral

Se você suspeitar que **dados estão sendo vazados dentro dos beacons de uma rede Wifi**, você pode verificar os beacons da rede usando um filtro como o seguinte: `wlan contains <NAMEofNETWORK>`, ou `wlan.ssid == "NAMEofNETWORK"` para procurar dentro dos pacotes filtrados por strings suspeitas.

## Encontrar Endereços MAC Desconhecidos em uma Rede Wifi

O seguinte link será útil para encontrar as **máquinas enviando dados dentro de uma Rede Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece **endereços MAC, pode removê-los da saída** adicionando verificações como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Uma vez que você tenha detectado **endereços MAC desconhecidos** se comunicando dentro da rede, você pode usar **filtros** como o seguinte: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar seu tráfego. Note que os filtros ftp/http/ssh/telnet são úteis se você tiver descriptografado o tráfego.

## Descriptografar Tráfego

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
