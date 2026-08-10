# Análise de Wifi Pcap

## Verificar BSSIDs

Com uma captura de Wi-Fi aberta no Wireshark, selecione _Wireless → WLAN Traffic_ para resumir as redes sem fio observadas na captura; cada linha representa uma rede sem fio.<sup>[[1]](#references)</sup>

![Análise de Wifi Pcap - Verificar BSSIDs: Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, pode começar a investigar todos os SSIDs da captura com Wireless --...](<../../../images/image (106).png>)

![Análise de Wifi Pcap - Verificar BSSIDs: Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, pode começar a investigar todos os SSIDs da captura com Wireless --...](<../../../images/image (492).png>)

### Brute Force

Para capturas WPA/WPA2-PSK, `aircrack-ng` requer um four-way EAPOL handshake utilizável e testa passphrases candidatas com um dicionário. Use `-w` para fornecer a wordlist e `-b` para direcionar o BSSID do access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Se houver uma correspondência, o Aircrack-ng recupera a chave pré-compartilhada; a senha e o SSID correspondentes podem então ser configurados nas configurações de descriptografia 802.11 do Wireshark quando a captura e o modo de segurança forem compatíveis.<sup>[[2]](#references)[[5]](#references)</sup>

## Dados em Beacons / Side Channel

Se você suspeitar que **dados estão sendo vazados no tráfego de side channel de beacon**, comece com um filtro de exibição como `wlan contains "NAMEofNETWORK"` ou `wlan.ssid == "NAMEofNETWORK"`, e então inspecione os frames correspondentes em busca de strings suspeitas. A primeira forma realiza uma busca ampla por bytes; a segunda corresponde ao campo SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Encontrar endereços MAC desconhecidos em uma rede Wi-Fi

O Wireshark expõe `wlan.ta` como o endereço do transmissor e `wlan.addr` como um endereço de hardware/MAC; os filtros de exibição podem combinar esses campos com operadores lógicos:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece **endereços MAC, remova-os da saída** adicionando verificações como `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Depois de detectar **endereços MAC desconhecidos** se comunicando dentro da rede, use um filtro como `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` para restringir o tráfego. Os filtros FTP, HTTP, SSH e Telnet são úteis somente quando o Wireshark consegue dissecar o payload descriptografado correspondente.<sup>[[3]](#references)[[5]](#references)</sup>

## Descriptografar tráfego

Para adicionar uma chave de descriptografia 802.11 no Wireshark, abra _Edit → Preferences → Protocols → IEEE 802.11_ e clique em _Edit_ ao lado de _Decryption Keys_.<sup>[[5]](#references)</sup>

![Encontrar endereços MAC desconhecidos em uma rede Wi-Fi - Descriptografar tráfego: depois de detectar endereços MAC desconhecidos se comunicando dentro da rede, você pode usar filtros como o seguinte:...](<../../../images/image (499).png>)

Para WPA/WPA2, o Wireshark normalmente precisa do handshake de quatro vias EAPOL e da senha/SSID correspondentes; fornecer a chave transitória pode evitar a exigência do handshake. A descriptografia por conexão do WPA3 requer o PMK da conexão.<sup>[[5]](#references)</sup>

## References

- [1] [Guia do usuário do Wireshark: tráfego WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guia do usuário do Wireshark: criação de expressões de filtro de exibição](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Referência de filtros de exibição do Wireshark: LAN sem fio IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guia do usuário do Wireshark: chaves de descriptografia WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
