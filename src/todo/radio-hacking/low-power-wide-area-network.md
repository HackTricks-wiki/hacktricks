# Rede de Área Ampla de Baixo Consumo

{{#include ../../banners/hacktricks-training.md}}

## Introdução

**Low-Power Wide Area Network** (LPWAN) é um grupo de tecnologias de rede sem fio, de baixo consumo e de área ampla, projetadas para **comunicações de longo alcance** a uma baixa taxa de bits.
Elas podem alcançar mais de **seis milhas** e suas **baterias** podem durar até **20 anos**.

Long Range (**LoRa**) é atualmente a camada física LPWAN mais implantada, e sua especificação aberta da camada MAC é a **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – camada física Chirp Spread Spectrum (CSS) desenvolvida pela Semtech (proprietária, mas documentada).
* LoRaWAN – camada MAC/de rede aberta mantida pela LoRa-Alliance. As versões 1.0.x e 1.1 são comuns em campo.
* Arquitetura típica: *end-device → gateway (packet-forwarder) → network-server → application-server*.

> O **modelo de segurança** depende de duas root keys AES-128 (AppKey/NwkKey), que derivam session keys durante o procedimento de *join* (OTAA) ou são codificadas permanentemente (ABP). Se qualquer key sofrer leak, o atacante obtém capacidade completa de leitura/escrita sobre o tráfego correspondente.

---

## Resumo da superfície de ataque

| Camada | Fraqueza | Impacto prático |
|-------|----------|------------------|
| PHY | Jamming reativo / seletivo | 100 % de perda de pacotes demonstrada com um único SDR e saída <1 W |
| MAC | Replay de Join-Accept e data-frame (reutilização de nonce, rollover do contador ABP) | Spoofing de dispositivos, injeção de mensagens, DoS |
| Network-Server | Packet-forwarder inseguro, filtros MQTT/UDP fracos, firmware desatualizado do gateway | RCE em gateways → pivot para a rede OT/IT |
| Application | AppKeys codificadas permanentemente ou previsíveis | Brute-force/decrypt do tráfego, impersonation de sensores |

---

## Vulnerabilidades recentes (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* aceitavam pacotes TCP que contornavam regras de firewall stateful em gateways Kerlink, permitindo a exposição da interface de gerenciamento remoto. Corrigido nas versões 4.0.11 / 4.2.1, respectivamente .
* **Série Dragino LG01/LG308** – Múltiplas CVEs de 2022-2024 (por exemplo, 2022-45227 directory traversal, 2022-45228 CSRF) ainda são observadas sem correção em 2025; permitem firmware dump não autenticado ou sobrescrita de configuração em milhares de gateways públicos .
* Overflow de *packet-forwarder UDP* da Semtech (advisory não publicado, corrigido em 2023-10): um uplink criado com mais de 255 B acionava stack-smash ‑> RCE em gateways de referência SX130x (encontrado no Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Técnicas práticas de ataque

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (reutilização de DevNonce)

1. Capture um **JoinRequest** legítimo.
2. Retransmita-o imediatamente (ou incremente o RSSI) antes que o dispositivo original transmita novamente.
3. O network-server aloca um novo DevAddr e novas session keys, enquanto o dispositivo-alvo continua com a sessão antiga → o atacante controla a sessão vaga e pode injetar uplinks falsificados.

### 3. Rebaixamento de Adaptive Data-Rate (ADR)

Force SF12/125 kHz para aumentar o airtime → esgote o duty-cycle do gateway (denial-of-service) mantendo baixo o impacto na bateria do atacante (basta enviar comandos MAC no nível da rede).

### 4. Jamming reativo

*HackRF One* executando um flowgraph do GNU Radio aciona um chirp de banda larga sempre que um preâmbulo é detectado – bloqueia todos os spreading factors com ≤200 mW TX; outage total medido a uma distância de 2 km .

---

## Ferramentas ofensivas (2025)

| Ferramenta | Finalidade | Observações |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Criar/analisar/atacar frames LoRaWAN, analisadores com DB e brute-forcer | Imagem Docker, compatível com entrada Semtech UDP |
| **LoRaPWN** | Utility Python da Trend Micro para realizar brute OTAA, gerar downlinks e descriptografar payloads | Demo lançada em 2023, independente de SDR |
| **LoRAttack** | Sniffer multicanal + replay com USRP; exporta PCAP/LoRaTap | Boa integração com Wireshark |
| **gr-lora / gr-lorawan** | Blocos OOT do GNU Radio para TX/RX de banda base | Base para ataques personalizados |

---

## Recomendações defensivas (checklist de pentester)

1. Prefira dispositivos **OTAA** com DevNonce verdadeiramente aleatório; monitore duplicatas.
2. Imponha **LoRaWAN 1.1**: contadores de frame de 32 bits, FNwkSIntKey / SNwkSIntKey distintos.
3. Armazene o frame-counter em memória não volátil (**ABP**) ou migre para OTAA.
4. Implante um **secure-element** (ATECC608A/SX1262-TRX-SE) para proteger as root keys contra extração de firmware.
5. Desative as portas UDP remotas do packet-forwarder (1700/1701) ou restrinja-as com WireGuard/VPN.
6. Mantenha os gateways atualizados; Kerlink/Dragino fornecem imagens corrigidas em 2024.
7. Implemente **detecção de anomalias de tráfego** (por exemplo, o analisador LAF) – sinalize resets de contador, joins duplicados e mudanças repentinas de ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
