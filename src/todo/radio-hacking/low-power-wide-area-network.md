# Rede de Área Ampla de Baixa Potência

{{#include ../../banners/hacktricks-training.md}}

## Introdução

**Rede de Área Ampla de Baixa Potência** (LPWAN) é um grupo de tecnologias de rede sem fio, de baixa potência e de área ampla, projetadas para **comunicações de longo alcance** a uma baixa taxa de bits. Elas podem alcançar mais de **seis milhas** e suas **baterias** podem durar até **20 anos**.

Long Range (**LoRa**) é atualmente a camada física LPWAN mais implantada e sua especificação de camada MAC aberta é **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – Camada física Chirp Spread Spectrum (CSS) desenvolvida pela Semtech (proprietária, mas documentada).
* LoRaWAN – Camada MAC/rede aberta mantida pela LoRa-Alliance. As versões 1.0.x e 1.1 são comuns no campo.
* Arquitetura típica: *dispositivo final → gateway (encaminhador de pacotes) → servidor de rede → servidor de aplicação*.

> O **modelo de segurança** depende de duas chaves raiz AES-128 (AppKey/NwkKey) que derivam chaves de sessão durante o procedimento de *junção* (OTAA) ou são codificadas (ABP). Se qualquer chave vazar, o atacante ganha capacidade total de leitura/gravação sobre o tráfego correspondente.

---

## Resumo da superfície de ataque

| Camada | Fraqueza | Impacto prático |
|--------|----------|------------------|
| PHY    | Jamming reativo / seletivo | 100 % de perda de pacotes demonstrada com um único SDR e <1 W de saída |
| MAC    | Repetição de Join-Accept & data-frame (reutilização de nonce, rollover de contador ABP) | Spoofing de dispositivo, injeção de mensagem, DoS |
| Servidor de Rede | Encaminhador de pacotes inseguro, filtros MQTT/UDP fracos, firmware de gateway desatualizado | RCE em gateways → pivotar para a rede OT/IT |
| Aplicação | AppKeys codificadas ou previsíveis | Força bruta/descriptografar tráfego, impersonar sensores |

---

## Vulnerabilidades recentes (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder* aceitou pacotes TCP que contornaram regras de firewall com estado em gateways Kerlink, permitindo a exposição da interface de gerenciamento remoto. Corrigido em 4.0.11 / 4.2.1, respectivamente.
* **Série Dragino LG01/LG308** – Múltiplas CVEs de 2022-2024 (por exemplo, 2022-45227 travessia de diretório, 2022-45228 CSRF) ainda observadas sem correção em 2025; habilitar despejo de firmware não autenticado ou sobrescrita de configuração em milhares de gateways públicos.
* Overflow de *encaminhador de pacotes UDP* da Semtech (aviso não lançado, corrigido em 2023-10): uplink elaborado maior que 255 B acionou stack-smash ‑> RCE em gateways de referência SX130x (encontrado pela Black Hat EU 2023 “LoRa Exploitation Reloaded”).

---

## Técnicas práticas de ataque

### 1. Capturar e descriptografar tráfego
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
3. O servidor de rede aloca um novo DevAddr e chaves de sessão enquanto o dispositivo alvo continua com a sessão antiga → o atacante possui a sessão vaga e pode injetar uplinks forjados.

### 3. Downgrade de Adaptive Data-Rate (ADR)

Force SF12/125 kHz para aumentar o tempo de transmissão → exaurir o ciclo de trabalho do gateway (negação de serviço) enquanto mantém o impacto na bateria do atacante baixo (apenas envie comandos MAC em nível de rede).

### 4. Jamming reativo

*HackRF One* executando o fluxo GNU Radio dispara um chirp de banda larga sempre que o preâmbulo é detectado – bloqueia todos os fatores de espalhamento com ≤200 mW TX; interrupção total medida a 2 km de distância.

---

## Ferramentas ofensivas (2025)

| Ferramenta | Propósito | Notas |
|-------------|-----------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Criar/analisar/atacar quadros LoRaWAN, analisadores com suporte a DB, força bruta | Imagem Docker, suporta entrada UDP Semtech |
| **LoRaPWN** | Utilitário Python da Trend Micro para força bruta OTAA, gerar downlinks, descriptografar payloads | Demonstração lançada em 2023, SDR-agnóstico |
| **LoRAttack** | Sniffer multi-canal + replay com USRP; exporta PCAP/LoRaTap | Boa integração com Wireshark |
| **gr-lora / gr-lorawan** | Blocos OOT do GNU Radio para TX/RX de banda base | Fundação para ataques personalizados |

---

## Recomendações defensivas (checklist de pentester)

1. Prefira dispositivos **OTAA** com DevNonce verdadeiramente aleatório; monitore duplicatas.
2. Aplique **LoRaWAN 1.1**: contadores de quadro de 32 bits, FNwkSIntKey / SNwkSIntKey distintos.
3. Armazene o contador de quadros em memória não volátil (**ABP**) ou migre para OTAA.
4. Implemente **elemento seguro** (ATECC608A/SX1262-TRX-SE) para proteger chaves raiz contra extração de firmware.
5. Desative portas de encaminhamento de pacotes UDP remotos (1700/1701) ou restrinja com WireGuard/VPN.
6. Mantenha os gateways atualizados; Kerlink/Dragino fornecem imagens corrigidas de 2024.
7. Implemente **detecção de anomalias de tráfego** (por exemplo, analisador LAF) – sinalize reinicializações de contadores, joins duplicados, mudanças súbitas de ADR.

## Referências

* LoRaWAN Auditing Framework (LAF) – https://github.com/IOActive/laf
* Visão geral do Trend Micro LoRaPWN – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
