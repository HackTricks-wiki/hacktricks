# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Introduction

**Low-Power Wide Area Network** (LPWAN) é um grupo de tecnologias de redes sem fio de baixa potência e área ampla, projetadas para **comunicações de longo alcance** com uma baixa taxa de bits.
Dependendo dos parâmetros de rádio, da antena, da região regulatória, do terreno e do duty cycle, as implementações de LPWAN podem trocar throughput por cobertura de vários quilômetros e vida útil da bateria de vários anos. Considere os valores de alcance e duração da bateria fornecidos pelos vendors como metas de projeto, não como garantias.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) é atualmente a physical layer de LPWAN mais utilizada, e sua especificação aberta da camada MAC é a **LoRaWAN**.

---

## LPWAN, LoRa, and LoRaWAN

* LoRa – Chirp Spread Spectrum (CSS) physical layer desenvolvida pela Semtech (proprietária, mas documentada).
* LoRaWAN – Camada MAC/Network aberta mantida pela LoRa-Alliance. As versões 1.0.x e 1.1 são comuns em campo.
* Arquitetura típica: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> No LoRaWAN 1.1, o **security model** utiliza root keys separadas de aplicação e de rede, baseadas em AES-128, para derivar session keys específicas de cada função durante o OTAA. Implementações anteriores da versão 1.0.x normalmente utilizam uma única AppKey para derivar as session keys de rede e de aplicação, enquanto o ABP provisiona as session keys diretamente. A capacidade obtida a partir de uma chave vazada depende, portanto, da versão do LoRaWAN e de qual chave foi exposta.<sup>[[3]](#references)</sup>

---

## Attack surface summary

| Layer | Weakness | Practical impact |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Perda localizada de pacotes; a eficácia depende do link budget, do timing, da largura de banda e das restrições regulatórias |
| MAC | Join e replay de data-frames quando o estado de nonce/counter é reutilizado | Desincronização do dispositivo, spoofing ou injection se o servidor/dispositivo violar as proteções contra replay |
| Network-Server | Packet-forwarder inseguro, filtros MQTT/UDP fracos, firmware desatualizado do gateway | RCE nos gateways → pivot para a rede OT/IT |
| Application | AppKeys hard-coded ou previsíveis | Brute-force/decrypt do tráfego, impersonation de sensores |

---

## Representative implementation vulnerabilities

* **CVE-2024-29862** – As versões do ChirpStack Gateway Bridge anteriores à 4.0.11 e as versões do MQTT Forwarder anteriores à 4.2.1 podiam se conectar a um MQTT broker controlado por um atacante porque a validação do certificado do servidor TLS estava desativada. Isso poderia expor credenciais e o tráfego do gateway; atualize para as releases corrigidas.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – A CVE-2022-45227 descreve uma listagem não autenticada do diretório `/lib/` contendo um backup para download; a CVE-2022-45228 é uma CSRF de baixa severidade na página de logout. Esses registros não comprovam o impacto alegado no LG308, a sobrescrita da configuração, o tamanho da população ou o estado do patch em 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Uma versão anterior desta página descrevia um suposto problema do Semtech UDP packet-forwarder como um **uplink criado com mais de 255 bytes causando um stack smash e RCE em reference gateways SX130x**, atribuído a uma apresentação “LoRa Exploitation Reloaded” da Black Hat Europe 2023 e a um patch privado de outubro de 2023. Esses detalhes precisos são mantidos aqui como uma linha de investigação, mas nenhum advisory, apresentação ou patch público correspondente pôde ser corroborado. Não trate o problema como uma vulnerabilidade conhecida sem obter o produto/versão afetado e uma fonte primária verificável.

---

## Practical attack techniques

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Esses comandos preservam o workflow original como **sintaxe ilustrativa**; o layout do repositório e as flags variam entre projetos/releases. A captura passiva não revela um AppKey forte. A tentativa offline é útil somente quando a root key é fraca o suficiente para ser encontrada e uma troca de mensagens de join capturada fornece um valor capaz de validar os candidatos.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testar a proteção contra replay do OTAA e o estado do nonce

1. Em uma rede de teste autorizada, capture um **JoinRequest** legítimo.
2. Reproduza a mesma requisição e confirme que o network server rejeita o `DevNonce` reutilizado.
3. Reinicie ou redefina o dispositivo de teste e repita a verificação para detectar perda do estado do nonce. Um servidor compatível deve rastrear os nonces usados; reproduzir um JoinRequest sozinho não revela as session keys recém-derivadas nem concede ao reprodutor o controle de uma sessão.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Downgrade do Adaptive Data-Rate (ADR)

Um atacante capaz de autenticar comandos MAC da camada de rede — por exemplo, após comprometer a network session key aplicável ou o network server — pode tentar forçar parâmetros de data-rate ineficientes e aumentar o airtime. Um transmissor não autenticado nas proximidades não pode emitir comandos ADR legitimamente apenas por conhecer o endereço de um dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reativo

Um jammer reativo pode transmitir após detectar um preâmbulo LoRa e interromper frames seletivamente. A página anterior afirmava que uma configuração HackRF/GNU Radio causava uma interrupção total a **2 km com no máximo 200 mW**, mas nenhuma fonte de medição comprobatória foi fornecida; mantenha esses números apenas como um objetivo de reprodução, não como um resultado esperado. A potência de transmissão, o timing, a largura de banda, os spreading factors afetados e o alcance necessários são específicos do ambiente. Teste somente dentro de uma configuração autorizada e confinada por RF, cumprindo as regras locais de espectro.

---

## Ferramentas ofensivas (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Criar/analisar/atacar frames LoRaWAN, analisadores com backend de DB, brute-forcer | Imagem Docker; suporta entrada UDP Semtech<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utilitário Python da Trend Micro para fazer brute force de OTAA, gerar downlinks e descriptografar payloads | Utilitário de pesquisa público; verifique o hardware e as versões do protocolo compatíveis<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de pesquisa para captura LoRaWAN multicanal, análise de sessões, derivação de chaves e testes de replay | Descrito em uma dissertação de mestrado de 2024; obtenha e verifique a implementação exata antes de confiar nas flags do exemplo<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocos out-of-tree do GNU Radio para recepção de baseband LoRa ou pesquisa de transceptores | Os projetos diferem em compatibilidade com o GNU Radio e conjunto de recursos<sup>[[9]](#references)</sup> |

---

## Recomendações defensivas (checklist de pentester)

1. Prefira **OTAA** e verifique se os dispositivos e servidores persistem o estado de nonce necessário; monitore joins duplicados rejeitados.
2. Prefira **LoRaWAN 1.1** quando houver suporte, para que as funções de rede usem session keys distintas e um tratamento de nonce atualizado.<sup>[[3]](#references)</sup>
3. Armazene o frame-counter em memória não volátil (**ABP**) ou migre para OTAA.
4. Implante um **secure element** adequado (por exemplo, ATECC608A em um design compatível) para reduzir a exposição das root keys no armazenamento comum do firmware.
5. Não exponha listeners UDP configurados do packet-forwarder (comumente 1700) a redes não confiáveis; autentique/criptografe o backhaul do gateway ou restrinja-o com uma VPN.
6. Mantenha os gateways em firmware compatível com o suporte do fornecedor e confirme o modelo/versão exato em relação aos advisories aplicáveis.
7. Implemente **detecção de anomalias de tráfego** (por exemplo, analisador LAF) — sinalize resets de contadores, joins duplicados e alterações repentinas de ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Visão geral do LoRaPWN da Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - especificação LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - parâmetros regionais do LoRaWAN 1.1 e sincronização de join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catálogo de dissertações da CTU - análise de segurança de protocolos LPWAN utilizando tecnologia SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceptor GNU Radio `gr-lora_sdr` da EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
