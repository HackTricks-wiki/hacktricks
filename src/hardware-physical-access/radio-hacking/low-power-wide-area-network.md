# Rede de Área Ampla e Baixo Consumo de Energia

{{#include ../../banners/hacktricks-training.md}}

## Introdução

**Low-Power Wide Area Network** (LPWAN) é um conjunto de tecnologias de rede sem fio, de baixo consumo de energia e ampla cobertura, projetadas para **comunicações de longo alcance** com baixa taxa de bits.
Dependendo dos parâmetros de rádio, da antena, da região regulatória, do terreno e do ciclo de atividade, as implantações LPWAN podem trocar throughput por cobertura de vários quilômetros e duração da bateria de vários anos. Considere os valores de alcance e bateria informados pelos fornecedores como metas de projeto, não como garantias.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) é atualmente a camada física LPWAN mais implantada, e sua especificação aberta de camada MAC é a **LoRaWAN**.

---

## LPWAN, LoRa e LoRaWAN

* LoRa – Camada física Chirp Spread Spectrum (CSS) desenvolvida pela Semtech (proprietária, mas documentada).
* LoRaWAN – Camada MAC/Network aberta mantida pela LoRa-Alliance. As versões 1.0.x e 1.1 são comuns em implantações.
* Arquitetura típica: *dispositivo final → gateway (packet-forwarder) → servidor de rede → servidor de aplicação*.<sup>[[3]](#references)</sup>

> Na LoRaWAN 1.1, o **modelo de segurança** usa chaves-raiz de aplicação e de rede AES-128 separadas para derivar chaves de sessão específicas de cada função durante o OTAA. Implantações anteriores da versão 1.0.x normalmente usam uma única AppKey para derivar as chaves de sessão de rede e de aplicação, enquanto o ABP provisiona as chaves de sessão diretamente. Portanto, os recursos obtidos com uma chave vazada dependem da versão da LoRaWAN e de qual chave foi exposta.<sup>[[3]](#references)</sup>

---

## Resumo da superfície de ataque

| Camada | Vulnerabilidade | Impacto prático |
|-------|----------|------------------|
| PHY | Jamming reativo/seletivo | Perda localizada de pacotes; a eficácia depende do link budget, do timing, da largura de banda e das restrições regulatórias |
| MAC | Replay de quadros Join e de dados quando o estado de nonce/contador é reutilizado | Dessincronização do dispositivo, spoofing ou injection se o servidor/dispositivo violar as proteções contra replay |
| Servidor de rede | packet-forwarder inseguro, filtros MQTT/UDP fracos, firmware de gateway desatualizado | RCE em gateways → pivot para a rede OT/IT |
| Aplicação | AppKeys codificadas no código ou previsíveis | Brute-force/decrypt do tráfego, impersonation de sensores |

---

## Vulnerabilidades representativas de implementações

* **CVE-2024-29862** – As versões do ChirpStack Gateway Bridge anteriores à 4.0.11 e as versões do MQTT Forwarder anteriores à 4.2.1 podiam se conectar a um broker MQTT controlado por um atacante, pois a validação do certificado do servidor TLS estava desabilitada. Isso poderia expor credenciais e tráfego do gateway; atualize para as versões corrigidas.<sup>[[4]](#references)</sup>
* **Firmware Dragino LG01 4.3.4** – A CVE-2022-45227 descreve uma listagem não autenticada do diretório `/lib/` contendo um arquivo de backup disponível para download; a CVE-2022-45228 é uma CSRF de baixa gravidade na página de logout. Esses registros não comprovam o impacto alegado no LG308, a sobrescrita de configuração, o tamanho da população afetada nem o estado dos patches em 2025.<sup>[[6]](#references)[[7]](#references)</sup>
* Uma versão anterior desta página descrevia um suposto problema no packet-forwarder UDP da Semtech como um **uplink malicioso com mais de 255 bytes, causando stack smash e RCE em gateways de referência SX130x**, atribuído a uma apresentação “LoRa Exploitation Reloaded” da Black Hat Europe 2023 e a um patch privado de outubro de 2023. Esses detalhes específicos são mantidos aqui como pista de pesquisa, mas não foi possível corroborar nenhum comunicado público, apresentação ou patch correspondente. Não considere o problema uma vulnerabilidade conhecida sem obter o produto/versão afetado e uma fonte primária verificável.

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

Esses comandos preservam o fluxo de trabalho original como **sintaxe ilustrativa**; o layout do repositório e as flags variam entre projetos/releases. A captura passiva não revela uma AppKey forte. A tentativa de adivinhação offline só é útil quando a chave raiz é fraca o suficiente para ser encontrada e uma troca de join capturada fornece um valor que permite validar as candidatas.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testar a proteção contra replay OTAA e o estado do nonce

1. Em uma rede de teste autorizada, capture um **JoinRequest** legítimo.
2. Reenvie a mesma solicitação e confirme que o servidor de rede rejeita o `DevNonce` reutilizado.
3. Reinicie ou restaure o dispositivo de teste e repita a verificação para detectar perda do estado do nonce. Um servidor em conformidade deve rastrear os nonces usados; reenviar um JoinRequest, por si só, não revela as novas chaves de sessão derivadas nem dá ao invasor controle sobre uma sessão.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Downgrade de Adaptive Data-Rate (ADR)

Um invasor que consiga autenticar comandos MAC da camada de rede — por exemplo, após comprometer a chave de sessão de rede aplicável ou o servidor de rede — pode tentar forçar parâmetros ineficientes de taxa de dados e aumentar o tempo de transmissão. Um transmissor não autenticado nas proximidades não pode emitir comandos ADR legítimos apenas por conhecer o endereço de um dispositivo.<sup>[[3]](#references)</sup>

### 4. Jamming reativo

Um jammer reativo pode transmitir após detectar um preâmbulo LoRa e interromper seletivamente quadros. A página anterior afirmava que uma configuração HackRF/GNU Radio causou uma interrupção total a **2 km com no máximo 200 mW**, mas não foi fornecida nenhuma fonte de medição que sustentasse esses dados; mantenha esses valores apenas como meta de reprodução, não como resultado esperado. A potência de transmissão necessária, o tempo, a largura de banda, os fatores de espalhamento afetados e o alcance dependem do ambiente. Teste somente em uma configuração autorizada e com contenção de RF, e cumpra as regras locais de espectro.

---

## Ferramentas ofensivas (2025)

| Ferramenta | Finalidade | Observações |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Criar/analisar/atacar quadros LoRaWAN, analisadores com suporte a DB, ferramenta de brute force | Imagem Docker; aceita entrada Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Utilitário Python da Trend Micro para fazer brute force de OTAA, gerar downlinks e descriptografar payloads | Utilitário público de pesquisa; verifique o hardware e as versões do protocolo compatíveis<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework de pesquisa para captura LoRaWAN multicanal, análise de sessão, derivação de chaves e testes de replay | Descrito em uma dissertação de mestrado de 2024; obtenha e verifique a implementação exata antes de confiar nas flags do exemplo<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Blocos out-of-tree do GNU Radio para recepção de banda base LoRa ou pesquisa de transceptores | Os projetos diferem na compatibilidade com o GNU Radio e no conjunto de funcionalidades<sup>[[9]](#references)</sup> |

---

## Recomendações defensivas (checklist para pentester)

1. Prefira **OTAA** e verifique se os dispositivos e servidores persistem o estado de nonce necessário; monitore tentativas de join duplicadas rejeitadas.
2. Prefira **LoRaWAN 1.1**, quando compatível, para que as funções de rede usem chaves de sessão distintas e o tratamento atualizado de nonce.<sup>[[3]](#references)</sup>
3. Armazene o contador de quadros em memória não volátil (**ABP**) ou migre para OTAA.
4. Use um **secure element** apropriado (por exemplo, ATECC608A em um projeto compatível) para reduzir a exposição das chaves raiz no armazenamento comum do firmware.
5. Não exponha a redes não confiáveis os listeners UDP configurados do packet forwarder (comumente na porta 1700); autentique/criptografe o backhaul do gateway ou restrinja-o com uma VPN.
6. Mantenha os gateways com firmware compatível com o suporte do fornecedor e confirme o modelo/versão exatos em relação aos avisos aplicáveis.
7. Implemente **detecção de anomalias de tráfego** (por exemplo, analisador LAF) – sinalize resets de contador, joins duplicados e mudanças repentinas de ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Visão geral do LoRaPWN da Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - especificação LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - parâmetros regionais do LoRaWAN 1.1 e sincronização de join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Catálogo de dissertações da CTU - Análise de segurança de protocolos LPWAN com uso de tecnologia SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceptor GNU Radio `gr-lora_sdr` da EPFL](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
