# Ataques de Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Os ataques de side-channel recuperam segredos observando a "leakage" física ou microarquitetural que está *correlacionada* com o estado interno, mas *não* faz parte da interface lógica do dispositivo. Os exemplos vão desde medir a corrente instantânea consumida por um smart card até abusar dos efeitos de gerenciamento de energia da CPU por meio de uma rede.

---

## Principais canais de leakage

| Canal | Alvo típico | Instrumentação |
|---------|---------------|-----------------|
| Consumo de energia | Smart cards, MCUs de IoT, FPGAs | Osciloscópio com resistor shunt ou sonda diferencial; o CW503 é uma fonte de alimentação para sondas/LNAs, não uma sonda em si<sup>[[11]](#references)</sup> |
| Campo eletromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda H-field/near-field com amplificador de baixo ruído e osciloscópio ou receptor SDR, como um RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo de execução / caches | CPUs desktop e na nuvem | Temporizadores de alta precisão (`rdtsc`/`rdtscp`) ou medição remota do tempo de percurso |
| Acústica / mecânica | Teclados, impressoras 3D, impressoras, relés e reguladores de tensão de CPU | Microfone MEMS ou vibrometro a laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptica e térmica | LEDs de status, displays, DRAM e dispositivos acoplados termicamente | Fotodiodo, câmera de alta velocidade ou câmera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Injeção de falhas | Criptografia em ASICs/MCUs | Glitch de clock/tensão, EMFI ou injeção a laser |

---

## Análise de potência

### Simple Power Analysis (SPA)
Observe um *único* traço e associe características visíveis a operações como desvios, multiplicação modular ou diferentes sequências de instruções.<sup>[[1]](#references)</sup>

A configuração exata depende do alvo. O exemplo a seguir usa a API de captura de alto nível atual do ChipWhisperer, depois que o osciloscópio e o alvo forem conectados e configurados:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Análise de potência diferencial/de correlação (DPA/CPA)
Adquira múltiplos traces, formule uma hipótese para um byte da chave `k`, calcule um modelo de vazamento baseado em Hamming-weight (HW) ou Hamming-distance (HD) e correlacione-o com cada amostra. A quantidade de traces necessária depende do alvo, do ruído, do alinhamento, das contramedidas e do modelo de vazamento; não há um limite fixo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA é uma referência padrão. Template attacks, mutual-information analysis e abordagens de machine learning podem ser úteis quando o vazamento é não linear ou os traces estão mal alinhados.

---

## Análise Eletromagnética (EMA)
A análise EM de campo próximo pode observar atividade dependente dos dados sem inserir um shunt no caminho da alimentação. Ela não necessariamente expõe o mesmo sinal que um trace de potência: a posição e a orientação da probe, a largura de banda, o ganho do front-end, a qualidade do trigger e a distância são fatores importantes.

---

## Ataques de Temporização e Microarquitetura
CPUs modernas vazam segredos por meio de recursos compartilhados:
* **Hertzbleed (2022)** – O ajuste dinâmico de tensão e frequência, dependente dos dados, cria um canal remoto de temporização. A demonstração original de recuperação de chave de ponta a ponta teve como alvo o SIKE; trabalhos posteriores discutem outras primitivas.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – A execução transitória pode expor dados usados por instruções de gather vetorial através de fronteiras de segurança.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – O tratamento incorreto do estado especulativo dos registradores vetoriais pode divulgar dados do mesmo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Um ataque de execução transitória combina execução fantasma com treinamento em execução transitória para criar gadgets de predição incorreta controlados pelo atacante.<sup>[[5]](#references)</sup>

---

## Ataques Acústicos e Ópticos
O vazamento acústico foi usado para recuperar chaves RSA a partir do ruído de um laptop em um experimento controlado, inclusive com o microfone de um celular próximo.<sup>[[6]](#references)</sup> Um estudo separado sobre teclados, de 2023, classificou as teclas digitadas com 95% de precisão quando treinado com gravações de um celular próximo e com 93% quando treinado com áudio do Zoom; esses números descrevem o experimento com dispositivo treinado daquele artigo, não um teclado ou uma vítima arbitrários.<sup>[[9]](#references)</sup> As emanações ópticas de LEDs de status também podem ser correlacionadas com os dados processados. Esses resultados dependem do alvo e da configuração; não generalize seu alcance ou taxa de sucesso para dispositivos não relacionados.<sup>[[7]](#references)</sup>

---

## Injeção de Falhas e Análise Diferencial de Falhas (DFA)
Combinar falhas controladas com observações de side-channel pode reduzir a busca por chaves para alguns algoritmos e implementações. Plataformas de laboratório comuns incluem os recursos de glitching de tensão/clock do ChipWhisperer e ferramentas dedicadas de injeção de falhas EM, como ChipSHOUTER ou PicoEMP. A descrição anterior de “sub-1 ns” não deve ser usada como especificação: o manual publicado do ChipSHOUTER indica larguras típicas de pulso inserido de **15–80 ns** com a ponta de 1 mm e **24–480 ns** com a ponta de 4 mm (embora o jitter de trigger/pulso seja especificado em picossegundos). A resolução temporal necessária, a posição da probe e o número de saídas com falha dependem do alvo e do modelo de falha.<sup>[[1]](#references)[[10]](#references)</sup>

## Indícios de Pesquisa Não Verificados Mantidos da Versão Anterior

A versão anterior também afirmava: uma configuração EM de **500 MHz–3 GHz** que recuperava uma chave STM32 a mais de **10 cm** usando um RTL-SDR; um LED de atividade DDR4 que revelava uma chave de rodada AES em menos de um minuto no “Black Hat 2023”; e uma plataforma open-source de glitching RISC-V de 2025 chamada **GlitchKit-R5**. Não foi possível localizar um artigo primário, material de conferência ou repositório de projeto correspondente durante esta auditoria. Esses detalhes exatos são mantidos como pistas para pesquisa/reprodução, não como resultados estabelecidos nem recomendações de ferramentas.

---

## Fluxo de Trabalho Típico de um Ataque
1. Identifique o canal de vazamento e o ponto de conexão (pino VCC, capacitor de desacoplamento, ponto de campo próximo).
2. Insira um trigger (GPIO ou baseado em padrão).  
3. Colete traces suficientes para o teste estatístico escolhido, registrando o texto simples/cifrado e outros metadados.
4. Faça o pré-processamento (alinhamento, remoção da média, filtro LP/HP, wavelet, PCA).
5. Recuperação de chave estatística ou com ML (CPA, MIA, DL-SCA).
6. Valide e repita o processo com os outliers.

---

## Defesas e Hardening
* Implementações **constant-time** e algoritmos memory-hard.
* **Masking/shuffling** – divida os segredos em partes aleatórias; resistência de primeira ordem certificada por TVLA.
* **Hiding** – reguladores de tensão on-chip, clock aleatório, lógica dual-rail, blindagens EM.
* **Detecção de falhas** – computação redundante, assinaturas de limiar.
* **Operacional** – desative DVFS/turbo em kernels de criptografia, isole SMT, proíba co-location em clouds multi-tenant.

---

## Ferramentas e Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscópio de 500 MS/s + trigger Cortex-M; API Python como acima.<sup>[[1]](#references)</sup>
* **Riscure Inspector e produtos de injeção de falhas** – ferramentas comerciais de análise e testes automatizados.
* **scaaml** – ferramentas e datasets de SCA com deep learning baseado em TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source para engenharia reversa de implementações ECC black-box por meio de side-channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentação do ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artigo sobre o ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: explorando a coleta especulativa de dados](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: expondo novas superfícies de ataque com treinamento em execução transitória](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extração de chave RSA por criptoanálise acústica de baixa largura de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Vazamento de informações por emanações ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentação do artefato pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Um ataque prático de side-channel acústico em teclados baseado em deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manual do usuário do ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentação do ChipWhisperer — fonte de alimentação da probe CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentação do Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — realização de ataques eletromagnéticos de side-channel de baixo custo usando RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificando propriedade intelectual: ataque de side-channel acústico e magnético a uma impressora 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — ataques de side-channel acústico a impressoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionando a temperatura usando DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
