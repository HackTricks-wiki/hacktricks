# Ataques de Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Ataques de side-channel recuperam segredos observando "leakage" físico ou microarquitetural que está *correlacionado* com o estado interno, mas *não* faz parte da interface lógica do dispositivo. Os exemplos vão desde medir a corrente instantânea consumida por um smart card até explorar efeitos de gerenciamento de energia da CPU pela rede.

Para um alvo com hardware de depuração ARM acessível, o [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) pode fornecer uma referência do caminho de execução junto com capturas de energia ou EM; trata-se de um trace de depuração, não de um canal de leakage.<sup>[[17]](#references)</sup>

---

## Principais canais de leakage

| Canal | Alvo típico | Instrumentação |
|---------|---------------|-----------------|
| Consumo de energia | Smart cards, MCUs de IoT, FPGAs | Osciloscópio com resistor shunt ou sonda diferencial; o CW503 é uma fonte de alimentação para sondas/LNAs, não uma sonda em si<sup>[[11]](#references)</sup> |
| Campo eletromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda de campo H/de campo próximo com amplificador de baixo ruído e osciloscópio ou receptor SDR, como um RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo de execução / caches | CPUs de desktop e cloud | Temporizadores de alta precisão (`rdtsc`/`rdtscp`) ou tempo de voo remoto |
| Acústica / mecânica | Teclados, impressoras 3D, impressoras, relés e reguladores de tensão de CPU | Microfone MEMS ou vibrometro laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptico e térmico | LEDs de status, telas, DRAM e dispositivos com acoplamento térmico | Fotodiodo, câmera de alta velocidade ou câmera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Injeção de falhas | Criptografia em ASIC/MCU | Glitch de clock/tensão, EMFI ou injeção a laser |

---

## Análise de potência

### Simple Power Analysis (SPA)
Observe um *único* trace e associe características visíveis a operações como desvios, multiplicação modular ou diferentes sequências de instruções.<sup>[[1]](#references)</sup>

A configuração exata depende do alvo. O exemplo a seguir usa a API de captura de alto nível atual do ChipWhisperer, após conectar e configurar o osciloscópio e o alvo:<sup>[[1]](#references)</sup>

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

### Differential/Correlation Power Analysis (DPA/CPA)
Adquira vários traces, formule uma hipótese para um byte da chave `k`, calcule um modelo de leakage baseado no peso de Hamming (HW) ou na distância de Hamming (HD) e correlacione-o com cada amostra. O número de traces necessário depende do alvo, do ruído, do alinhamento, das contramedidas e do modelo de leakage; não há um limite fixo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA é uma referência padrão. Template attacks, análise de informação mútua e abordagens de machine learning podem ser úteis quando o vazamento é não linear ou os traces estão mal alinhados.

---

## Análise Eletromagnética (EMA)
A análise EM de campo próximo pode observar atividade dependente dos dados sem inserir um shunt no caminho da alimentação. Ela não necessariamente expõe o mesmo sinal que um trace de energia: posição e orientação da sonda, largura de banda, ganho do front-end, qualidade do trigger e distância são fatores importantes.

---

## Ataques de Timing e Microarquitetura
CPUs modernas vazam segredos por meio de recursos compartilhados:
* **Hertzbleed (2022)** – O escalonamento dinâmico de tensão e frequência, dependente dos dados, cria um canal remoto de timing. A demonstração original de recuperação de chave ponta a ponta teve como alvo o SIKE; trabalhos posteriores discutem outras primitivas.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – A execução transitória pode expor dados usados por instruções vector gather através de fronteiras de segurança.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – O tratamento incorreto do estado especulativo de registradores vetoriais pode divulgar dados do mesmo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Um ataque de execução transitória combina execução fantasma com treinamento em execução transitória para criar gadgets de misprediction controlados pelo atacante.<sup>[[5]](#references)</sup>

---

## Ataques Acústicos e Ópticos
O vazamento acústico já foi usado para recuperar chaves RSA a partir do ruído de laptops em um experimento controlado, inclusive com o microfone de um celular próximo.<sup>[[6]](#references)</sup> Um estudo separado de 2023 sobre teclados classificou pressionamentos de teclas com 95% de precisão quando treinado com gravações feitas por um celular próximo e com 93% quando treinado com áudio do Zoom; esses números descrevem o experimento com dispositivos treinados daquele artigo, não um teclado ou vítima qualquer.<sup>[[9]](#references)</sup> Emanações ópticas de LEDs de status também podem ser correlacionadas com dados processados. Esses resultados são específicos ao alvo e à configuração; não generalize seu alcance ou taxa de sucesso para dispositivos não relacionados.<sup>[[7]](#references)</sup>

---

## Injeção de Falhas e Análise Diferencial de Falhas (DFA)
Combinar falhas controladas com observações de canal lateral pode reduzir a busca de chave para alguns algoritmos e implementações. Plataformas de laboratório comuns incluem os recursos de glitching de tensão/clock do ChipWhisperer e ferramentas dedicadas de injeção de falhas EM, como ChipSHOUTER ou PicoEMP. A descrição anterior de “sub-1 ns” não deve ser usada como especificação: o manual publicado do ChipSHOUTER indica larguras típicas de pulso inserido de **15–80 ns** com a ponta de 1 mm e **24–480 ns** com a ponta de 4 mm (embora o jitter do trigger/pulso seja especificado em picosegundos). A resolução de timing necessária, o posicionamento da sonda e o número de saídas com falha dependem do alvo e do modelo de falhas.<sup>[[1]](#references)[[10]](#references)</sup>

## Pistas de Pesquisa Não Verificadas Mantidas da Versão Anterior

A versão anterior também afirmava: uma configuração EM de **500 MHz–3 GHz** que recuperava uma chave STM32 a mais de **10 cm**, usando um RTL-SDR; um LED de atividade DDR4 que revelava uma chave de rodada AES em menos de um minuto no “Black Hat 2023”; e uma plataforma open-source de glitching RISC-V de 2025 chamada **GlitchKit-R5**. Não foi possível localizar nenhum artigo primário, material de conferência ou repositório de projeto correspondente durante esta auditoria. Esses detalhes exatos são mantidos como pistas para pesquisa/reprodução, não como resultados estabelecidos ou recomendações de ferramentas.

---

## Fluxo de Trabalho Típico de um Ataque
1. Identifique o canal de vazamento e o ponto de conexão (pino VCC, capacitor de desacoplamento, ponto de campo próximo).
2. Insira um trigger (GPIO ou baseado em padrão).  
3. Colete traces suficientes para o teste estatístico escolhido, registrando o plaintext/ciphertext e outros metadados.
4. Faça o pré-processamento (alinhamento, remoção da média, filtro LP/HP, wavelet, PCA).
5. Recuperação de chave estatística ou por ML (CPA, MIA, DL-SCA).
6. Valide e repita para os outliers.

---

## Defesas e Fortalecimento
* Implementações **constant-time** e algoritmos com uso intensivo de memória.
* **Masking/shuffling** – divida os segredos em partes aleatórias; resistência de primeira ordem certificada por TVLA.
* **Hiding** – reguladores de tensão no chip, clock aleatório, lógica dual-rail, blindagens EM.
* **Detecção de falhas** – computação redundante, assinaturas de limiar.
* **Operacional** – desative DVFS/turbo em kernels criptográficos, isole SMT, proíba co-location em clouds multi-tenant.

---

## Ferramentas e Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscópio de 500 MS/s + trigger Cortex-M; API Python conforme acima.<sup>[[1]](#references)</sup>
* **Riscure Inspector e produtos de injeção de falhas** – ferramentas comerciais de análise e testes automatizados.
* **scaaml** – ferramentas de SCA de deep learning baseadas em TensorFlow e conjuntos de dados.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source para engenharia reversa de implementações ECC black-box por meio de canais laterais.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentação do ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artigo sobre o ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: explorando a coleta especulativa de dados](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: expondo novas superfícies de ataque com treinamento em execução transitória](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extração de chave RSA por meio de criptoanálise acústica de baixa largura de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Vazamento de informação por emanações ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentação do artefato pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Um ataque prático de canal lateral acústico em teclados baseado em deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manual do usuário do ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentação do ChipWhisperer — fonte de alimentação da sonda CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentação do Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — realização de ataques de canal lateral eletromagnético de baixo custo usando RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificando propriedade intelectual: ataque de canal lateral acústico e magnético a uma impressora 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — ataques de canal lateral acústico a impressoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionando a temperatura usando DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Seguindo as instruções: rastreamento ARM em tempo real com ETM, ITM e TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
