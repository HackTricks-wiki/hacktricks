# Ataques de Análise de Side-Channel

{{#include ../../banners/hacktricks-training.md}}

Os ataques de side-channel recuperam segredos observando um "vazamento" físico ou microarquitetural que é *correlacionado* com o estado interno, mas que não faz parte da interface lógica do dispositivo. Os exemplos variam desde medir a corrente instantânea consumida por um smart card até explorar efeitos de gerenciamento de energia da CPU por meio de uma rede.

---

## Principais Canais de Vazamento

| Canal | Alvo Típico | Instrumentação |
|---------|---------------|-----------------|
| Consumo de energia | Smart cards, MCUs de IoT, FPGAs | Osciloscópio com resistor shunt ou sonda diferencial; o CW503 é uma fonte de alimentação para sondas/LNAs, não uma sonda por si só<sup>[[11]](#references)</sup> |
| Campo eletromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda H-field/near-field com amplificador de baixo ruído e osciloscópio ou receptor SDR, como um RTL-SDR<sup>[[13]](#references)</sup> |
| Tempo de execução / caches | CPUs desktop e cloud | Timers de alta precisão (`rdtsc`/`rdtscp`) ou tempo de percurso remoto |
| Acústico / mecânico | Teclados, impressoras 3-D, impressoras, relés e reguladores de tensão de CPU | Microfone MEMS ou vibômetro a laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Óptico e térmico | LEDs de status, displays, DRAM e dispositivos termicamente acoplados | Fotodiodo, câmera de alta velocidade ou câmera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Injeção de falhas | Criptografia em ASIC/MCU | Glitch de clock/tensão, EMFI ou injeção a laser |

---

## Análise de Energia

### Simple Power Analysis (SPA)
Observe um *único* trace e associe características visíveis a operações como branches, multiplicação modular ou diferentes sequências de instruções.<sup>[[1]](#references)</sup>

A configuração exata depende do alvo. O exemplo a seguir usa a API de captura de alto nível atual do ChipWhisperer depois que o scope e o target foram conectados e configurados:<sup>[[1]](#references)</sup>
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
Adquira múltiplos traces, formule uma hipótese para um byte de chave `k`, calcule um modelo de leakage baseado em Hamming-weight (HW) ou Hamming-distance (HD) e correlacione-o com cada sample. A quantidade de traces necessária é determinada pelo alvo, pelo ruído, pelo alinhamento, pelas countermeasures e pelo modelo de leakage; não é um limite fixo.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA é uma baseline padrão. Template attacks, mutual-information analysis e abordagens de machine learning podem ser úteis quando o leakage é não linear ou os traces estão mal alinhados.

---

## Análise Eletromagnética (EMA)
A análise EM de near-field pode observar atividade dependente dos dados sem inserir um shunt no caminho de alimentação. Ela não necessariamente expõe o mesmo sinal que um power trace: a posição e a orientação da probe, a largura de banda, o ganho do front-end, a qualidade do trigger e a distância são fatores importantes.

---

## Ataques de Temporização e Microarquitetura
CPUs modernas deixam vazar segredos por meio de recursos compartilhados:
* **Hertzbleed (2022)** – O dynamic voltage and frequency scaling dependente dos dados cria um canal de temporização remoto. A demonstração original de recuperação de chave end-to-end teve como alvo o SIKE; trabalhos posteriores discutem outras primitivas.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – A execução transiente pode expor dados usados por instruções vector gather através de limites de segurança.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – O tratamento incorreto do estado especulativo de vector registers pode divulgar dados do mesmo núcleo físico.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Um ataque de execução transiente combina phantom execution com training em transient execution para criar gadgets de misprediction controlados pelo atacante.<sup>[[5]](#references)</sup>

---

## Ataques Acústicos e Ópticos
O leakage acústico foi usado para recuperar chaves RSA a partir do ruído de um laptop em um experimento controlado, inclusive com o microfone de um celular próximo.<sup>[[6]](#references)</sup> Um estudo separado de 2023 sobre teclados classificou as teclas pressionadas com 95% de precisão quando treinado com gravações de um celular próximo e com 93% quando treinado com áudio do Zoom; esses números descrevem o experimento com o dispositivo treinado daquele artigo, não um teclado ou vítima arbitrários.<sup>[[9]](#references)</sup> Emanações ópticas de LEDs de status também podem ser correlacionadas com dados processados. Esses resultados são específicos do alvo e da configuração; não generalize seu alcance ou taxa de sucesso para dispositivos não relacionados.<sup>[[7]](#references)</sup>

---

## Injeção de Falhas e Differential Fault Analysis (DFA)
Combinar falhas controladas com observações de side-channel pode reduzir a busca da chave para alguns algoritmos e implementações. Plataformas de laboratório comuns incluem os recursos de voltage/clock glitching do ChipWhisperer e ferramentas dedicadas de EM fault injection, como ChipSHOUTER ou PicoEMP. A descrição anterior do rascunho, de “sub-1 ns”, não deve ser usada como especificação: o manual publicado do ChipSHOUTER lista larguras típicas de pulsos inseridos de **15–80 ns** com sua ponta de 1 mm e de **24–480 ns** com sua ponta de 4 mm (embora o jitter do trigger/pulso seja especificado em picossegundos). A resolução temporal necessária, o posicionamento da probe e o número de saídas com falha dependem do alvo e do modelo de falha.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

O rascunho anterior também afirmava: uma configuração EM de **500 MHz–3 GHz** que recuperava uma chave de STM32 a mais de **10 cm** usando um RTL-SDR; um LED de atividade DDR4 que revelava uma chave de rodada do AES em menos de um minuto no “Black Hat 2023”; e uma plataforma open-source de glitching para RISC-V de 2025 chamada **GlitchKit-R5**. Nenhum artigo primário, material de conferência ou repositório de projeto correspondente pôde ser localizado durante esta auditoria. Esses detalhes exatos são mantidos como pistas para pesquisa/reprodução, não como resultados estabelecidos ou recomendações de ferramentas.

---

## Fluxo de Trabalho Típico do Ataque
1. Identifique o canal de leakage e o ponto de conexão (pino VCC, capacitor de desacoplamento, ponto de near-field).
2. Insira o trigger (GPIO ou baseado em pattern).
3. Colete traces suficientes para o teste estatístico escolhido, registrando plaintext/ciphertext e outros metadados.
4. Faça o pré-processamento (alinhamento, remoção da média, filtro LP/HP, wavelet, PCA).
5. Faça a recuperação estatística ou por ML da chave (CPA, MIA, DL-SCA).
6. Valide e repita o processo para os outliers.

---

## Defesas e Hardening
* Implementações **constant-time** e algoritmos memory-hard.
* **Masking/shuffling** – divida os segredos em shares aleatórios; a resistência de primeira ordem é certificada pelo TVLA.
* **Hiding** – reguladores de tensão on-chip, clock randomizado, lógica dual-rail, blindagens EM.
* **Detecção de falhas** – computação redundante, threshold signatures.
* **Operacional** – desative DVFS/turbo em kernels de criptografia, isole SMT, proíba co-location em clouds multi-tenant.

---

## Ferramentas e Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscópio de 500 MS/s + trigger Cortex-M; API Python conforme descrito acima.<sup>[[1]](#references)</sup>
* **Riscure Inspector e produtos de fault injection** – ferramentas comerciais de análise e testes automatizados.
* **scaaml** – ferramentas e datasets de SCA baseada em deep learning e TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit open-source para reverse engineering de implementações ECC black-box por meio de side-channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Documentação do ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artigo sobre o ataque Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Explorando a coleta especulativa de dados](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Expondo novas superfícies de ataque com training em transient execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Extração de chave RSA por meio de criptoanálise acústica de baixa largura de banda](https://eprint.iacr.org/2013/857.pdf)
- [7] [Vazamento de informações a partir de emanações ópticas](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Documentação do artefato pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Um ataque prático de side-channel acústico baseado em deep learning contra teclados](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - manual do usuário do ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Documentação do ChipWhisperer — fonte de alimentação da probe CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Documentação do Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Realizando ataques de side-channel eletromagnético de baixo custo usando RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Decodificando propriedade intelectual: ataque de side-channel acústico e magnético contra uma impressora 3-D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Ataques de side-channel acústico contra impressoras](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Espionando a temperatura usando DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
