# Ataques de Side Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Ataques de side-channel recuperam segredos observando "leakage" físico ou microarquitetural que é *correlacionado* com o estado interno, mas *não* faz parte da interface lógica do dispositivo. Os exemplos variam desde medir a corrente instantânea consumida por um smart card até abusar de efeitos de gerenciamento de energia da CPU por meio de uma rede.

---

## Principais Canais de Leakage

| Canal | Alvo Típico | Instrumentação |
|---------|---------------|-----------------|
| Consumo de energia | Smart cards, MCUs IoT, FPGAs | Osciloscópio + resistor shunt/sonda HS (por exemplo, CW503)
| Campo eletromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda de campo H + LNA, ChipWhisperer/RTL-SDR
| Tempo de execução / caches | CPUs desktop e cloud | Timers de alta precisão (rdtsc/rdtscp), time-of-flight remoto
| Acústico / mecânico | Teclados, impressoras 3D, relés | Microfone MEMS, vibômetro a laser
| Óptico e térmico | LEDs, impressoras a laser, DRAM | Fotodiodo / câmera de alta velocidade, câmera IR
| Induzido por falhas | Criptografia de ASICs/MCUs | Clock/voltage glitch, EMFI, injeção a laser

---

## Análise de Energia

### Simple Power Analysis (SPA)
Observe um *único* trace e associe diretamente picos/vales às operações (por exemplo, S-boxes do DES).
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
Adquira *N > 1 000* traces, formule uma hipótese sobre o byte de chave `k`, calcule o modelo HW/HD e correlacione-o com a leakage.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA permanece no estado da arte, mas variantes de machine learning (MLA, deep-learning SCA) agora dominam competições como a ASCAD-v2 (2023).

---

## Análise Eletromagnética (EMA)
Sondas EM de near-field (500 MHz–3 GHz) leak informações idênticas às obtidas por *power analysis* **sem** inserir shunts. Pesquisas de 2024 demonstraram a recuperação de chaves a **>10 cm** de um STM32 usando correlação de espectro e front-ends RTL-SDR de baixo custo.

---

## Ataques de Timing e Microarquitetura
CPUs modernas leak segredos por meio de recursos compartilhados:
* **Hertzbleed (2022)** – o escalonamento de frequência por DVFS correlaciona-se com o Hamming weight, permitindo a extração *remota* de chaves EdDSA.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – execução transiente para ler dados de AVX-gather entre threads SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – a má predição vetorial especulativa leak registradores entre domínios.

---

## Ataques Acústicos e Ópticos
* O **iLeakKeys** de 2024 demonstrou 95 % de precisão na recuperação de keystrokes de laptops a partir de um **microfone de smartphone em uma chamada do Zoom**, usando um classificador CNN.
* Fotodiodos de alta velocidade capturam a atividade do LED de DDR4 e reconstroem chaves de round do AES em menos de 1 minuto (BlackHat 2023).

---

## Injeção de Falhas e Differential Fault Analysis (DFA)
A combinação de falhas com side-channel leakage reduz a busca de chaves (por exemplo, 1-trace AES DFA). Ferramentas recentes com preço acessível para hobbyistas:
* **ChipSHOUTER & PicoEMP** – glitching por pulso eletromagnético inferior a 1 ns.
* **GlitchKit-R5 (2025)** – plataforma open-source de clock/voltage glitching compatível com SoCs RISC-V.

---

## Fluxo de Trabalho Típico de um Ataque
1. Identificar o canal de leakage e o ponto de acesso (pino VCC, capacitor de desacoplamento, ponto de near-field).
2. Inserir um trigger (GPIO ou baseado em pattern).
3. Coletar >1 k traces com sampling/filters adequados.
4. Fazer o pré-processamento (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Recuperar a chave por métodos estatísticos ou ML (CPA, MIA, DL-SCA).
6. Validar e iterar sobre os outliers.

---

## Defesas e Hardening
* Implementações **constant-time** e algoritmos memory-hard.
* **Masking/shuffling** – dividir segredos em shares aleatórios; resistência de primeira ordem certificada pelo TVLA.
* **Hiding** – reguladores de tensão on-chip, clock randomizado, lógica dual-rail, escudos EM.
* **Detecção de falhas** – computação redundante, threshold signatures.
* **Operacional** – desabilitar DVFS/turbo em kernels criptográficos, isolar SMT, proibir co-location em clouds multi-tenant.

---

## Ferramentas e Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscópio de 500 MS/s + trigger Cortex-M; API Python como acima.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – comercial, oferece avaliação automatizada de leakage (TVLA-2.0).
* **scaaml** – biblioteca de SCA deep-learning baseada em TensorFlow (v1.2 – 2025).
* **pyecsca** – framework open-source de SCA para ECC da ANSSI.

---

## Referências

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
