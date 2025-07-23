# Análise de Ataques de Canal Lateral

{{#include ../../banners/hacktricks-training.md}}

Ataques de canal lateral recuperam segredos observando "vazamentos" físicos ou micro-arquitetônicos que estão *correlacionados* com o estado interno, mas *não* fazem parte da interface lógica do dispositivo. Exemplos variam desde medir a corrente instantânea consumida por um cartão inteligente até abusar dos efeitos de gerenciamento de energia da CPU através de uma rede.

---

## Principais Canais de Vazamento

| Canal | Alvo Típico | Instrumentação |
|-------|-------------|-----------------|
| Consumo de energia | Cartões inteligentes, MCUs IoT, FPGAs | Osciloscópio + resistor de shunt/sonda HS (por exemplo, CW503) |
| Campo eletromagnético (EM) | CPUs, RFID, aceleradores AES | Sonda H-field + LNA, ChipWhisperer/RTL-SDR |
| Tempo de execução / caches | CPUs de desktop e nuvem | Temporizadores de alta precisão (rdtsc/rdtscp), tempo de voo remoto |
| Acústico / mecânico | Teclados, impressoras 3-D, relés | Microfone MEMS, vibrometro a laser |
| Óptico e térmico | LEDs, impressoras a laser, DRAM | Fotodiodo / câmera de alta velocidade, câmera IR |
| Induzido por falhas | Criptos ASIC/MCU | Falha de clock/tensão, EMFI, injeção a laser |

---

## Análise de Potência

### Análise de Potência Simples (SPA)
Observe um *único* traço e associe diretamente picos/vales com operações (por exemplo, S-boxes DES).
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
### Análise de Potência Diferencial/Corracional (DPA/CPA)
Adquira *N > 1 000* traços, hipotetize o byte da chave `k`, calcule o modelo HW/HD e correlacione com o leak.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA continua sendo o estado da arte, mas variantes de aprendizado de máquina (MLA, SCA de aprendizado profundo) agora dominam competições como ASCAD-v2 (2023).

---

## Análise Eletromagnética (EMA)
Sondas EM de campo próximo (500 MHz–3 GHz) vazam informações idênticas à análise de potência *sem* inserir shunts. Pesquisas de 2024 demonstraram recuperação de chaves a **>10 cm** de um STM32 usando correlação de espectro e front-ends RTL-SDR de baixo custo.

---

## Ataques de Tempo & Microarquitetura
CPUs modernas vazam segredos através de recursos compartilhados:
* **Hertzbleed (2022)** – escalonamento de frequência DVFS correlaciona com peso de Hamming, permitindo extração *remota* de chaves EdDSA.
* **Downfall / Gather Data Sampling (Intel, 2023)** – execução transitória para ler dados AVX-gather através de threads SMT.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – predição de vetor especulativa vaza registradores entre domínios.

Para um tratamento amplo de questões da classe Spectre, veja {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## Ataques Acústicos & Ópticos
* 2024 "​iLeakKeys" mostrou 95 % de precisão na recuperação de pressionamentos de teclas de laptop a partir de um **microfone de smartphone via Zoom** usando um classificador CNN.
* Fotodiodos de alta velocidade capturam atividade de LED DDR4 e reconstroem chaves de rodada AES em menos de 1 minuto (BlackHat 2023).

---

## Injeção de Falhas & Análise de Falhas Diferenciais (DFA)
Combinar falhas com vazamento de canal lateral encurta a busca de chaves (por exemplo, DFA AES de 1 traço). Ferramentas recentes com preços acessíveis para entusiastas:
* **ChipSHOUTER & PicoEMP** – glitching de pulso eletromagnético sub-1 ns.
* **GlitchKit-R5 (2025)** – plataforma de glitch de clock/tensão de código aberto suportando SoCs RISC-V.

---

## Fluxo de Trabalho Típico de Ataque
1. Identificar canal de vazamento e ponto de montagem (pino VCC, capacitor de desacoplamento, ponto de campo próximo).
2. Inserir gatilho (GPIO ou baseado em padrão).
3. Coletar >1 k traços com amostragem/filtros adequados.
4. Pré-processar (alinhamento, remoção de média, filtro LP/HP, wavelet, PCA).
5. Recuperação de chave estatística ou ML (CPA, MIA, DL-SCA).
6. Validar e iterar sobre outliers.

---

## Defesas & Fortalecimento
* Implementações **em tempo constante** e algoritmos resistentes à memória.
* **Mascaramento/shuffling** – dividir segredos em partes aleatórias; resistência de primeira ordem certificada por TVLA.
* **Ocultação** – reguladores de tensão on-chip, clock randomizado, lógica de dupla via, escudos EM.
* **Detecção de falhas** – computação redundante, assinaturas de limiar.
* **Operacional** – desabilitar DVFS/turbo em núcleos criptográficos, isolar SMT, proibir co-localização em nuvens multi-inquilino.

---

## Ferramentas & Frameworks
* **ChipWhisperer-Husky** (2024) – osciloscópio de 500 MS/s + gatilho Cortex-M; API Python como acima.
* **Riscure Inspector & FI** – comercial, suporta avaliação automatizada de vazamento (TVLA-2.0).
* **scaaml** – biblioteca SCA de aprendizado profundo baseada em TensorFlow (v1.2 – 2025).
* **pyecsca** – framework SCA ECC de código aberto da ANSSI.

---

## Referências

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
