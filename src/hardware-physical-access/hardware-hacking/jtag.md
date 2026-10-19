# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Busca mais segura por pinos e configuração do hardware

- Identifique primeiro Vtref e GND com um multímetro. Muitos adaptadores precisam de Vtref para definir a tensão de I/O.
- Conversão de nível: prefira conversores de nível bidirecionais projetados para sinais push-pull (as linhas JTAG não são open-drain). Evite conversores I2C de direção automática para JTAG.
- Adaptadores úteis: placas FT2232H/FT232H (por exemplo, Tigard), CMSIS-DAP, J-Link, ST-LINK (específico do fornecedor), ESP-USB-JTAG (em ESP32-Sx). Conecte no mínimo TCK, TMS, TDI, TDO, GND e Vtref; opcionalmente TRST e SRST.

Para um conector sem documentação, identifique GND verificando a continuidade com um plano de terra conhecido **enquanto o alvo estiver sem alimentação**. Depois de mudar para o modo de tensão e ligar o alvo, não classifique todos os pinos com tensão alta como Vtref: entradas digitais em nível alto podem parecer semelhantes no multímetro. Rastreie os trilhos candidatos até capacitores de desacoplamento próximos e compare as formas de onda durante a ativação e o desligamento com um osciloscópio. Uma subida ou descida mais lenta, com formato de capacitor, é evidência de uma rede de alimentação/referência, mas verifique a tensão e a fiação antes de conectar uma sonda com conversão de nível. No PiFex, é possível selecionar uma referência externa de tensão mais baixa para o alvo por meio de `VCCA_IN`, em vez da configuração padrão de 3,3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** é uma ferramenta que você pode carregar em um MCU compatível com Arduino ou, experimentalmente, em um Raspberry Pi para fazer brute-force de pinouts JTAG desconhecidos e enumerar registradores de instrução.<sup>[[3]](#references)</sup>

- Arduino: conecte os pinos digitais D2–D11 a até 10 pads/pontos de teste JTAG suspeitos e o GND do Arduino ao GND do alvo. Alimente o alvo separadamente, a menos que saiba que o trilho é seguro. Prefira lógica de 3,3 V (por exemplo, Arduino Due) ou use um conversor de nível/resistores em série ao sondar alvos de 1,8–3,3 V.
- Raspberry Pi: a versão para Pi expõe menos GPIOs utilizáveis (por isso, as varreduras são mais lentas); consulte o repositório para ver o mapa de pinos e as restrições atuais.

Depois de gravar o firmware, abra o monitor serial a 115200 baud e envie `h` para obter ajuda. Fluxo típico:

- `l` encontra loopbacks para evitar falsos positivos
- `r` alterna os pull-ups internos, se necessário
- `s` procura TCK/TMS/TDI/TDO (e, às vezes, TRST/SRST)
- `y` faz brute-force do IR para descobrir opcodes não documentados
- `x` captura o estado dos pinos por boundary-scan

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Se um TAP válido for encontrado, você verá linhas começando com `FOUND!` indicando os pinos descobertos.

### Dicas de segurança para JTAGenum

- Sempre conecte os terras e nunca aplique tensão a pinos desconhecidos acima de Vtref do alvo. Em caso de dúvida, adicione resistores de 100–470 Ω em série aos pinos candidatos.
- Se o dispositivo usar SWD/SWJ em vez de JTAG de 4 fios, o JTAGenum pode não detectá-lo; experimente ferramentas SWD ou um adaptador compatível com SWJ-DP.

## Descoberta de pinos GPIO com go-jtagenum

Em um alvo ligado, com aterramento comum verificado e tensão de I/O compatível, `go-jtagenum` pode enumerar sinais JTAG candidatos a partir dos GPIOs do Raspberry Pi. O JSON de `-pins` mapeia rótulos para **números GPIO**, não para posições físicas no conector.<sup>[[5]](#references)</sup> No exemplo do SSD, a primeira varredura de IDCODE também relatou uma cadeia implausivelmente longa de valores variáveis: uma linha TDO candidata variável, por si só, não comprova a existência de um TAP válido. Verifique novamente um resultado plausível com uma varredura BYPASS, que desloca um padrão de bits conhecido de TDI até TDO através do registrador bypass de um bit.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Para aquela placa, BYPASS confirmou `TCK=10`, `TMS=14`, `TDI=9` e `TDO=15`; os pinos extras eram apenas candidatos **possíveis** a nTRST. Se um candidato retornar apenas zeros ou um padrão inconsistente, verifique o contato, a alimentação do alvo, os pull-ups e os atrasos do clock/reset antes de atribuir um sinal a ele.<sup>[[4]](#references)[[5]](#references)</sup> A ferramenta também aceita `-known-pins` com `test_bypass` para testar novamente um mapeamento recuperado.<sup>[[5]](#references)</sup>

## Caracterizar um TAP não documentado com UrJTAG

Um pinout descoberto não identifica os opcodes do registrador de instruções (IR) nem as larguras do registrador de dados (DR) necessárias para a depuração. Com uma compilação do UrJTAG que ofereça suporte ao cabo GPIO do Raspberry Pi, configure o mapeamento recuperado e execute `idcode`, depois `detect` e, por fim, `discover`. O exemplo do SSD retornou um TAP, um IR de quatro bits e diferentes larguras de DR para diferentes valores de IR. Um comprimento de DR igual a `-1` ou a mensagem “TDO preso em 0” não define um registrador utilizável; verifique o timing, a fiação e a instrução selecionada, em vez de atribuir uma largura a ele.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Este é um reconhecimento TAP, não uma identificação automática da CPU: compare o IDCODE resultante com a documentação do dispositivo e os targets OpenOCD compatíveis. O banco de dados local de fabricantes do UrJTAG pode rotular como desconhecido um ID válido.<sup>[[4]](#references)</sup>

## Primeiro contato com OpenOCD (scan e IDCODE)

OpenOCD é o OSS de facto para JTAG/SWD. Com um adaptador compatível, você pode fazer o scan da cadeia e ler os IDCODEs:<sup>[[1]](#references)</sup>

- Exemplo genérico com um J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG integrado do ESP32-S3 (não é necessária uma sonda externa):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Observações

- Se você obtiver um IDCODE com "todos uns/zeros", verifique a fiação, a alimentação, o Vtref e se a porta não está bloqueada por fuses/option bytes.
- Consulte `irscan`/`drscan` de baixo nível do OpenOCD para interação manual com o TAP ao inicializar cadeias desconhecidas.<sup>[[1]](#references)</sup>

## Adicionar um alvo não documentado ao OpenOCD

Depois de conhecer o ID do TAP e o comprimento do IR, examine os scripts `cpu/`, `target/` e `board/` do OpenOCD para encontrar uma **arquitetura de CPU correspondente** e, em seguida, crie configurações separadas para o adaptador e o alvo.<sup>[[4]](#references)[[6]](#references)</sup> O mapeamento de GPIO do Pi e o alvo ARCv2 a seguir são o exemplo de SSD testado, não uma configuração JTAG universal. A escolha do alvo ARC e as configurações de debug foram suposições que funcionaram para este dispositivo; em outra placa, substitua-as pelo ID, comprimento do IR, arquitetura e números de GPIO medidos para o alvo.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Execute `openocd -f raspberrypi-io.cfg -f target.cfg` e confirme que o exame do TAP é bem-sucedido antes de ler a memória. O exemplo abriu o Telnet na porta `4444` e um servidor GDB na porta `3333`; reconhecer um IDCODE, por si só, não prova que o target de CPU selecionado pode ser examinado ou depurado.<sup>[[4]](#references)</sup> Os GPIOs do Raspberry Pi não precisam ser os pinos identificados como JTAG em uma placa breakout quando o adaptador permite o remapeamento com `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Parar a CPU e despejar a memória/flash

Depois que o TAP for reconhecido e um script de target for escolhido, você poderá parar o core e despejar regiões da memória ou a flash interna. Exemplos (ajuste o target, os endereços-base e os tamanhos):<sup>[[1]](#references)</sup>

- Target genérico após a inicialização:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (prefira SBA quando disponível):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar ou ler usando o helper do OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Dicas para despejo de memória

- Use `mdw/mdh/mdb` para verificar a memória antes de despejos longos.
- Em cadeias com vários dispositivos, configure BYPASS nos dispositivos que não são alvos ou use um arquivo de placa que defina todos os TAPs.

Para um mapa de memória não documentado, a pesquisa sobre SSD verificou um despejo de 1 MiB em busca de strings reconhecíveis do controlador e, em seguida, usou um GDB compatível com a arquitetura, por meio do OpenOCD, para inspecionar `$pc`, a desmontagem e os registradores. Esses endereços ativos orientaram um segundo despejo de região, que foi comparado com instruções correspondentes em uma compilação do Ghidra compatível com ARC. Strings, por si só, são apenas uma verificação de plausibilidade, não uma prova de que a imagem esteja completa ou mapeada corretamente.<sup>[[4]](#references)</sup> Consulte [análise de firmware](../firmware-analysis/) para ver etapas mais abrangentes de análise estática.

## Truques de boundary-scan (EXTEST/SAMPLE)

Mesmo quando o acesso de depuração da CPU está bloqueado, o boundary-scan ainda pode estar disponível. Com UrJTAG/OpenOCD, você pode:<sup>[[1]](#references)</sup>
- Usar SAMPLE para registrar o estado dos pinos enquanto o sistema está em execução (encontrar atividade no barramento, confirmar o mapeamento dos pinos).
- Usar EXTEST para controlar os pinos (por exemplo, fazer bit-banging nas linhas de SPI flash externa via MCU para lê-la offline, se a fiação da placa permitir).

Fluxo mínimo do UrJTAG com um adaptador FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Você precisa do BSDL do dispositivo para conhecer a ordem dos bits do registrador de boundary scan. Atenção: alguns fornecedores bloqueiam as células de boundary scan na produção.

## Alvos modernos e observações

- ESP32‑S3/C3 incluem uma bridge USB‑JTAG nativa; o OpenOCD pode se comunicar diretamente via USB sem uma probe externa. Muito útil para triagem e dumps.<sup>[[2]](#references)</sup>
- O debug de RISC‑V (v0.13+) é amplamente compatível com o OpenOCD; prefira SBA para acesso à memória quando não for seguro interromper o core.
- Muitos MCUs implementam autenticação de debug e estados de ciclo de vida. Se o JTAG parecer inativo, mas a alimentação estiver correta, o dispositivo pode estar com eFuses configurados para o estado fechado ou exigir uma probe autenticada.

## Defesas e reforço (o que esperar em dispositivos reais)

- Desative permanentemente ou bloqueie o JTAG/SWD em produção (por exemplo, STM32 RDP nível 2, eFuses do ESP que desativam o PAD JTAG, APPROTECT/DPAP da NXP/Nordic).
- Exija debug autenticado (ARMv8.2‑A ADIv6 Debug Authentication, desafio-resposta gerenciado pelo OEM), mantendo o acesso à fabricação.
- Evite encaminhar test pads de fácil acesso; esconda vias de teste, remova/instale resistores para isolar o TAP e use conectores com chaveamento ou gabaritos com pinos pogo.
- Bloqueio de debug na inicialização: coloque o TAP atrás de uma ROM inicial que imponha secure boot.

## References

- [1] [Guia do usuário do OpenOCD – Comandos e configuração de JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Depuração JTAG do Espressif ESP32‑S3 (USB‑JTAG, uso do OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – scanner de pinout JTAG baseado em Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Hacking de JTAG com um Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — enumeração de JTAG via GPIO](https://github.com/gremwell/go-jtagenum)
- [6] [Guia do usuário do OpenOCD — Configuração do adaptador de debug](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
