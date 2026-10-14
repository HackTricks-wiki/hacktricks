# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** é uma ferramenta que você pode carregar em um MCU compatível com Arduino ou, experimentalmente, em um Raspberry Pi para fazer brute-force de pinouts JTAG desconhecidos e enumerar registradores de instruções.<sup>[[3]](#references)</sup>

- Arduino: conecte os pinos digitais D2–D11 a até 10 pads/testpoints JTAG suspeitos e o GND do Arduino ao GND do dispositivo-alvo. Alimente o dispositivo-alvo separadamente, a menos que saiba que a linha de alimentação é segura. Prefira lógica de 3,3 V (por exemplo, Arduino Due) ou use um conversor de nível/resistores em série ao sondar dispositivos-alvo de 1,8–3,3 V.
- Raspberry Pi: a versão para Pi expõe menos GPIOs utilizáveis (portanto, as varreduras são mais lentas); consulte o repositório para ver o mapeamento de pinos e as limitações atuais.

Depois de gravar o firmware, abra o monitor serial a 115200 baud e envie `h` para obter ajuda. Fluxo típico:

- `l` encontra loopbacks para evitar falsos positivos
- `r` alterna os pull-ups internos, se necessário
- `s` procura TCK/TMS/TDI/TDO (e, às vezes, TRST/SRST)
- `y` faz brute-force do IR para descobrir opcodes não documentados
- `x` captura um snapshot boundary-scan dos estados dos pinos

![JTAG - JTAGenum: x snapshot boundary-scan dos estados dos pinos](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot boundary-scan dos estados dos pinos](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot boundary-scan dos estados dos pinos](<../../images/image (774).png>)



Se um TAP válido for encontrado, você verá linhas começando com `FOUND!` indicando os pinos descobertos.

### Dicas de segurança para JTAGenum

- Sempre conecte o terra em comum e nunca aplique aos pinos desconhecidos uma tensão superior à Vtref do dispositivo-alvo. Em caso de dúvida, adicione resistores de 100–470 Ω em série aos pinos candidatos.
- Se o dispositivo usar SWD/SWJ em vez de JTAG de 4 fios, o JTAGenum talvez não o detecte; experimente ferramentas SWD ou um adaptador compatível com SWJ-DP.

## Busca mais segura de pinos e configuração do hardware

- Identifique primeiro Vtref e GND com um multímetro. Muitos adaptadores precisam de Vtref para definir a tensão de I/O.
- Conversão de nível: prefira conversores de nível bidirecionais projetados para sinais push-pull (as linhas JTAG não são open-drain). Evite conversores I2C autodirecionais para JTAG.
- Adaptadores úteis: placas FT2232H/FT232H (por exemplo, Tigard), CMSIS-DAP, J-Link, ST-LINK (específico do fabricante), ESP-USB-JTAG (em ESP32-Sx). Conecte, no mínimo, TCK, TMS, TDI, TDO, GND e Vtref; opcionalmente, TRST e SRST.

## Primeiro contato com o OpenOCD (varredura e IDCODE)

OpenOCD é o OSS de facto para JTAG/SWD. Com um adaptador compatível, você pode varrer a cadeia e ler os IDCODEs:<sup>[[1]](#references)</sup>

- Exemplo genérico com um J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG integrado do ESP32-S3 (não é necessária uma probe externa):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Observações

- Se você obtiver um IDCODE com “todos uns/zeros”, verifique a fiação, a alimentação, o Vtref e se a porta não está bloqueada por fuses/option bytes.
- Consulte os comandos de baixo nível `irscan`/`drscan` do OpenOCD para interagir manualmente com o TAP ao inicializar cadeias desconhecidas.<sup>[[1]](#references)</sup>

## Parando a CPU e despejando a memória/flash

Depois que o TAP for reconhecido e um script de target for escolhido, você poderá parar o core e despejar regiões de memória ou a flash interna. Exemplos (ajuste o target, os endereços base e os tamanhos):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, programar ou ler via helper do OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Dicas para despejar a memória

- Use `mdw/mdh/mdb` para verificar a memória antes de despejos longos.
- Em cadeias com vários dispositivos, defina BYPASS nos dispositivos que não são alvos ou use um arquivo de placa que defina todos os TAPs.

## Truques de boundary-scan (EXTEST/SAMPLE)

Mesmo quando o acesso de debug da CPU está bloqueado, o boundary-scan ainda pode estar exposto. Com UrJTAG/OpenOCD, você pode:<sup>[[1]](#references)</sup>
- Usar SAMPLE para capturar o estado dos pinos enquanto o sistema está em execução (encontrar atividade no barramento, confirmar o mapeamento dos pinos).
- Usar EXTEST para controlar os pinos (por exemplo, fazer bit-bang nas linhas de uma SPI flash externa via MCU para lê-la offline, se a fiação da placa permitir).

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
Você precisa do BSDL do dispositivo para saber a ordem dos bits do registrador boundary. Cuidado: alguns fabricantes bloqueiam as células boundary-scan na produção.

## Alvos modernos e observações

- ESP32‑S3/C3 incluem uma bridge USB‑JTAG nativa; o OpenOCD pode se comunicar diretamente via USB sem uma probe externa. Muito conveniente para triagem e dumps.<sup>[[2]](#references)</sup>
- O debug RISC‑V (v0.13+) é amplamente suportado pelo OpenOCD; prefira SBA para acesso à memória quando não for possível parar o core com segurança.
- Muitos MCUs implementam autenticação de debug e estados de ciclo de vida. Se o JTAG parecer inativo, mas a alimentação estiver correta, o dispositivo pode estar com fusíveis configurados para um estado fechado ou exigir uma probe autenticada.

## Defesas e reforço de segurança (o que esperar em dispositivos reais)

- Desative ou bloqueie permanentemente JTAG/SWD na produção (por exemplo, STM32 RDP nível 2, eFuses do ESP que desativam PAD JTAG, APPROTECT/DPAP da NXP/Nordic).
- Exija debug autenticado (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gerenciado pelo OEM), mantendo o acesso de fabricação.
- Evite encaminhar pads de teste de fácil acesso; oculte vias de teste, remova/popule resistores para isolar o TAP e use conectores com chaveamento ou fixtures com pogo pins.
- Bloqueio de debug na inicialização: coloque o TAP atrás da ROM inicial, que impõe o secure boot.

## References

- [1] [Guia do usuário do OpenOCD – comandos e configuração JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG do Espressif ESP32‑S3 (USB‑JTAG, uso do OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – scanner de pinout JTAG baseado em Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
