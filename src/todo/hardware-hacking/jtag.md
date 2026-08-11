# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** é uma ferramenta que você pode carregar em um MCU compatível com Arduino ou, experimentalmente, em um Raspberry Pi, para fazer brute-force de pinouts JTAG desconhecidos e enumerar registradores de instruções.<sup>[[3]](#references)</sup>

- Arduino: conecte os pinos digitais D2–D11 a até 10 pads/testpoints JTAG suspeitos, e o GND do Arduino ao GND do alvo. Alimente o alvo separadamente, a menos que você saiba que o rail é seguro. Prefira lógica de 3,3 V (por exemplo, Arduino Due) ou use um level shifter/resistores em série ao sondar alvos de 1,8–3,3 V.
- Raspberry Pi: a versão para Pi expõe menos GPIOs utilizáveis (portanto, os scans são mais lentos); consulte o repositório para verificar o pin map e as restrições atuais.

Depois de fazer o flash, abra o monitor serial a 115200 baud e envie `h` para obter ajuda. Fluxo típico:

- `l` encontra loopbacks para evitar false positives
- `r` alterna os pull-ups internos, se necessário
- `s` faz scan em busca de TCK/TMS/TDI/TDO (e, às vezes, TRST/SRST)
- `y` faz brute-force do IR para descobrir opcodes não documentados
- `x` captura um snapshot de boundary-scan dos estados dos pinos

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (774).png>)



Se um TAP válido for encontrado, você verá linhas começando com `FOUND!`, indicando os pinos descobertos.

### Dicas de segurança do JTAGenum

- Sempre compartilhe o ground e nunca aplique aos pinos desconhecidos uma tensão acima do Vtref do alvo. Em caso de dúvida, adicione resistores de 100–470 Ω em série aos pinos candidatos.
- Se o dispositivo usar SWD/SWJ em vez de JTAG de 4 fios, o JTAGenum pode não detectá-lo; tente usar ferramentas SWD ou um adaptador compatível com SWJ-DP.

## Busca mais segura de pinos e configuração de hardware

- Identifique primeiro o Vtref e o GND com um multímetro. Muitos adaptadores precisam do Vtref para definir a tensão de I/O.
- Level shifting: prefira level shifters bidirecionais projetados para sinais push-pull (as linhas JTAG não são open-drain). Evite shifters I2C com direção automática para JTAG.
- Adaptadores úteis: placas FT2232H/FT232H (por exemplo, Tigard), CMSIS-DAP, J-Link, ST-LINK (específico do vendor), ESP-USB-JTAG (em ESP32-Sx). Conecte, no mínimo, TCK, TMS, TDI, TDO, GND e Vtref; opcionalmente, TRST e SRST.

## Primeiro contato com o OpenOCD (scan e IDCODE)

OpenOCD é o OSS de facto para JTAG/SWD. Com um adaptador compatível, você pode fazer scan da chain e ler os IDCODEs:<sup>[[1]](#references)</sup>

- Exemplo genérico com um J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB-JTAG integrado do ESP32‑S3 (não requer probe externo):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notas

- Se você obtiver um IDCODE com "todos os bits 1/0", verifique a fiação, a alimentação, Vtref e se a porta não está bloqueada por fusíveis/option bytes.
- Consulte o `irscan`/`drscan` de baixo nível do OpenOCD para interação manual com o TAP ao inicializar cadeias desconhecidas.<sup>[[1]](#references)</sup>

## Interrompendo a CPU e extraindo a memória/flash

Depois que o TAP for reconhecido e um script de destino for escolhido, você poderá interromper o core e extrair regiões da memória ou a flash interna. Exemplos (ajuste o target, os endereços base e os tamanhos):<sup>[[1]](#references)</sup>

- Target genérico após a inicialização:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefira SBA quando disponível):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar ou ler usando o helper do OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Dicas de Memory Dumping

- Use `mdw/mdh/mdb` para verificar rapidamente a memória antes de fazer dumps longos.
- Para chains com vários dispositivos, defina BYPASS nos alvos que não serão usados ou use um board file que defina todos os TAPs.

## Técnicas de boundary-scan (EXTEST/SAMPLE)

Mesmo quando o acesso de debug da CPU está bloqueado, o boundary-scan ainda pode estar exposto. Com UrJTAG/OpenOCD, você pode:<sup>[[1]](#references)</sup>
- Usar SAMPLE para capturar o estado dos pinos enquanto o sistema está em execução (encontrar atividade no barramento e confirmar o mapeamento dos pinos).
- Usar EXTEST para controlar os pinos (por exemplo, fazer bit-bang das linhas de uma flash SPI externa por meio do MCU para lê-la offline, se a fiação da placa permitir).

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
Você precisa do BSDL do dispositivo para conhecer a ordem dos bits do boundary register. Tenha cuidado, pois alguns fabricantes bloqueiam as boundary-scan cells em produção.

## Alvos modernos e observações

- ESP32‑S3/C3 incluem uma USB‑JTAG bridge nativa; o OpenOCD pode se comunicar diretamente via USB sem uma probe externa. Muito conveniente para triagem e dumps.<sup>[[2]](#references)</sup>
- O RISC‑V debug (v0.13+) é amplamente compatível com o OpenOCD; prefira SBA para acesso à memória quando o core não puder ser interrompido com segurança.
- Muitos MCUs implementam autenticação de debug e estados de ciclo de vida. Se o JTAG parecer inativo, mas a alimentação estiver correta, o dispositivo pode estar configurado por fuses para um estado fechado ou exigir uma probe autenticada.

## Defesas e hardening (o que esperar em dispositivos reais)

- Desabilitar permanentemente ou bloquear JTAG/SWD em produção (por exemplo, STM32 RDP level 2, eFuses do ESP que desabilitam PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Exigir debug autenticado (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response gerenciado pelo OEM) mantendo o acesso de manufacturing.
- Não encaminhar test pads fáceis de acessar; ocultar test vias, remover/instalar resistores para isolar o TAP e usar conectores com keying ou fixtures com pogo pins.
- Bloqueio de debug na inicialização: proteger o TAP atrás da ROM inicial, que impõe secure boot.

## References

- [1] [Guia do usuário do OpenOCD – comandos e configuração do JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG do Espressif ESP32‑S3 (USB‑JTAG, uso do OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – scanner de pinout JTAG baseado em Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
