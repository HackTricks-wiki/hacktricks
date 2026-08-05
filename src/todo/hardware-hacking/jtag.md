# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) é uma ferramenta que você pode carregar em um MCU compatível com Arduino ou, experimentalmente, em um Raspberry Pi para fazer brute-force de pinouts JTAG desconhecidos e até enumerar registradores de instruções.

- Arduino: conecte os pinos digitais D2–D11 a até 10 pads/testpoints JTAG suspeitos e o GND do Arduino ao GND do alvo. Alimente o alvo separadamente, a menos que você saiba que o rail é seguro. Prefira lógica de 3,3 V (por exemplo, Arduino Due) ou use um conversor de nível/resistores em série ao testar alvos de 1,8–3,3 V.
- Raspberry Pi: a versão para Pi expõe menos GPIOs utilizáveis (portanto, os scans são mais lentos); consulte o repositório para verificar o mapa de pinos e as restrições atuais.

Depois de gravar o firmware, abra o monitor serial a 115200 baud e envie `h` para obter ajuda. Fluxo típico:

- `l` encontra loopbacks para evitar falsos positivos
- `r` alterna os pull-ups internos, se necessário
- `s` faz o scan de TCK/TMS/TDI/TDO (e, às vezes, TRST/SRST)
- `y` faz brute-force do IR para descobrir opcodes não documentados
- `x` captura um snapshot de boundary-scan dos estados dos pinos

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot de boundary-scan dos estados dos pinos](<../../images/image (774).png>)



Se um TAP válido for encontrado, você verá linhas começando com `FOUND!`, indicando os pinos descobertos.

Dicas
- Sempre compartilhe o terra e nunca acione pinos desconhecidos acima do Vtref do alvo. Em caso de dúvida, adicione resistores de 100–470 Ω em série nos pinos candidatos.
- Se o dispositivo usar SWD/SWJ em vez de JTAG de 4 fios, o JTAGenum poderá não detectá-lo; tente ferramentas SWD ou um adaptador compatível com SWJ-DP.

## Busca mais segura de pinos e configuração do hardware

- Identifique primeiro o Vtref e o GND com um multímetro. Muitos adaptadores precisam do Vtref para definir a tensão de I/O.
- Conversão de nível: prefira conversores de nível bidirecionais projetados para sinais push-pull (as linhas JTAG não são open-drain). Evite conversores I2C de direção automática para JTAG.
- Adaptadores úteis: placas FT2232H/FT232H (por exemplo, Tigard), CMSIS-DAP, J-Link, ST-LINK (específico do fabricante), ESP-USB-JTAG (em ESP32-Sx). Conecte, no mínimo, TCK, TMS, TDI, TDO, GND e Vtref; opcionalmente, TRST e SRST.

## Primeiro contato com o OpenOCD (scan e IDCODE)

OpenOCD é o OSS de facto para JTAG/SWD. Com um adaptador compatível, você pode fazer o scan da cadeia e ler os IDCODEs:

- Exemplo genérico com um J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB‑JTAG integrado do ESP32‑S3 (não requer probe externo):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notas
- Se você obtiver um IDCODE com "todos os uns/zeros", verifique a fiação, a alimentação, o Vtref e se a porta não está bloqueada por fusíveis/bytes de opção.
- Consulte o `irscan`/`drscan` de baixo nível do OpenOCD para a interação manual com o TAP ao inicializar chains desconhecidas.<sup>[[1]](#references)</sup>

## Parando a CPU e fazendo dump da memória/flash

Depois que o TAP for reconhecido e um script de target for escolhido, você poderá parar o core e fazer dump de regiões de memória ou da flash interna. Exemplos (ajuste o target, os endereços-base e os tamanhos):

- Target genérico após a inicialização:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferir SBA quando disponível):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar ou ler via o helper do OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Dicas
- Use `mdw/mdh/mdb` para verificar a memória antes de dumps longos.
- Para cadeias com vários dispositivos, defina BYPASS nos alvos que não serão utilizados ou use um arquivo de placa que defina todos os TAPs.

## Truques de boundary-scan (EXTEST/SAMPLE)

Mesmo quando o acesso de debug da CPU está bloqueado, o boundary-scan ainda pode estar exposto. Com UrJTAG/OpenOCD, você pode:
- Usar SAMPLE para capturar o estado dos pinos enquanto o sistema está em execução (encontrar atividade no barramento e confirmar o mapeamento dos pinos).
- Usar EXTEST para controlar os pinos (por exemplo, fazer bit-banging nas linhas de uma memória flash SPI externa por meio do MCU para lê-la offline, se a fiação da placa permitir).

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
Você precisa do BSDL do dispositivo para conhecer a ordenação dos bits do boundary register. Tenha cuidado, pois alguns fabricantes bloqueiam as células de boundary-scan em produção.

## Targets modernos e observações

- ESP32-S3/C3 incluem uma ponte USB-JTAG nativa; o OpenOCD pode se comunicar diretamente via USB sem um probe externo. Muito conveniente para triagem e dumps.<sup>[[2]](#references)</sup>
- O debug RISC-V (v0.13+) é amplamente suportado pelo OpenOCD; prefira SBA para acesso à memória quando o core não puder ser interrompido com segurança.
- Muitos MCUs implementam autenticação de debug e estados de ciclo de vida. Se o JTAG parecer inativo, mas a alimentação estiver correta, o dispositivo pode estar configurado com fuses para um estado fechado ou exigir um probe autenticado.

## Defesas e hardening (o que esperar em dispositivos reais)

- Desabilite ou bloqueie permanentemente o JTAG/SWD em produção (por exemplo, STM32 RDP nível 2, eFuses do ESP que desabilitam o PAD JTAG, APPROTECT/DPAP da NXP/Nordic).
- Exija debug autenticado (ARMv8.2-A ADIv6 Debug Authentication, challenge-response gerenciado pelo OEM), mantendo o acesso de fabricação.
- Não roteie test pads fáceis de acessar; enterre as vias de teste, remova/popule resistores para isolar o TAP e use conectores com chaveamento ou fixtures com pogo pins.
- Bloqueio de debug na inicialização: coloque o TAP atrás de uma ROM inicial que imponha o secure boot.

## Referências

- [1] [Guia do usuário do OpenOCD – comandos e configuração do JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debug JTAG do Espressif ESP32-S3 (USB-JTAG, uso do OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
