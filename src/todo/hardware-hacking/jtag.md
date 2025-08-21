# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) é uma ferramenta que você pode carregar em um MCU compatível com Arduino ou (experimentalmente) em um Raspberry Pi para forçar a descoberta de pinagens JTAG desconhecidas e até enumerar registradores de instrução.

- Arduino: conecte os pinos digitais D2–D11 a até 10 pads/testpoints JTAG suspeitos, e o GND do Arduino ao GND do alvo. Alimente o alvo separadamente, a menos que você saiba que a linha é segura. Prefira lógica de 3,3 V (por exemplo, Arduino Due) ou use um conversor de nível/resistores em série ao sondar alvos de 1,8–3,3 V.
- Raspberry Pi: a construção do Pi expõe menos GPIOs utilizáveis (portanto, as varreduras são mais lentas); verifique o repositório para o mapa de pinos atual e restrições.

Uma vez gravado, abra o monitor serial a 115200 baud e envie `h` para ajuda. Fluxo típico:

- `l` encontrar loopbacks para evitar falsos positivos
- `r` alternar pull‑ups internos se necessário
- `s` escanear para TCK/TMS/TDI/TDO (e às vezes TRST/SRST)
- `y` forçar IR para descobrir opcodes não documentados
- `x` instantâneo de boundary‑scan dos estados dos pinos

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Se um TAP válido for encontrado, você verá linhas começando com `FOUND!` indicando pinos descobertos.

Dicas
- Sempre compartilhe o terra e nunca acione pinos desconhecidos acima do Vtref do alvo. Se tiver dúvidas, adicione resistores em série de 100–470 Ω nos pinos candidatos.
- Se o dispositivo usar SWD/SWJ em vez de JTAG de 4 fios, o JTAGenum pode não detectá-lo; tente ferramentas SWD ou um adaptador que suporte SWJ‑DP.

## Caça a pinos mais segura e configuração de hardware

- Identifique Vtref e GND primeiro com um multímetro. Muitos adaptadores precisam de Vtref para definir a tensão de I/O.
- Conversão de nível: prefira conversores de nível bidirecionais projetados para sinais push‑pull (as linhas JTAG não são open‑drain). Evite conversores I2C de direção automática para JTAG.
- Adaptadores úteis: placas FT2232H/FT232H (por exemplo, Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (específicos do fornecedor), ESP‑USB‑JTAG (no ESP32‑Sx). Conecte no mínimo TCK, TMS, TDI, TDO, GND e Vtref; opcionalmente TRST e SRST.

## Primeiro contato com OpenOCD (varredura e IDCODE)

OpenOCD é o OSS de fato para JTAG/SWD. Com um adaptador suportado, você pode escanear a cadeia e ler IDCODEs:

- Exemplo genérico com um J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG embutido (nenhuma sonda externa necessária):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notas
- Se você receber um IDCODE "todos uns/zeros", verifique a fiação, a energia, o Vtref e se a porta não está bloqueada por fusíveis/opções de bytes.
- Veja OpenOCD `irscan`/`drscan` de baixo nível para interação manual com TAP ao iniciar cadeias desconhecidas.

## Parando a CPU e despejando memória/flash

Uma vez que o TAP é reconhecido e um script de destino é escolhido, você pode parar o núcleo e despejar regiões de memória ou flash interno. Exemplos (ajuste o alvo, endereços base e tamanhos): 

- Alvo genérico após a inicialização:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefira SBA quando disponível):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programar ou ler via helper OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Use `mdw/mdh/mdb` para verificar a integridade da memória antes de dumps longos.
- Para cadeias de múltiplos dispositivos, defina BYPASS em não-alvos ou use um arquivo de placa que defina todos os TAPs.

## Truques de boundary-scan (EXTEST/SAMPLE)

Mesmo quando o acesso de depuração da CPU está bloqueado, o boundary-scan ainda pode estar exposto. Com UrJTAG/OpenOCD você pode:
- SAMPLE para capturar estados dos pinos enquanto o sistema está em execução (encontrar atividade no barramento, confirmar mapeamento de pinos).
- EXTEST para acionar pinos (por exemplo, bit-bang linhas SPI externas via o MCU para lê-las offline se a fiação da placa permitir).

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
Você precisa do BSDL do dispositivo para conhecer a ordem dos bits do registrador de limite. Cuidado, pois alguns fornecedores bloqueiam células de boundary-scan na produção.

## Alvos modernos e notas

- ESP32‑S3/C3 incluem uma ponte USB‑JTAG nativa; OpenOCD pode se comunicar diretamente via USB sem uma sonda externa. Muito conveniente para triagem e dumps.
- O debug RISC‑V (v0.13+) é amplamente suportado pelo OpenOCD; prefira SBA para acesso à memória quando o núcleo não puder ser interrompido com segurança.
- Muitos MCUs implementam autenticação de debug e estados de ciclo de vida. Se o JTAG parecer morto, mas a energia estiver correta, o dispositivo pode estar fundido em um estado fechado ou requerer uma sonda autenticada.

## Defesas e endurecimento (o que esperar em dispositivos reais)

- Desative permanentemente ou bloqueie JTAG/SWD na produção (por exemplo, nível 2 RDP STM32, eFuses ESP que desativam PAD JTAG, APPROTECT/DPAP NXP/Nordic).
- Exija autenticação de debug (ARMv8.2‑A ADIv6 Autenticação de Debug, desafio-resposta gerenciado por OEM) enquanto mantém o acesso de fabricação.
- Não roteie pads de teste fáceis; enterre vias de teste, remova/popule resistores para isolar TAP, use conectores com chaves ou fixações de pinos pogo.
- Bloqueio de debug na inicialização: proteja o TAP atrás de um ROM inicial que impõe o boot seguro.

## Referências

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
