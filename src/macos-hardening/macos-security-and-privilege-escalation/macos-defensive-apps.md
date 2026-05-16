# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitorizará cada conexión realizada por cada proceso. Dependiendo del modo (permitir conexiones en silencio, denegar conexiones en silencio y alertar) **te mostrará una alerta** cada vez que se establezca una nueva conexión. También tiene una GUI muy buena para ver toda esta información.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall de Objective-See. Este es un firewall básico que te alertará sobre conexiones sospechosas (tiene una GUI pero no es tan elegante como la de Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicación de Objective-See que buscará en varias ubicaciones donde **malware podría estar persistiendo** (es una herramienta de una sola ejecución, no un servicio de monitorización).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Como KnockKnock, pero monitorizando procesos que generan persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicación de Objective-See para encontrar **keyloggers** que instalan "event taps" de teclado

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Sistema de autorización binaria y monitorización para macOS. Usa un cliente de **Endpoint Security** para autorizar eventos **`exec`** antes de que el código se ejecute, por lo que es común en flotas empresariales enfocadas en **allowlisting/denylisting** en lugar de solo detección post-ejecución.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Herramienta de análisis dinámico de macOS tipo Procmon. Ingiere **Endpoint Security telemetry** (procesos, archivos, interprocesos, login y eventos relacionados con XProtect) y es útil para entender qué puede observar realmente un sensor maduro basado en ES.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Herramientas ligeras de Objective-See para telemetría de **process**, **file** y **DNS**. En macOS modernos tienen prerrequisitos extra como **root**, **Terminal Full Disk Access**, o aprobación de **System/Network Extension**. Para más ideas de instrumentación consulta [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

La mayoría de los productos modernos de seguridad para macOS se ejecutan como alguna combinación de **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, y aplicaciones con **Full Disk Access**. Una lista rápida de verificación para operadores:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
Si `systemextensionsctl list` muestra un sensor como **`[activated enabled]`**, normalmente es el indicador más rápido de que la extensión realmente está activa. En **macOS 15 Sequoia y posteriores**, MDM también puede marcar extensiones de seguridad específicas como **no eliminables desde la UI**, así que "desactivarlo desde System Settings" ya no es una suposición segura. Para más detalles internos, consulta [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetría nativa reciente que los defensores pueden consumir

Las versiones recientes de macOS hicieron que algunos bypasses iniciados por el usuario y antes difíciles de detectar fueran mucho más ruidosos para los blue teams:

- **macOS 15+**: Los clientes de Endpoint Security pueden recibir eventos **`gatekeeper_user_override`**, por lo que los bypasses manuales de Gatekeeper pueden registrarse de forma centralizada.
- **Las herramientas actuales de Endpoint Security en macOS** también pueden ingerir eventos de **detección de malware de XProtect**, lo que facilita confirmar lo que Apple ya detectó en el endpoint.
- **macOS 15.4+**: Endpoint Security añade **`tcc_modify`**, lo que por fin da a los defensores una forma compatible de monitorizar **concesiones/revocaciones de TCC** en lugar de extraer logs de depuración de TCC.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Esto es útil tanto para defenders como para red teamers que hacen autoevaluación: si el target tiene una stack madura basada en ES, **las cadenas de bypass de Gatekeeper / TCC aprobadas por el usuario pueden ser mucho más visibles que antes**. Para información general sobre estas protecciones, consulta [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) y [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
