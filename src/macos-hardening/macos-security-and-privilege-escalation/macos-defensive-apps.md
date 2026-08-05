# Aplicaciones defensivas de macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoriza cada conexión realizada por cada proceso. Según el modo (permitir conexiones silenciosamente, denegar conexiones silenciosamente y alertar), **te mostrará una alerta** cada vez que se establezca una nueva conexión. También tiene una GUI muy intuitiva para visualizar toda esta información.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall de Objective-See. Es un firewall básico que te alertará sobre conexiones sospechosas (tiene una GUI, pero no es tan sofisticada como la de Little Snitch).

## Detección de persistencia

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicación de Objective-See que buscará en varias ubicaciones donde **podría persistir el malware** (es una herramienta de ejecución única, no un servicio de monitorización).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Similar a KnockKnock, pero monitoriza los procesos que generan persistencia.

## Detección de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicación de Objective-See para encontrar **keyloggers** que instalan "event taps" del teclado.

## Telemetría de endpoints / control de ejecución

- [**Santa**](https://santa.dev/): Sistema de autorización y monitorización de binarios para macOS. Utiliza un cliente de **Endpoint Security** para autorizar eventos **`exec`** antes de que se ejecute el código, por lo que es común en flotas empresariales centradas en **allowlisting/denylisting** en lugar de únicamente en la detección posterior a la ejecución.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Herramienta de análisis dinámico para macOS similar a Procmon. Ingiere **telemetría de Endpoint Security** (eventos relacionados con procesos, archivos, comunicación entre procesos, inicio de sesión y XProtect) y resulta útil para comprender qué puede observar realmente un sensor ES maduro.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Herramientas ligeras de Objective-See para obtener telemetría de **procesos**, **archivos** y **DNS**. En versiones modernas de macOS tienen requisitos adicionales, como **root**, **Full Disk Access para Terminal** o la aprobación de **System/Network Extension**. Para consultar más ideas de instrumentación, revisa [esta otra página sobre inspección, debugging y fuzzing de aplicaciones de macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triage rápido de herramientas defensivas

La mayoría de los productos de seguridad modernos para macOS se ejecutan como una combinación de **System Extensions / clientes de Endpoint Security**, **agentes/daemons de launchd** y aplicaciones con **Full Disk Access**. Una checklist rápida para el operador:
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
Si `systemextensionsctl list` muestra un sensor como **`[activated enabled]`**, normalmente es el indicador más rápido de que la extensión está realmente activa. En **macOS 15 Sequoia y posteriores**, MDM también puede marcar extensiones de seguridad específicas como **no extraíbles desde la UI**, por lo que "deshabilitarla desde System Settings" ya no es una suposición segura. Para conocer los detalles internos, consulta [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetría nativa reciente que los defensores pueden consumir

Las versiones recientes de macOS han hecho que algunos bypasses iniciados por el usuario, que antes eran molestos de detectar, generen mucho más ruido para los equipos defensivos:

- **macOS 15+**: los clientes de Endpoint Security pueden recibir eventos **`gatekeeper_user_override`**, por lo que los bypasses manuales de Gatekeeper se pueden registrar de forma centralizada.
- Las herramientas actuales de Endpoint Security de macOS también pueden ingerir eventos de detección de malware de **XProtect**, lo que facilita confirmar qué detectó Apple en el endpoint.
- **macOS 15.4+**: Endpoint Security añade **`tcc_modify`**, lo que finalmente proporciona a los defensores una forma compatible de monitorizar **concesiones/revocaciones de TCC** en lugar de extraer logs de depuración de TCC.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Esto resulta útil tanto para defensores como para red teamers que realizan autoevaluaciones: si el objetivo cuenta con un stack basado en ES maduro, **las cadenas de bypass de Gatekeeper / TCC aprobadas por el usuario pueden ser mucho más visibles que antes**. Para obtener información general sobre estas protecciones, consulta [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) y [TCC](macos-security-protections/macos-tcc/README.md).

## Referencias

- [1] [Objective-See - ¡Creer es hacer TCCing! Apple finalmente añade eventos de TCC a Endpoint Security](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Presentamos: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
