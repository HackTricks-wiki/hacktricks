# Extracción de configuración y TTPs de AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 es un framework modular y open-source de post-exploitation/C2 con beacons de Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) y soporte para BOF. Esta página documenta:
- Cómo está integrada su configuración empaquetada con RC4 y cómo extraerla de los beacons
- Indicadores de red/perfil para listeners HTTP/SMB/TCP
- TTPs comunes de loaders y persistence observados in the wild, con enlaces a páginas relevantes sobre técnicas de Windows

Las versiones recientes upstream también incluyen listeners de beacon DNS/DoH y la familia independiente de agentes/listeners Gopher, por lo que la infraestructura moderna de Adaptix puede exponer más superficies que las HTTP/SMB/TCP originales, incluso cuando un sample específico todavía utiliza el agente de beacon clásico.

## Perfiles y campos de los beacons

AdaptixC2 admite tres tipos principales de beacon:
- BEACON_HTTP: web C2 con servers/ports, SSL, method, URI, headers, user-agent y un nombre de parámetro personalizado configurables
- BEACON_SMB: C2 peer-to-peer mediante named-pipe (intranet)
- BEACON_TCP: direct sockets, opcionalmente con un marker antepuesto para ofuscar el inicio del protocolo

Estos son los layouts de beacon documentados públicamente en los primeros análisis de Adaptix y todavía son el punto de partida más común para la extracción desde samples. Sin embargo, las builds actuales upstream también incluyen los extenders `BeaconDNS` y Gopher en el lado del server, por lo que no se debe asumir que cada deployment activo de Adaptix expone únicamente infraestructura HTTP/SMB/TCP.

Campos de perfil típicos observados en las configuraciones de beacons HTTP (después del descifrado):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – utilizados para analizar los tamaños de las respuestas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Las builds recientes de BeaconHTTP también admiten la rotación seleccionada por el operador entre múltiples URIs, user-agents, headers Host y servers, con selección secuencial o aleatoria. Desde la perspectiva de hunting, esto significa que un único host infectado puede distribuir sus conexiones entre varias rutas de callback y combinaciones de headers sin dejar de pertenecer a la familia clásica de beacons empaquetados con RC4.

Ejemplo de perfil HTTP predeterminado (de una build de beacon):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["172.16.196.1"],
"ports": [4443],
"http_method": "POST",
"uri": "/uri.php",
"parameter": "X-Beacon-Id",
"user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 2,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
Perfil HTTP malicioso observado (ataque real):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["tech-system[.]online"],
"ports": [443],
"http_method": "POST",
"uri": "/endpoint/api",
"parameter": "X-App-Id",
"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 4,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
## Empaquetado de configuración cifrada y ruta de carga

Cuando el operador hace clic en Create en el builder, AdaptixC2 inserta el perfil cifrado como un bloque final en el beacon. El formato es:
- 4 bytes: tamaño de la configuración (uint32, little-endian)
- N bytes: datos de configuración cifrados con RC4
- 16 bytes: clave RC4

El loader del beacon copia la clave de 16 bytes desde el final y descifra con RC4 el bloque de N bytes in situ:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicaciones prácticas:
- Toda la estructura suele encontrarse dentro de la sección PE .rdata.
- La extracción es determinista: leer el tamaño, leer el ciphertext de ese tamaño, leer la clave de 16 bytes colocada inmediatamente después y, a continuación, aplicar RC4 para descifrar.

## Flujo de trabajo de extracción de la configuración (defenders)

Escribe un extractor que imite la lógica del beacon:
1) Localiza el blob dentro del PE (normalmente .rdata). Un enfoque pragmático consiste en buscar en .rdata una disposición plausible [size|ciphertext|16‑byte key] e intentar aplicar RC4.
2) Lee los primeros 4 bytes → size (uint32 LE).
3) Lee los siguientes N=size bytes → ciphertext.
4) Lee los últimos 16 bytes → RC4 key.
5) Aplica RC4 para descifrar el ciphertext. Después, analiza el perfil en texto plano como:
- escalares u32/boolean, según lo indicado anteriormente
- strings con longitud prefijada (longitud u32 seguida de bytes; puede haber un NUL final)
- arrays: servers_count seguido de esa cantidad de pares [string, u32 port]

Proof-of-concept mínimo en Python (independiente, sin dependencias externas) que funciona con un blob previamente extraído:
```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
S = list(range(256))
j = 0
for i in range(256):
j = (j + S[i] + key[i % len(key)]) & 0xFF
S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for b in data:
i = (i + 1) & 0xFF
j = (j + S[i]) & 0xFF
S[i], S[j] = S[j], S[i]
K = S[(S[i] + S[j]) & 0xFF]
out.append(b ^ K)
return bytes(out)

class P:
def __init__(self, buf: bytes):
self.b = buf; self.o = 0
def u32(self) -> int:
v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
def u8(self) -> int:
v = self.b[self.o]; self.o += 1; return v
def s(self) -> str:
L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
p = P(plain)
cfg = {}
cfg['agent_type']    = p.u32()
cfg['use_ssl']       = bool(p.u8())
n                    = p.u32()
cfg['servers']       = []
cfg['ports']         = []
for _ in range(n):
cfg['servers'].append(p.s())
cfg['ports'].append(p.u32())
cfg['http_method']   = p.s()
cfg['uri']           = p.s()
cfg['parameter']     = p.s()
cfg['user_agent']    = p.s()
cfg['http_headers']  = p.s()
cfg['ans_pre_size']  = p.u32()
cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
cfg['kill_date']     = p.u32()
cfg['working_time']  = p.u32()
cfg['sleep_delay']   = p.u32()
cfg['jitter_delay']  = p.u32()
cfg['listener_type'] = 0
cfg['download_chunk_size'] = 0x19000
return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```
Consejos:
- Al automatizar, usa un parser de PE para leer `.rdata` y aplica una ventana deslizante: para cada offset o, prueba `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, clave candidata = los siguientes 16 bytes; descifra con RC4 y comprueba que los campos de texto se decodifiquen como UTF-8 y que las longitudes sean razonables.
- Analiza los perfiles SMB/TCP siguiendo las mismas convenciones con longitud prefijada.

## Perfiles de listener personalizados: no codifiques únicamente el esquema HTTP clásico

El formato de empaquetado externo (`u32 size | RC4 ciphertext | 16-byte key`) es reutilizable, por lo que los listeners personalizados por el actor pueden mantener el mismo flujo de extracción y cambiar por completo el diseño de los campos descifrados.

Un buen ejemplo reciente es la campaña de Tropic Trooper de abril de 2026, en la que el beacon de Adaptix extraído no contenía un perfil HTTP/TCP estándar. En su lugar, el blob descifrado almacenaba parámetros de transporte de GitHub, como:
- `repo_owner`
- `repo_name`
- `api_host` (por ejemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estrategia práctica para el parser:
- Primero detecta el blob RC4 externo exactamente como de costumbre.
- Tras el descifrado, decide según strings centinela y la validez de los campos, en lugar de forzar inmediatamente el parser HTTP.
- Entre los buenos centinelas se incluyen `api.github.com`, `/issues?state=open`, verbos/URI HTTP, strings con formato de named pipe o arrays de servidor/puerto claramente válidos.
- Si el parser HTTP falla pero el texto plano contiene strings UTF-8 coherentes con longitud prefijada, conserva la muestra e intenta esquemas alternativos en lugar de descartarla como un falso positivo.

En esa campaña, el listener personalizado usaba GitHub issues como transporte C2, y el beacon consultaba `ipinfo.io` para conocer su IP externa, ya que la API de GitHub no revela directamente al operador la dirección de origen de la víctima.

## Fingerprinting y hunting de red

HTTP
- Común: POST a URI seleccionadas por el operador (por ejemplo, `/uri.php`, `/endpoint/api`)
- Parámetro de header personalizado usado para el ID del beacon (por ejemplo, `X‑Beacon‑Id`, `X‑App‑Id`)
- User-agents que imitan Firefox 20 o versiones contemporáneas de Chrome
- Cadencia de polling visible mediante `sleep_delay`/`jitter_delay`
- Las versiones más recientes pueden rotar URI, user-agents, headers `Host` y servidores entre callbacks, por lo que conviene agrupar según nombres de headers poco comunes, patrones de tamaño de respuesta, reutilización de TLS y temporización, en lugar de asumir un único par de ruta/UA

SMB/TCP
- Listeners de named pipe SMB para C2 en intranets donde la salida web está restringida
- Los beacons TCP pueden anteponer algunos bytes al tráfico para ofuscar el inicio del protocolo

Valores predeterminados actuales del teamserver upstream
- `profile.yaml` incluye actualmente el teamserver `0.0.0.0:4321`, el endpoint `/endpoint`, los nombres de archivo del certificado/clave `server.rsa.crt` y `server.rsa.key`, y extenders para HTTP, SMB, TCP, DNS, Beacon agent y Gopher
- En las rutas no coincidentes, el handler de error predeterminado devuelve `Server: AdaptixC2` y `Adaptix-Version: v1.2`
- El body 404 estándar contiene `AdaptixC2 404` y `You need to enter the correct connection details.`
- Los scans de todo Internet realizados en 2026 encontraron muchos teamservers expuestos en `4321` y muchos listeners de beacon en `43211`, por lo que ambos puertos son pivotes iniciales útiles, pero no deben considerarse exhaustivos

Fingerprints de listeners DNS/DoH
- El extender BeaconDNS actual responde de forma autoritativa (`AA=true`)
- Las queries que no coinciden con la estructura del protocolo del beacon —en particular, nombres con menos de 5 labels antes del dominio configurado— suelen recibir como respuesta `TXT "OK"`
- Si el TTL base configurado se deja en cero, el listener usa una base de 10 segundos y añade hasta 59 segundos de jitter
- Esto hace que las sondas activas con pocos labels sean útiles cuando no hay ningún listener HTTP expuesto

## TTPs de loader y persistencia observadas en incidentes

Loaders de PowerShell en memoria
- Descargan payloads Base64/XOR (`Invoke‑RestMethod` / WebClient)
- Asignan memoria no administrada, copian shellcode y cambian la protección a `0x40` (`PAGE_EXECUTE_READWRITE`) mediante `VirtualProtect`
- Ejecutan mediante invocación dinámica de .NET: `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`

Loaders de shellcode por etapas / software firmado troyanizado
- Una cadena de Tropic Trooper de 2026 usó un ejecutable SumatraPDF troyanizado (loader TOSHIS) que redirigía `_security_init_cookie` hacia código malicioso en lugar de parchear el entry point del PE
- El loader resolvía APIs mediante hashing Adler-32, descargaba un PDF señuelo, obtenía shellcode de segunda etapa, lo descifraba con AES-128-CBC mediante WinCrypt (`CryptDeriveKey` a partir de una seed hardcoded) y ejecutaba reflectivamente un beacon de Adaptix en memoria
- Posteriormente, la persistencia pasó a tareas programadas con nombres aparentemente legítimos como `\MSDNSvc` o `\MicrosoftUDN`, configuradas para volver a lanzar el agent aproximadamente cada dos horas

Consulta estas páginas para conocer la ejecución en memoria y las consideraciones de AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistencia observados
- Acceso directo de la carpeta de Startup (`.lnk`) para volver a lanzar un loader al iniciar sesión
- Claves Registry Run (`HKCU/HKLM ...\CurrentVersion\Run`), a menudo con nombres aparentemente legítimos como `"Updater"` para iniciar `loader.ps1`
- DLL search-order hijacking colocando `msimg32.dll` bajo `%APPDATA%\Microsoft\Windows\Templates` para procesos susceptibles

Análisis detallados y comprobaciones de la técnica:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideas para hunting
- PowerShell generando transiciones RW→RX: `VirtualProtect` a `PAGE_EXECUTE_READWRITE` dentro de `powershell.exe`
- Patrones de invocación dinámica (`GetDelegateForFunctionPointer`)
- Respuestas HTTPS 404 no coincidentes con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details.`
- Respuestas DNS con `AA=true` y `TXT "OK"` para queries cortas bajo dominios sospechosos
- Tráfico de la API de GitHub a `/repos/<owner>/<repo>/issues` seguido de consultas a `ipinfo.io` desde la misma cadena de loader/beacon
- `.lnk` de Startup bajo las carpetas Startup del usuario o comunes
- Claves Run sospechosas (por ejemplo, `"Updater"`) y nombres de loader como `update.ps1`/`loader.ps1`
- Muestras de PE troyanizadas que redirigen `_security_init_cookie` hacia código downloader antes de mostrar un documento señuelo
- Rutas de DLL modificables por el usuario bajo `%APPDATA%\Microsoft\Windows\Templates` que contienen `msimg32.dll`

## Notas sobre los campos de OpSec

- KillDate: timestamp después del cual el agent se autoexpira
- WorkingTime: horas durante las que el agent debe estar activo para mezclarse con la actividad empresarial

Estos campos pueden usarse para el clustering y para explicar periodos de inactividad observados.

## YARA y pistas estáticas

Unit 42 publicó reglas YARA básicas para beacons (C/C++ y Go) y constantes de API hashing de loaders. Considera complementarlas con reglas que busquen el diseño `[size|ciphertext|16-byte-key]` cerca del final de `.rdata` del PE, los strings del perfil HTTP predeterminado y markers más recientes de servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.

## Referencias

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
