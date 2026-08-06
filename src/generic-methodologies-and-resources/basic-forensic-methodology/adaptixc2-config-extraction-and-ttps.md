# Extracción de configuración y TTPs de AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 es un framework modular y open-source de post-exploitation/C2 con beacons de Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) y soporte para BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Cómo está integrada su configuración empaquetada con RC4 y cómo extraerla de los beacons
- Indicadores de red/perfil para listeners HTTP/SMB/TCP
- TTPs comunes de loaders y persistence observados en la naturaleza, con enlaces a páginas relevantes de técnicas de Windows

Las versiones upstream recientes también incluyen listeners de beacon DNS/DoH y la familia independiente de agentes/listeners Gopher, por lo que la infraestructura moderna de Adaptix puede exponer más que las superficies HTTP/SMB/TCP originales, incluso cuando una muestra específica todavía utiliza el agente beacon clásico.<sup>[[2]](#references)[[3]](#references)</sup>

## Perfiles y campos de los beacons

AdaptixC2 admite tres tipos principales de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web con servidores/puertos/SSL configurables, método, URI, headers, user-agent y un nombre de parámetro personalizado
- BEACON_SMB: C2 peer-to-peer mediante named pipe (intranet)
- BEACON_TCP: sockets directos, opcionalmente con un marker antepuesto para ofuscar el inicio del protocolo

Estos layouts de beacon están documentados públicamente en análisis iniciales de Adaptix y siguen siendo el punto de partida más común para la extracción desde muestras.<sup>[[1]](#references)</sup> Sin embargo, las builds actuales upstream también incluyen los extenders `BeaconDNS` y Gopher en el servidor, por lo que no debe asumirse que todas las implementaciones activas de Adaptix exponen únicamente infraestructura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campos de perfil típicos observados en las configuraciones de beacons HTTP (después del descifrado):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – utilizados para analizar los tamaños de las respuestas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Las builds recientes de BeaconHTTP también admiten la rotación seleccionada por el operador entre varias URIs, user-agents, headers Host y servidores, con selección secuencial o aleatoria.<sup>[[2]](#references)</sup> Desde la perspectiva de hunting, esto significa que un único host infectado puede distribuir sus conexiones entre varias rutas de callback y combinaciones de headers sin abandonar la familia clásica de beacons empaquetados con RC4.

Ejemplo de perfil HTTP predeterminado (de una build de beacon):<sup>[[1]](#references)</sup>
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
Perfil HTTP malicioso observado (ataque real):<sup>[[1]](#references)</sup>
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
## Empaquetado de la configuración cifrada y ruta de carga

Cuando el operador hace clic en Create en el builder, AdaptixC2 inserta el profile cifrado como un blob final en el beacon. El formato es:<sup>[[1]](#references)</sup>
- 4 bytes: tamaño de la configuración (uint32, little-endian)
- N bytes: datos de configuración cifrados con RC4
- 16 bytes: clave RC4

El loader del beacon copia la clave de 16 bytes del final y descifra con RC4 el bloque de N bytes in situ:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicaciones prácticas:<sup>[[1]](#references)</sup>
- Toda la estructura suele encontrarse dentro de la sección PE .rdata.
- La extracción es determinista: leer el tamaño, leer el ciphertext de ese tamaño, leer la clave de 16 bytes colocada inmediatamente después y, a continuación, descifrar con RC4.

## Flujo de extracción de la configuración (defenders)

Escribe un extractor que imite la lógica del beacon:<sup>[[1]](#references)</sup>
1) Localiza el blob dentro del PE (normalmente en .rdata). Un enfoque pragmático consiste en buscar en .rdata una disposición plausible de [size|ciphertext|16-byte key] e intentar RC4.
2) Lee los primeros 4 bytes → size (uint32 LE).
3) Lee los siguientes N=size bytes → ciphertext.
4) Lee los últimos 16 bytes → clave RC4.
5) Descifra el ciphertext con RC4. A continuación, analiza el perfil en claro como:
- escalares u32/boolean, según lo indicado anteriormente
- strings con longitud prefijada (longitud u32 seguida de bytes; puede haber un NUL final)
- arrays: servers_count seguido de esa cantidad de pares [string, u32 port]

Prueba de concepto mínima en Python (independiente, sin dependencias externas) que funciona con un blob extraído previamente:
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
- Analiza los perfiles SMB/TCP siguiendo las mismas convenciones de longitud prefijada.

## Perfiles de listener personalizados: no codifiques únicamente el esquema HTTP clásico

El formato de empaquetado externo (`u32 size | RC4 ciphertext | 16-byte key`) es reutilizable, por lo que los listeners personalizados por el actor pueden mantener el mismo flujo de extracción y cambiar completamente el diseño de los campos descifrados.

Un buen ejemplo reciente es la campaña de Tropic Trooper de abril de 2026, en la que el beacon de Adaptix extraído no contenía un perfil HTTP/TCP estándar. En su lugar, el blob descifrado almacenaba parámetros de transporte de GitHub, como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por ejemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estrategia práctica para el parser:
- Primero detecta el blob RC4 externo exactamente como de costumbre.
- Después del descifrado, decide según cadenas centinela y la validez de los campos, en lugar de forzar inmediatamente el parser HTTP.
- Entre los buenos centinelas se incluyen `api.github.com`, `/issues?state=open`, verbos/URI HTTP, cadenas con formato de named pipe o arrays de servidor/puerto claramente válidos.
- Si el parser HTTP falla, pero el texto plano contiene cadenas UTF-8 coherentes con longitud prefijada, conserva la muestra e intenta esquemas alternativos en lugar de descartarla como un false positive.

En esa campaña, el listener personalizado usaba GitHub issues como transporte C2, y el beacon consultaba `ipinfo.io` para conocer su IP externa, ya que la API de GitHub no revela directamente al operador la dirección de origen de la víctima.<sup>[[5]](#references)</sup>

## Fingerprinting y hunting de red

HTTP<sup>[[1]](#references)</sup>
- Común: POST a URI seleccionadas por el operador (por ejemplo, `/uri.php`, `/endpoint/api`)
- Parámetro de header personalizado utilizado para el ID del beacon (por ejemplo, `X-Beacon-Id`, `X-App-Id`)
- User-agents que imitan Firefox 20 o versiones contemporáneas de Chrome
- Cadencia de polling visible mediante `sleep_delay`/`jitter_delay`
- Las versiones más recientes pueden rotar URI, user-agents, headers Host y servidores entre callbacks, por lo que conviene agrupar según nombres de headers poco comunes, patrones de tamaño de respuesta, reutilización de TLS y tiempos, en lugar de asumir un único par de ruta/UA<sup>[[2]](#references)</sup>

SMB/TCP<sup>[[1]](#references)</sup>
- Listeners de named pipe SMB para C2 en intranets donde la salida web está restringida
- Los beacons TCP pueden anteponer algunos bytes al tráfico para ofuscar el inicio del protocolo

Valores predeterminados actuales del teamserver upstream
- `profile.yaml` incluye actualmente el teamserver `0.0.0.0:4321`, el endpoint `/endpoint`, los nombres de archivo de certificado/clave `server.rsa.crt` y `server.rsa.key`, y extenders para HTTP, SMB, TCP, DNS, Beacon agent y Gopher<sup>[[2]](#references)</sup>
- En rutas no coincidentes, el handler de error predeterminado devuelve `Server: AdaptixC2` y `Adaptix-Version: v1.2`<sup>[[4]](#references)</sup>
- El body 404 estándar contiene `AdaptixC2 404` y `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- Los scans a escala de Internet realizados en 2026 encontraron muchos teamservers expuestos en `4321` y muchos listeners de beacon en `43211`, por lo que ambos puertos son pivots iniciales útiles, pero no deben considerarse exhaustivos<sup>[[4]](#references)</sup>

Fingerprints de listeners DNS/DoH<sup>[[4]](#references)</sup>
- El extender BeaconDNS actual responde autoritativamente (`AA=true`)
- Las consultas que no coinciden con la estructura del protocolo del beacon —en particular, nombres con menos de 5 labels antes del dominio configurado— suelen responderse con `TXT "OK"`
- Si el TTL base configurado se deja en cero, el listener utiliza una base de 10 segundos y añade hasta 59 segundos de jitter
- Esto hace que los active probes con labels cortos sean útiles cuando no hay ningún listener HTTP expuesto

## TTPs de loader y persistence observadas en incidentes

Loaders de PowerShell en memoria<sup>[[1]](#references)</sup>
- Descargan payloads Base64/XOR (`Invoke-RestMethod` / `WebClient`)<sup>[[9]](#references)</sup>
- Reservan memoria no administrada, copian shellcode y cambian la protección a 0x40 (PAGE_EXECUTE_READWRITE) mediante `VirtualProtect`<sup>[[7]](#references)</sup>
- Ejecutan mediante invocación dinámica de .NET: `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`<sup>[[6]](#references)</sup>

Loaders de shellcode por etapas / software firmado troyanizado<sup>[[5]](#references)</sup>
- Una cadena de Tropic Trooper de 2026 utilizó un ejecutable SumatraPDF troyanizado (loader TOSHIS) que redirigía `_security_init_cookie` hacia código malicioso en lugar de modificar el entry point del PE
- El loader resolvía APIs mediante hashing Adler-32, descargaba un PDF señuelo, obtenía shellcode de segunda etapa, lo descifraba con AES-128-CBC mediante WinCrypt (`CryptDeriveKey` a partir de un seed hardcodeado) y ejecutaba reflectivamente un beacon de Adaptix en memoria
- La persistence pasó posteriormente a scheduled tasks con nombres de apariencia legítima como `\MSDNSvc` o `\MicrosoftUDN`, configuradas para volver a lanzar el agent aproximadamente cada dos horas

Consulta estas páginas para obtener información sobre ejecución en memoria y consideraciones de AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistence observados<sup>[[1]](#references)</sup>
- Acceso directo (.lnk) en la Startup folder para volver a lanzar un loader durante el logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), a menudo con nombres de apariencia legítima como "Updater" para iniciar `loader.ps1`<sup>[[10]](#references)</sup>
- DLL search-order hijack colocando `msimg32.dll` bajo `%APPDATA%\Microsoft\Windows\Templates` para procesos vulnerables

Análisis detallados de técnicas y comprobaciones:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideas para hunting
- Procesos de PowerShell que generan transiciones RW→RX: `VirtualProtect` hacia `PAGE_EXECUTE_READWRITE` dentro de `powershell.exe`<sup>[[8]](#references)</sup>
- Patrones de invocación dinámica (`GetDelegateForFunctionPointer`)
- Respuestas HTTPS 404 no coincidentes con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- Respuestas DNS con `AA=true` y `TXT "OK"` para consultas cortas bajo dominios sospechosos<sup>[[4]](#references)</sup>
- Tráfico de la API de GitHub hacia `/repos/<owner>/<repo>/issues`, seguido de consultas a `ipinfo.io` desde la misma cadena de loader/beacon<sup>[[5]](#references)</sup>
- `.lnk` de Startup en carpetas Startup del usuario o comunes<sup>[[1]](#references)</sup>
- Run keys sospechosas (por ejemplo, "Updater") y nombres de loader como `update.ps1`/`loader.ps1`<sup>[[1]](#references)</sup>
- Muestras PE troyanizadas que redirigen `_security_init_cookie` hacia código de downloader antes de mostrar un documento señuelo<sup>[[5]](#references)</sup>
- Rutas de DLL modificables por el usuario bajo `%APPDATA%\Microsoft\Windows\Templates` que contienen `msimg32.dll`<sup>[[1]](#references)</sup>

## Notas sobre los campos de OpSec

- KillDate: timestamp después del cual el agent expira por sí mismo<sup>[[1]](#references)</sup>
- WorkingTime: horas durante las que el agent debe estar activo para mezclarse con la actividad empresarial<sup>[[1]](#references)</sup>

Estos campos pueden utilizarse para agrupar muestras y explicar periodos de baja actividad.

## YARA y pistas estáticas

Unit 42 publicó YARA básica para beacons (C/C++ y Go) y constantes de API-hashing de loaders.<sup>[[1]](#references)</sup> Considera complementarla con reglas que busquen el diseño [size|ciphertext|16-byte-key] cerca del final de `.rdata` del PE, las cadenas del perfil HTTP predeterminado y markers más recientes de servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
