# Extracción de configuración y TTPs de AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 es un framework modular y de código abierto de post-exploitation/C2 con beacons de Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) y compatibilidad con BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Cómo se incrusta la configuración empaquetada con RC4 y cómo extraerla de los beacons
- Indicadores de red/perfil para listeners HTTP/SMB/TCP
- TTPs comunes de loader y persistence observados en la práctica, con enlaces a páginas relevantes sobre técnicas de Windows

Las versiones upstream recientes también incluyen listeners de beacon DNS/DoH y la familia independiente de agentes/listeners Gopher, por lo que la infraestructura moderna de Adaptix puede exponer más que las superficies HTTP/SMB/TCP originales, aunque una muestra específica siga usando el agente beacon clásico.<sup>[[2]](#references)</sup>

## Perfiles y campos de Beacon

AdaptixC2 admite tres tipos principales de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web con servidores/puertos/SSL configurables, método, URI, headers, user-agent y un nombre de parámetro personalizado
- BEACON_SMB: C2 peer-to-peer con named pipe (intranet)
- BEACON_TCP: sockets directos, opcionalmente con un marcador antepuesto para ofuscar el inicio del protocolo

Estos son los diseños de beacon documentados públicamente en los primeros análisis de Adaptix y siguen siendo el punto de partida más habitual para la extracción desde muestras.<sup>[[1]](#references)</sup> Sin embargo, las versiones upstream actuales también incluyen extensiones `BeaconDNS` y Gopher en el servidor, así que no des por hecho que toda implementación activa de Adaptix expone únicamente infraestructura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campos típicos del perfil observados en las configuraciones de beacon HTTP (tras el descifrado):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32): se usan para analizar los tamaños de las respuestas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Las versiones recientes de BeaconHTTP también admiten la rotación seleccionada por el operador entre varias URI, user-agents, headers Host y servidores, con selección secuencial o aleatoria.<sup>[[2]](#references)</sup> Desde la perspectiva de threat hunting, esto significa que un único host infectado puede distribuir sus conexiones entre varias rutas de callback y combinaciones de headers sin dejar de pertenecer a la familia clásica de beacons empaquetados con RC4.

Ejemplo de perfil HTTP predeterminado (de una compilación de beacon):<sup>[[1]](#references)</sup>

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

## Empaquetado de configuración cifrada y ruta de carga

Cuando el operador hace clic en Create en el generador, AdaptixC2 incrusta el perfil cifrado como un blob al final del beacon. El formato es:<sup>[[1]](#references)</sup>
- 4 bytes: tamaño de la configuración (uint32, little-endian)
- N bytes: datos de configuración cifrados con RC4
- 16 bytes: clave RC4

El cargador del beacon copia la clave de 16 bytes del final y descifra con RC4 el bloque de N bytes in situ:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implicaciones prácticas:<sup>[[1]](#references)</sup>
- Toda la estructura suele estar dentro de la sección PE .rdata.
- La extracción es determinista: leer el tamaño, leer el texto cifrado de ese tamaño, leer la clave RC4 de 16 bytes situada inmediatamente después y, luego, descifrar con RC4.

## Flujo de trabajo para extraer la configuración (defensores)

Escribe un extractor que imite la lógica del beacon:<sup>[[1]](#references)</sup>
1) Localiza el blob dentro del PE (normalmente en .rdata). Un enfoque práctico es buscar en .rdata una disposición plausible de [tamaño|texto cifrado|clave de 16 bytes] e intentar descifrarla con RC4.
2) Lee los primeros 4 bytes → tamaño (uint32 LE).
3) Lee los siguientes N=size bytes → texto cifrado.
4) Lee los últimos 16 bytes → clave RC4.
5) Descifra el texto cifrado con RC4. Luego, analiza el perfil descifrado como:
   - escalares u32/booleanos, como se indicó anteriormente
   - cadenas con longitud prefijada (longitud u32 seguida de bytes; puede haber un NUL final)
   - arrays: servers_count seguido de esa cantidad de pares [cadena, puerto u32]

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
- Al automatizar, usa un analizador PE para leer `.rdata` y luego aplica una ventana deslizante: para cada desplazamiento `o`, prueba `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]` y la siguiente clave de 16 bytes; descifra con RC4 y comprueba que los campos de texto se decodifiquen como UTF-8 y que las longitudes sean razonables.
- Analiza los perfiles SMB/TCP siguiendo las mismas convenciones de longitud prefijada.

## Perfiles de listener personalizados: no fijes únicamente el esquema HTTP clásico

El formato de empaquetado externo (`u32 size | RC4 ciphertext | 16-byte key`) es reutilizable, por lo que los listeners personalizados por el actor pueden mantener el mismo flujo de extracción y cambiar por completo el diseño de los campos descifrados.

Un buen ejemplo reciente es la campaña de Tropic Trooper de marzo de 2026, en la que el beacon Adaptix extraído no contenía un perfil HTTP/TCP estándar. En su lugar, el blob descifrado almacenaba parámetros de transporte de GitHub como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por ejemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estrategia práctica para el parser:
- Primero, detecta el blob RC4 externo como de costumbre.
- Tras descifrarlo, decide según cadenas centinela y la validez de los campos, en lugar de forzar inmediatamente el parser HTTP.
- Entre las buenas cadenas centinela están `api.github.com`, `/issues?state=open`, verbos/URI HTTP, cadenas con formato de named pipe o arrays de servidores/puertos claramente válidos.
- Si el parser HTTP falla, pero el texto plano contiene cadenas UTF-8 coherentes con longitud prefijada, conserva la muestra e intenta otros esquemas en lugar de descartarla como falso positivo.

En esa campaña, el listener personalizado usaba GitHub issues como transporte C2, y el beacon consultaba `ipinfo.io` para conocer su IP externa, ya que la API de GitHub no revela directamente al operador la dirección de origen de la víctima.<sup>[[5]](#references)</sup>

## Fingerprinting de red y búsqueda de amenazas

HTTP:<sup>[[1]](#references)</sup>
- Común: POST a URI seleccionadas por el operador (p. ej., `/uri.php`, `/endpoint/api`)
- Parámetro de header personalizado usado como ID del beacon (p. ej., X‑Beacon‑Id, X‑App‑Id)
- User-agents que imitan Firefox 20 o versiones contemporáneas de Chrome
- Cadencia de sondeo visible mediante sleep_delay/jitter_delay
- Las versiones más recientes pueden rotar URI, user-agents, headers Host y servidores entre callbacks; por tanto, agrupa según nombres de headers poco comunes, patrones de tamaño de respuesta, reutilización de TLS y tiempos, en vez de asumir un único par de ruta/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners SMB con named pipe para C2 en intranets donde la salida web está restringida
- Los beacons TCP pueden anteponer unos pocos bytes al tráfico para ofuscar el inicio del protocolo

Valores predeterminados actuales del teamserver upstream
- `profile.yaml` incluye actualmente el teamserver `0.0.0.0:4321`, el endpoint `/endpoint`, los nombres de archivo del certificado/clave `server.rsa.crt` y `server.rsa.key`, y extensores para HTTP, SMB, TCP, DNS, el agente Beacon y Gopher.<sup>[[2]](#references)</sup>
- Para las rutas no coincidentes, el handler de error predeterminado devuelve `Server: AdaptixC2` y `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- El cuerpo 404 estándar contiene `AdaptixC2 404` y `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Los escaneos de todo Internet realizados en 2026 encontraron muchos teamservers expuestos en el puerto `4321` y muchos listeners de beacon en el `43211`; por eso, ambos puertos son pivotes iniciales útiles, aunque no deben considerarse exhaustivos.<sup>[[4]](#references)</sup>

Huella de listeners DNS/DoH:<sup>[[4]](#references)</sup>
- El extensor BeaconDNS actual responde autoritativamente (`AA=true`)
- Las consultas que no coinciden con el formato del protocolo del beacon —en particular, los nombres con menos de 5 etiquetas antes del dominio configurado— suelen recibir como respuesta `TXT "OK"`
- Si el TTL base configurado se deja en cero, el listener usa una base de 10 segundos y añade hasta 59 segundos de jitter
- Esto hace que las sondas activas con etiquetas cortas sean útiles cuando no hay un listener HTTP expuesto

## TTPs de loader y persistencia observados en incidentes

Loaders de PowerShell en memoria:<sup>[[1]](#references)</sup>
- Descargan payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Asignan memoria no administrada, copian shellcode y cambian la protección a 0x40 (PAGE_EXECUTE_READWRITE) mediante VirtualProtect.<sup>[[7]](#references)</sup>
- Ejecutan mediante invocación dinámica de .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software firmado troyanizado / loaders de shellcode por etapas:<sup>[[5]](#references)</sup>
- Una cadena de Tropic Trooper de 2026 utilizó un ejecutable SumatraPDF troyanizado (loader TOSHIS) que redirigía `_security_init_cookie` a código malicioso en lugar de modificar el punto de entrada PE
- El loader resolvía APIs mediante hashing Adler-32, descargaba un PDF señuelo, obtenía shellcode de segunda etapa, lo descifraba con AES-128-CBC mediante WinCrypt (`CryptDeriveKey` a partir de una semilla codificada de forma fija) y ejecutaba reflectivamente un beacon Adaptix en memoria
- Más adelante, la persistencia pasó a tareas programadas con nombres de apariencia legítima, como `\MSDNSvc` o `\MicrosoftUDN`, configuradas para volver a iniciar el agente aproximadamente cada dos horas

Consulta estas páginas sobre ejecución en memoria y consideraciones relativas a AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistencia observados:<sup>[[1]](#references)</sup>
- Acceso directo (.lnk) en la carpeta Startup para volver a iniciar un loader al iniciar sesión
- Claves Run del registro (HKCU/HKLM ...\CurrentVersion\Run), a menudo con nombres de apariencia legítima como "Updater" para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- Secuestro del orden de búsqueda de DLL mediante la colocación de msimg32.dll en %APPDATA%\Microsoft\Windows\Templates para procesos vulnerables

Análisis detallados y comprobaciones de técnicas:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideas para la búsqueda de amenazas
- PowerShell que genera transiciones RW→RX: VirtualProtect a PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Patrones de invocación dinámica (GetDelegateForFunctionPointer)
- Respuestas HTTPS 404 a rutas no coincidentes con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respuestas DNS con `AA=true` y `TXT "OK"` a consultas cortas en dominios sospechosos.<sup>[[4]](#references)</sup>
- Tráfico de la API de GitHub a `/repos/<owner>/<repo>/issues` seguido de consultas a `ipinfo.io` desde la misma cadena de loader/beacon.<sup>[[5]](#references)</sup>
- Archivos .lnk en las carpetas Startup del usuario o comunes.<sup>[[1]](#references)</sup>
- Claves Run sospechosas (p. ej., "Updater") y nombres de loader como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Muestras PE troyanizadas que redirigen `_security_init_cookie` a código de descarga antes de mostrar un documento señuelo.<sup>[[5]](#references)</sup>
- Rutas de DLL modificables por el usuario bajo %APPDATA%\Microsoft\Windows\Templates que contengan msimg32.dll.<sup>[[1]](#references)</sup>

## Notas sobre campos OpSec

- KillDate: marca de tiempo tras la cual el agente se desactiva por sí mismo.<sup>[[1]](#references)</sup>
- WorkingTime: horas en las que el agente debe estar activo para mimetizarse con la actividad empresarial.<sup>[[1]](#references)</sup>

Estos campos pueden usarse para agrupar muestras y explicar períodos de inactividad observados.

## YARA y pistas estáticas

Unit 42 publicó reglas YARA básicas para beacons (C/C++ y Go) y constantes de hashing de API de loaders.<sup>[[1]](#references)</sup> Considera complementarlas con reglas que busquen el formato [size|ciphertext|16-byte-key] cerca del final de `.rdata` de PE, las cadenas del perfil HTTP predeterminado y marcadores más recientes de servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Un nuevo framework de código abierto utilizado en ataques reales (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentación de Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting a escala de un framework C2 de código abierto (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper cambia a AdaptixC2 y a un listener de beacon personalizado (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de protección de memoria – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Claves Run del registro/Carpeta Startup](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
