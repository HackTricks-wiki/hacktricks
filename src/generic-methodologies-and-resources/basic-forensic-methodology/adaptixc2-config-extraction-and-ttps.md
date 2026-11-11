# Extracción de configuración y TTP de AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 es un framework modular y de código abierto de post-explotación/C2, con beacons de Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) y soporte para BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Cómo se integra su configuración empaquetada con RC4 y cómo extraerla de los beacons
- Indicadores de red y perfiles para listeners HTTP/SMB/TCP
- TTP habituales de loader y persistencia observados en entornos reales, con enlaces a páginas sobre técnicas de Windows pertinentes

Las versiones upstream recientes también incluyen listeners de beacon DNS/DoH y la familia independiente de agentes/listeners Gopher, por lo que la infraestructura moderna de Adaptix podría exponer algo más que las superficies HTTP/SMB/TCP originales, incluso si una muestra concreta sigue usando el agente beacon clásico.<sup>[[2]](#references)</sup>

## Perfiles y campos del beacon

AdaptixC2 admite tres tipos principales de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web con servidores/puertos/SSL configurables, método, URI, encabezados, user-agent y un nombre de parámetro personalizado
- BEACON_SMB: C2 peer-to-peer mediante named pipe (intranet)
- BEACON_TCP: sockets directos, opcionalmente con un marcador antepuesto para ofuscar el inicio del protocolo

Estos son los formatos de beacon documentados públicamente en los primeros análisis de Adaptix y siguen siendo el punto de partida más habitual para la extracción desde muestras.<sup>[[1]](#references)</sup> Sin embargo, las compilaciones upstream actuales también incluyen extensiones `BeaconDNS` y Gopher del lado del servidor, así que no se debe asumir que todas las implementaciones activas de Adaptix exponen únicamente infraestructura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

El siguiente resumen de campos y las muestras JSON describen el formato HTTP analizado en 2025; no son una especificación de parser para las compilaciones upstream más recientes. Campos habituales en esas muestras (tras el descifrado):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – usados para analizar los tamaños de las respuestas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Las compilaciones recientes de BeaconHTTP también admiten la rotación seleccionada por el operador entre varias URI, user-agents, encabezados Host y servidores, con selección secuencial o aleatoria.<sup>[[2]](#references)</sup> Desde la perspectiva del threat hunting, esto significa que un único host infectado puede distribuir sus callbacks entre varias rutas y combinaciones de encabezados sin dejar de pertenecer a la familia clásica de beacons empaquetados con RC4.

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

## Empaquetado de la configuración cifrada y ruta de carga

Cuando el operador hace clic en Create en el builder, AdaptixC2 compila el perfil cifrado dentro del beacon. No asumas que está al final del PE o del shellcode: localiza los bytes del perfil mediante un análisis de secciones o siguiendo `getProfile()` en el ejemplo. El formato empaquetado es:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: tamaño de la configuración (uint32, little‑endian)
- N bytes: datos de configuración cifrados con RC4
- 16 bytes: clave RC4

El loader del beacon copia la clave de 16 bytes desde el final y descifra con RC4 el bloque de N bytes in situ:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implicaciones prácticas:<sup>[[1]](#references)</sup>
- Toda la estructura suele estar dentro de la sección PE .rdata.
- La extracción es determinista: leer el tamaño, leer el texto cifrado de ese tamaño, leer la clave de 16 bytes colocada inmediatamente después y, luego, descifrar con RC4.

## Flujo de trabajo para extraer la configuración (defensores)

Para el triaje general de muestras antes de extraer el beacon, consulta [Malware Analysis](malware-analysis.md).

Escribe un extractor que imite la lógica del beacon:<sup>[[1]](#references)</sup>
1) Localiza el blob dentro del PE (normalmente en .rdata). Un enfoque práctico consiste en buscar en .rdata una estructura plausible [size|ciphertext|16-byte key] e intentar aplicar RC4.
2) Lee los primeros 4 bytes → tamaño (uint32 LE).
3) Lee los siguientes N=size bytes → texto cifrado.
4) Lee los últimos 16 bytes → clave RC4.
5) Descifra el texto cifrado con RC4. Luego analiza el perfil en texto plano así:
   - escalares u32/booleanos, como se indicó arriba
   - cadenas precedidas por su longitud (longitud u32 seguida de bytes; puede haber un NUL final)
   - arreglos: servers_count seguido de esa cantidad de pares [string, u32 port]

Prueba de concepto en Python para HTTP heredado (independiente, sin dependencias externas) para un blob extraído previamente en el orden de campos de 2025. Usa el analizador del esquema actual que aparece abajo para compilaciones estándar recientes:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Analizar los perfiles HTTP y DNS estándar actuales

El upstream actual empaqueta primero seis valores `u32` little-endian: marca/tipo del agente, fecha de finalización, tiempo de actividad, intervalo de suspensión, jitter y marca/tipo del listener. Los datos específicos de HTTP comienzan luego con un indicador SSL de un byte. A diferencia del ejemplo heredado, incluye listas con contador de URI, user-agent y encabezados Host, seguidas del modo de rotación y la configuración del proxy. Por lo tanto, el parser heredado empieza a leer el indicador SSL desde el campo de fecha de finalización y produce resultados falsos en estas compilaciones. Las longitudes de cadena y los valores enteros de este perfil usan codificación little-endian; las cadenas empaquetadas incluyen un NUL final si no están vacías.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Con los helpers `P` y `rc4` de arriba, usa este parser en el texto plano **HTTP estándar** descifrado. Mantén la clave RC4 fuera de los informes públicos: el perfil HTTP puede contener un nombre de usuario y una contraseña del proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Analizar un perfil de texto plano HTTP estándar actual</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Para un beacon DNS estándar, lee los mismos seis campos `u32` comunes y, a continuación, las cadenas `domain`, `resolvers`, `doh_resolvers` y `qtype`, precedidas por su longitud. Lee `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` y `dns_mode` como `u32`; después, lee la cadena de user-agent de DoH precedida por su longitud. `dns_mode` distingue entre UDP, DoH y las dos direcciones de fallback. Este es un formato independiente: no fuerces el texto plano de DNS a pasar por el parser HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Consejos:
- Al automatizar, usa un parser PE para leer .rdata y luego aplica una ventana deslizante: para cada desplazamiento o, prueba size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = los siguientes 16 bytes; descifra con RC4 y comprueba que los campos de cadena se decodifiquen como UTF-8 y que las longitudes sean razonables.
- Analiza los perfiles SMB/TCP siguiendo las mismas convenciones de longitud prefijada.

## Perfiles de listener personalizados: no te limites al esquema HTTP clásico

El formato externo de empaquetado (`u32 size | RC4 ciphertext | 16-byte key`) es reutilizable, así que los listeners personalizados por los actores pueden seguir el mismo flujo de extracción y cambiar por completo el diseño de los campos descifrados.

Un buen ejemplo reciente es la campaña de Tropic Trooper de marzo de 2026, en la que el beacon de Adaptix extraído no contenía un perfil HTTP/TCP estándar. En cambio, el blob descifrado almacenaba parámetros de transporte de GitHub como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por ejemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estrategia práctica para el parser:
- Primero, detecta el blob RC4 externo como de costumbre.
- Tras descifrarlo, decide según las cadenas centinela y la validez de los campos, en vez de forzar de inmediato el parser HTTP.
- Algunas buenas cadenas centinela son `api.github.com`, `/issues?state=open`, verbos/URI HTTP, cadenas con formato de named pipe o matrices claramente válidas de servidores/puertos.
- Si el parser HTTP falla, pero el texto plano contiene cadenas UTF-8 coherentes precedidas por su longitud, conserva la muestra e intenta otros esquemas en vez de descartarla como un falso positivo.

En esa campaña, el listener personalizado usaba los issues de GitHub como transporte C2, y el beacon consultaba `ipinfo.io` para averiguar su IP externa, ya que la API de GitHub no revela directamente al operador la dirección de origen de la víctima.<sup>[[5]](#references)</sup>

## Fingerprinting de red y hunting

HTTP:<sup>[[1]](#references)</sup>
- Común: POST a URI elegidas por el operador (p. ej., /uri.php, /endpoint/api)
- Parámetro de header personalizado usado para el ID del beacon (p. ej., X‑Beacon‑Id, X‑App‑Id)
- User-agents que imitan Firefox 20 o versiones contemporáneas de Chrome
- La frecuencia de sondeo puede observarse mediante sleep_delay/jitter_delay
- Las versiones más recientes pueden rotar URI, user-agents, headers Host y servidores entre callbacks; por tanto, agrupa según nombres de headers poco comunes, patrones en el tamaño de las respuestas, reutilización de TLS y tiempos, en lugar de asumir un único par de ruta/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners SMB con named pipes para C2 en intranets donde el tráfico web saliente está restringido
- Los beacons TCP pueden anteponer unos pocos bytes al tráfico para ofuscar el inicio del protocolo

Valores predeterminados actuales del teamserver upstream
- `profile.yaml` incluye actualmente el teamserver `0.0.0.0:4321`, el endpoint `/endpoint`, los nombres de archivo de certificado/clave `server.rsa.crt` y `server.rsa.key`, y extensores para HTTP, SMB, TCP, DNS, el agente Beacon y Gopher.<sup>[[2]](#references)</sup>
- Para las rutas sin coincidencia, el handler de errores predeterminado devuelve `Server: AdaptixC2` y `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- El cuerpo 404 estándar contiene `AdaptixC2 404` y `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Los escaneos de todo Internet realizados en 2026 detectaron muchos teamservers expuestos en `4321` y muchos listeners de beacon en `43211`; ambos puertos son buenos puntos de partida para pivotes, pero no deben considerarse exhaustivos.<sup>[[4]](#references)</sup>

Huellas de listeners DNS/DoH:<sup>[[4]](#references)</sup>
- El extensor BeaconDNS actual responde autoritativamente (`AA=true`)
- Las consultas que no coinciden con el formato del protocolo del beacon —en particular, nombres con menos de 5 etiquetas antes del dominio configurado— suelen recibir como respuesta `TXT "OK"`
- Si el TTL base configurado se deja en cero, el listener usa una base de 10 segundos y añade hasta 59 segundos de jitter
- Esto hace que las pruebas activas con etiquetas cortas sean útiles cuando no hay un listener HTTP expuesto

## TTP de loaders y persistencia observadas en incidentes

Loaders de PowerShell en memoria:<sup>[[1]](#references)</sup>
- Descargan payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Asignan memoria no administrada, copian shellcode y cambian la protección a 0x40 (PAGE_EXECUTE_READWRITE) mediante VirtualProtect.<sup>[[7]](#references)</sup>
- Ejecutan mediante invocación dinámica de .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software firmado troyanizado / loaders de shellcode por etapas:<sup>[[5]](#references)</sup>
- Una cadena de Tropic Trooper de 2026 usó un ejecutable SumatraPDF troyanizado (loader TOSHIS) que redirigía `_security_init_cookie` a código malicioso en lugar de modificar el punto de entrada del PE
- El loader resolvía APIs mediante hashing Adler-32, descargaba un PDF señuelo, obtenía shellcode de segunda etapa, lo descifraba con AES-128-CBC mediante WinCrypt (`CryptDeriveKey` a partir de una semilla codificada de forma rígida) y ejecutaba reflectivamente un beacon de Adaptix en memoria
- Más adelante, la persistencia pasó a tareas programadas con nombres de apariencia legítima, como `\MSDNSvc` o `\MicrosoftUDN`, configuradas para volver a iniciar el agente aproximadamente cada dos horas

Consulta estas páginas sobre ejecución en memoria y consideraciones de AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistencia observados:<sup>[[1]](#references)</sup>
- Acceso directo (.lnk) en la carpeta Startup para volver a iniciar un loader al iniciar sesión
- Claves Run del registro (HKCU/HKLM ...\CurrentVersion\Run), a menudo con nombres de apariencia legítima, como "Updater", para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- Secuestro del orden de búsqueda de DLL mediante la ubicación de msimg32.dll en %APPDATA%\Microsoft\Windows\Templates para procesos vulnerables

Análisis detallados de técnicas y comprobaciones:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideas de hunting
- Transiciones RW→RX iniciadas por PowerShell: VirtualProtect a PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Patrones de invocación dinámica (GetDelegateForFunctionPointer)
- Respuestas HTTPS 404 sin coincidencia que incluyan `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respuestas DNS con `AA=true` y `TXT "OK"` a consultas cortas bajo dominios sospechosos.<sup>[[4]](#references)</sup>
- Tráfico de la API de GitHub a `/repos/<owner>/<repo>/issues`, seguido de consultas a `ipinfo.io` desde la misma cadena de loader/beacon.<sup>[[5]](#references)</sup>
- Archivos .lnk de inicio en carpetas Startup del usuario o compartidas.<sup>[[1]](#references)</sup>
- Claves Run sospechosas (p. ej., "Updater") y nombres de loader como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Muestras de PE troyanizadas que redirigen `_security_init_cookie` a código de descarga antes de mostrar un documento señuelo.<sup>[[5]](#references)</sup>
- Rutas de DLL modificables por el usuario en %APPDATA%\Microsoft\Windows\Templates que contengan msimg32.dll.<sup>[[1]](#references)</sup>

## Notas sobre los campos OpSec

- KillDate: marca de tiempo tras la cual el agente se desactiva automáticamente.<sup>[[1]](#references)</sup>
- WorkingTime: horas en las que el agente debe estar activo para camuflarse con la actividad empresarial.<sup>[[1]](#references)</sup>

Estos campos pueden usarse para agrupar muestras y explicar períodos de inactividad observados.

## YARA y pistas estáticas

Unit 42 publicó reglas YARA básicas para beacons (C/C++ y Go) y constantes de hashing de API de loaders.<sup>[[1]](#references)</sup> Considera complementarlas con reglas que busquen el formato [size|ciphertext|16-byte-key] cerca del final de .rdata en el PE, las cadenas del perfil HTTP predeterminado y marcadores más recientes del servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: un nuevo framework de código abierto utilizado en ataques reales (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 en GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentación de Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: fingerprinting a escala de un framework C2 de código abierto (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper recurre a AdaptixC2 y a un listener de beacon personalizado (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Documentación de Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Documentación de Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de protección de memoria – Documentación de Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Claves Run del registro/Carpeta Startup](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Generación de perfiles de AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser de perfiles de beacon de AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Generación de perfiles DNS de AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Empaquetado de perfiles de AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
