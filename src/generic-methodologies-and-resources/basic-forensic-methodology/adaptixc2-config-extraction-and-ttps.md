# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 es un framework modular de código abierto de post‑exploitation/C2 con beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) y soporte BOF. Esta página documenta:
- Cómo su configuración empaquetada con RC4 está incrustada y cómo extraerla de los beacons
- Indicadores de red/perfil para listeners HTTP/SMB/TCP
- TTPs comunes de loader y persistence observados en el mundo real, con enlaces a páginas de técnicas relevantes de Windows

## Beacon profiles and fields

AdaptixC2 soporta tres tipos principales de beacon:
- BEACON_HTTP: web C2 con servers/ports/SSL configurables, method, URI, headers, user‑agent y un nombre de parameter personalizado
- BEACON_SMB: C2 peer‑to‑peer por named‑pipe (intranet)
- BEACON_TCP: sockets directos, opcionalmente con un marker prepended para ofuscar el inicio del protocolo

Campos típicos de perfil observados en configs de beacon HTTP (después del descifrado):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – usados para parsear los tamaños de respuesta
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
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

Cuando el operator hace clic en Create en el builder, AdaptixC2 inserta el perfil cifrado como un tail blob al final del beacon. El formato es:
- 4 bytes: tamaño de la configuración (uint32, little‑endian)
- N bytes: datos de configuración cifrados con RC4
- 16 bytes: RC4 key

El beacon loader copia la clave de 16 bytes desde el final y descifra con RC4 el bloque de N bytes en su lugar:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicaciones prácticas:
- Toda la estructura suele vivir dentro de la sección .rdata del PE.
- La extracción es determinista: leer size, leer el ciphertext de ese tamaño, leer la clave de 16‑bytes colocada inmediatamente después, y luego RC4‑decrypt.

## Flujo de extracción de configuración (defensores)

Escribe un extractor que imite la lógica del beacon:
1) Localiza el blob dentro del PE (comúnmente .rdata). Un enfoque pragmático es escanear .rdata en busca de una disposición plausible [size|ciphertext|16‑byte key] y probar con RC4.
2) Leer los primeros 4 bytes → size (uint32 LE).
3) Leer los siguientes N=size bytes → ciphertext.
4) Leer los últimos 16 bytes → RC4 key.
5) Descifrar con RC4 el ciphertext. A continuación, analizar el perfil en claro como:
- u32/boolean scalars como se indicó arriba
- length‑prefixed strings (u32 length seguido de bytes; puede estar presente un NUL final)
- arrays: servers_count seguido por esa cantidad de pares [string, u32 port]

Prueba de concepto mínima en Python (standalone, sin dependencias externas) que funciona con un blob pre‑extraído:
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
- Cuando automatices, usa un PE parser para leer .rdata y luego aplica una ventana deslizante: para cada offset o, intenta size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt y verifica que los campos string se decodifiquen como UTF‑8 y que las longitudes sean razonables.
- Parse SMB/TCP profiles siguiendo las mismas convenciones con prefijo de longitud.

## Detección de red y búsqueda

HTTP
- Común: POST a URIs seleccionadas por el operador (p. ej., /uri.php, /endpoint/api)
- Parámetro de cabecera personalizado usado para el beacon ID (p. ej., X‑Beacon‑Id, X‑App‑Id)
- User‑agents que imitan Firefox 20 o builds contemporáneos de Chrome
- Cadencia de polling visible vía sleep_delay/jitter_delay

SMB/TCP
- Listeners en named‑pipe SMB para C2 intranet cuando el egress web está restringido
- Los beacons TCP pueden anteponer unos bytes antes del tráfico para ofuscar el inicio del protocolo

## TTPs de loader y persistencia observados en incidentes

Loaders de PowerShell en memoria
- Descargan payloads Base64/XOR (Invoke‑RestMethod / WebClient)
- Allocan memoria unmanaged, copian shellcode, cambian la protección a 0x40 (PAGE_EXECUTE_READWRITE) vía VirtualProtect
- Ejecutan vía invocación dinámica .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Consulta estas páginas para ejecución en memoria y consideraciones AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistencia observados
- Acceso directo en Startup folder (.lnk) para relanzar un loader al iniciar sesión
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), frecuentemente con nombres que suenan benignos como "Updater" para iniciar loader.ps1
- DLL search‑order hijack dejando msimg32.dll bajo %APPDATA%\Microsoft\Windows\Templates para procesos susceptibles

Deep‑dives y comprobaciones de técnicas:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideas para hunting
- Transiciones RW→RX originadas por PowerShell: VirtualProtect a PAGE_EXECUTE_READWRITE dentro de powershell.exe
- Patrones de invocación dinámica (GetDelegateForFunctionPointer)
- .lnk en Startup del usuario o en carpetas Startup comunes
- Run keys sospechosas (p. ej., "Updater"), y nombres de loaders como update.ps1/loader.ps1
- Rutas de DLL escriturables por el usuario bajo %APPDATA%\Microsoft\Windows\Templates que contengan msimg32.dll

## Notas sobre campos de OpSec

- KillDate: timestamp después del cual el agente se auto‑expira
- WorkingTime: horas en las que el agente debería estar activo para mezclarse con la actividad laboral

Estos campos pueden usarse para clustering y para explicar periodos de inactividad observados.

## YARA y pistas estáticas

Unit 42 publicó YARA básica para beacons (C/C++ y Go) y constantes de API‑hashing de loaders. Considera complementar con reglas que busquen el layout [size|ciphertext|16‑byte‑key] cerca del final de PE .rdata y las cadenas del perfil HTTP por defecto.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
