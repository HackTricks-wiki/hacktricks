# Extração de Configuração do AdaptixC2 e TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 é um framework modular e open‑source de post‑exploitation/C2 com beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e suporte a BOF. Esta página documenta:
- Como a sua configuração empacotada com RC4 é embutida e como extraí‑la dos beacons
- Indicadores de rede/perfil para listeners HTTP/SMB/TCP
- TTPs comuns de loader e persistência observados no mundo real, com links para páginas de técnicas relevantes do Windows

## Perfis e campos de beacon

AdaptixC2 suporta três tipos primários de beacon:
- BEACON_HTTP: web C2 com servidores/portas/SSL configuráveis, method, URI, headers, user‑agent, e um nome de parâmetro customizado
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: sockets diretos, opcionalmente com um marcador pré‑inserido para ofuscar o início do protocolo

Campos típicos de perfil observados em configs de beacon HTTP (após descriptografia):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – usado para analisar os tamanhos das respostas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Exemplo de perfil HTTP padrão (de um build de beacon):
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
## Empacotamento da configuração criptografada e caminho de carregamento

Quando o operador clica em Criar no builder, o AdaptixC2 incorpora o perfil criptografado como um blob final no beacon. O formato é:
- 4 bytes: tamanho da configuração (uint32, little‑endian)
- N bytes: dados de configuração criptografados com RC4
- 16 bytes: chave RC4

O beacon loader copia a chave de 16‑byte do final e descriptografa com RC4 o bloco de N‑byte no próprio local:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicações práticas:
- Toda a estrutura frequentemente vive dentro da seção PE .rdata.
- A extração é determinística: leia o size, leia o ciphertext desse tamanho, leia a 16‑byte key colocada imediatamente depois, e então RC4‑decrypt.

## Fluxo de extração de configuração (defensores)

Implemente um extractor que imite a beacon logic:
1) Localize o blob dentro do PE (comumente .rdata). Uma abordagem pragmática é escanear .rdata em busca de um layout plausível [size|ciphertext|16‑byte key] e tentar RC4.
2) Leia os primeiros 4 bytes → size (uint32 LE).
3) Leia os próximos N=size bytes → ciphertext.
4) Leia os últimos 16 bytes → RC4 key.
5) RC4‑decrypt o ciphertext. Em seguida, parse o plain profile como:
- u32/boolean scalars conforme indicado acima
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- arrays: servers_count seguido por esse número de pares [string, u32 port]

Prova de conceito mínima em Python (standalone, no external deps) que funciona com um blob pré-extraído:
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
Tips:
- When automating, use a PE parser to read .rdata then apply a sliding window: for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt and check that string fields decode as UTF‑8 and lengths are sane.
- Parse SMB/TCP profiles by following the same length‑prefixed conventions.

## Network fingerprinting and hunting

HTTP
- Comum: POST para URIs selecionadas pelo operador (e.g., /uri.php, /endpoint/api)
- Parâmetro de header customizado usado para beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents imitando Firefox 20 ou builds contemporâneos do Chrome
- Cadência de polling visível via sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners para C2 de intranet onde o web egress é restrito
- TCP beacons podem prefixar alguns bytes antes do tráfego para ofuscar o início do protocolo

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Fazem download de payloads Base64/XOR (Invoke‑RestMethod / WebClient)
- Alocam memória unmanaged, copiam shellcode, trocam proteção para 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Executam via invocação dinâmica .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Atalho na pasta Startup (.lnk) para relançar um loader no logon
- Chaves Run do Registry (HKCU/HKLM ...\CurrentVersion\Run), frequentemente com nomes que soam benignos como "Updater" para iniciar loader.ps1
- DLL search‑order hijack colocando msimg32.dll em %APPDATA%\Microsoft\Windows\Templates para processos suscetíveis

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell gerando transições RW→RX: VirtualProtect para PAGE_EXECUTE_READWRITE dentro de powershell.exe
- Padrões de invocação dinâmica (GetDelegateForFunctionPointer)
- .lnk de Startup sob pastas Startup do usuário ou comuns
- Chaves Run suspeitas (e.g., "Updater"), e nomes de loader como update.ps1/loader.ps1
- Caminhos de DLL graváveis por usuário sob %APPDATA%\Microsoft\Windows\Templates contendo msimg32.dll

## Notes on OpSec fields

- KillDate: timestamp após o qual o agent expira automaticamente
- WorkingTime: horas em que o agent deve estar ativo para se misturar com atividade empresarial

Esses campos podem ser usados para agrupamento e para explicar períodos silenciosos observados.

## YARA and static leads

Unit 42 publicou YARA básicas para beacons (C/C++ and Go) e constantes de hashing de API do loader. Considere complementar com regras que procurem pelo layout [size|ciphertext|16‑byte‑key] próximo ao final de PE .rdata e pelas default HTTP profile strings.

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
