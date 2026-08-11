# Extração de Configuração e TTPs do AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 é um framework modular e open-source de post-exploitation/C2 com beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e suporte a BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Como sua configuração compactada com RC4 é incorporada e como extraí-la dos beacons
- Indicadores de rede/perfil para listeners HTTP/SMB/TCP
- TTPs comuns de loaders e persistence observados em ambientes reais, com links para páginas de técnicas relevantes do Windows

Versões upstream recentes também incluem listeners de beacon DNS/DoH e a família separada de agentes/listeners Gopher; portanto, a infraestrutura moderna do Adaptix pode expor mais do que as superfícies HTTP/SMB/TCP originais, mesmo quando uma amostra específica ainda usa o agente beacon clássico.<sup>[[2]](#references)</sup>

## Perfis e campos do beacon

AdaptixC2 oferece suporte a três tipos principais de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web com servers/ports, SSL, method, URI, headers, user-agent e um nome de parâmetro customizáveis
- BEACON_SMB: C2 peer-to-peer com named-pipe (intranet)
- BEACON_TCP: direct sockets, opcionalmente com um marker prependido para ofuscar o início do protocolo

Esses são os layouts de beacon documentados publicamente nas primeiras análises do Adaptix e ainda são o ponto de partida mais comum para a extração no lado da amostra.<sup>[[1]](#references)</sup> No entanto, builds upstream atuais também incluem os extenders `BeaconDNS` e Gopher no lado do servidor; portanto, não presuma que toda implantação ativa do Adaptix exponha apenas infraestrutura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campos de perfil típicos observados em configurações de beacon HTTP (após a decriptação):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – usados para analisar os tamanhos das respostas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Builds recentes do BeaconHTTP também oferecem suporte à rotação selecionada pelo operador entre múltiplas URIs, user-agents, headers Host e servers, com seleção sequencial ou aleatória.<sup>[[2]](#references)</sup> Do ponto de vista de hunting, isso significa que um host infectado pode distribuir callbacks por vários caminhos e combinações de headers sem deixar de pertencer à família clássica de beacons compactados com RC4.

Exemplo de perfil HTTP padrão (de um build de beacon):<sup>[[1]](#references)</sup>
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
## Empacotamento da configuração criptografada e caminho de carregamento

Quando o operador clica em Create no builder, o AdaptixC2 incorpora o perfil criptografado como um blob final no beacon. O formato é:<sup>[[1]](#references)</sup>
- 4 bytes: tamanho da configuração (uint32, little-endian)
- N bytes: dados de configuração criptografados com RC4
- 16 bytes: chave RC4

O carregador do beacon copia a chave de 16 bytes do final e descriptografa com RC4 o bloco de N bytes no próprio local:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicações práticas:<sup>[[1]](#references)</sup>
- Toda a estrutura geralmente fica dentro da seção .rdata do PE.
- A extração é determinística: ler size, ler o ciphertext desse tamanho, ler a chave de 16 bytes colocada imediatamente depois e, então, executar RC4-decrypt.

## Fluxo de extração da configuração (defensores)

Escreva um extractor que imite a lógica do beacon:<sup>[[1]](#references)</sup>
1) Localize o blob dentro do PE (comumente em .rdata). Uma abordagem pragmática é varrer .rdata em busca de um layout plausível [size|ciphertext|16-byte key] e tentar RC4.
2) Leia os primeiros 4 bytes → size (uint32 LE).
3) Leia os próximos N=size bytes → ciphertext.
4) Leia os 16 bytes finais → RC4 key.
5) Faça RC4-decrypt do ciphertext. Em seguida, analise o plain profile como:
- escalares u32/boolean conforme indicado acima
- strings prefixadas por tamanho (tamanho u32 seguido pelos bytes; um NUL final pode estar presente)
- arrays: servers_count seguido por essa quantidade de pares [string, u32 port]

Prova de conceito mínima em Python (standalone, sem deps externas) que funciona com um blob pré-extraído:
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
Dicas:
- Ao automatizar, use um parser de PE para ler `.rdata` e aplique uma sliding window: para cada offset o, tente size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; faça RC4-decrypt e verifique se os campos de string são decodificados como UTF-8 e se os comprimentos são razoáveis.
- Faça o parse dos profiles SMB/TCP seguindo as mesmas convenções de length-prefixed.

## Custom listener profiles: não use hard-code apenas para o schema HTTP clássico

O formato de packing externo (`u32 size | RC4 ciphertext | 16-byte key`) é reutilizável, portanto listeners customizados pelo actor podem manter o mesmo workflow de extração enquanto alteram completamente o layout dos campos descriptografados.

Um bom exemplo recente é a campanha do Tropic Trooper de março de 2026, na qual o Adaptix beacon extraído não continha um profile HTTP/TCP padrão. Em vez disso, o blob descriptografado armazenava parâmetros de transporte do GitHub, como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por exemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estratégia prática de parsing:
- Primeiro, detecte o blob RC4 externo exatamente como de costume.
- Após a descriptografia, faça o branch com base em sentinel strings e na sanidade dos campos, em vez de forçar imediatamente o parser HTTP.
- Bons sentinels incluem `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings no estilo named-pipe ou arrays obviamente válidos de server/port.
- Se o parser HTTP falhar, mas o plaintext contiver strings UTF-8 coerentes e length-prefixed, mantenha o sample e tente schemas alternativos, em vez de descartá-lo como false positive.

Nessa campanha, o custom listener usava GitHub issues como transporte de C2, e o beacon consultava `ipinfo.io` para descobrir seu IP externo, pois a GitHub API não revela diretamente ao operator o source address da vítima.<sup>[[5]](#references)</sup>

## Network fingerprinting e hunting

HTTP:<sup>[[1]](#references)</sup>
- Comum: POST para URIs selecionadas pelo operator (por exemplo, /uri.php, /endpoint/api)
- Custom header parameter usado para o beacon ID (por exemplo, X‑Beacon‑Id, X‑App‑Id)
- User-agents imitando Firefox 20 ou builds contemporâneos do Chrome
- Cadência de polling visível por meio de sleep_delay/jitter_delay
- Builds mais recentes podem rotacionar URIs, user-agents, Host headers e servers entre callbacks; portanto, faça clustering com base em nomes de headers incomuns, padrões de response-size, reutilização de TLS e timing, em vez de presumir um único par path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners SMB named-pipe para C2 de intranet quando o web egress é restrito
- TCP beacons podem adicionar alguns bytes antes do traffic para ofuscar o início do protocolo

Defaults atuais do upstream teamserver
- `profile.yaml` atualmente inclui o teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nomes de arquivos de certificate/key `server.rsa.crt` e `server.rsa.key`, além de extenders para HTTP, SMB, TCP, DNS, Beacon agent e Gopher.<sup>[[2]](#references)</sup>
- Em routes sem correspondência, o default error handler retorna `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- O body padrão de 404 contém `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Scans em escala da Internet realizados em 2026 encontraram muitos teamservers expostos na porta `4321` e muitos beacon listeners na porta `43211`; portanto, ambas as portas são seed pivots úteis, mas não devem ser tratadas como exaustivas.<sup>[[4]](#references)</sup>

Fingerprints de DNS/DoH listener:<sup>[[4]](#references)</sup>
- O extender BeaconDNS atual responde autoritativamente (`AA=true`)
- Queries que não correspondem ao formato do beacon protocol — especialmente nomes com menos de 5 labels antes do domínio configurado — normalmente recebem a resposta `TXT "OK"`
- Se o base TTL configurado permanecer em zero, o listener usa uma base de 10 segundos e adiciona até 59 segundos de jitter
- Isso torna probes ativos com labels curtos úteis quando nenhum HTTP listener está exposto

## Loader e persistence TTPs observados em incidents

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Baixam payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alocam memória não gerenciada, copiam shellcode e alteram a proteção para 0x40 (PAGE_EXECUTE_READWRITE) por meio de VirtualProtect.<sup>[[7]](#references)</sup>
- Executam por meio de dynamic invocation do .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Uma cadeia do Tropic Trooper de 2026 usou um executável SumatraPDF trojanizado (TOSHIS loader) que redirecionava `_security_init_cookie` para código malicioso, em vez de fazer patch do PE entry point
- O loader resolvia APIs por meio de Adler-32 hashing, baixava um decoy PDF, obtinha o second-stage shellcode, descriptografava-o com AES-128-CBC por meio do WinCrypt (`CryptDeriveKey` a partir de um seed hardcoded) e executava reflectively um Adaptix beacon na memória
- A persistence posteriormente passou a usar scheduled tasks com nomes aparentemente benignos, como `\MSDNSvc` ou `\MicrosoftUDN`, configuradas para relançar o agent aproximadamente a cada duas horas

Consulte estas páginas para considerações sobre execução in-memory e AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistence observados:<sup>[[1]](#references)</sup>
- Atalho (.lnk) na Startup folder para relançar um loader no logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), frequentemente com nomes aparentemente benignos, como "Updater", para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack colocando msimg32.dll em %APPDATA%\Microsoft\Windows\Templates para processos vulneráveis

Análises detalhadas e verificações de techniques:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideias para hunting
- PowerShell gerando transições RW→RX: VirtualProtect para PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Padrões de dynamic invocation (GetDelegateForFunctionPointer)
- HTTPS 404s sem correspondência com `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respostas DNS com `AA=true` e `TXT "OK"` para queries curtas em domínios suspeitos.<sup>[[4]](#references)</sup>
- Traffic da GitHub API para `/repos/<owner>/<repo>/issues` seguido de consultas a `ipinfo.io` pela mesma cadeia de loader/beacon.<sup>[[5]](#references)</sup>
- .lnk de inicialização em user ou common Startup folders.<sup>[[1]](#references)</sup>
- Run keys suspeitas (por exemplo, "Updater") e nomes de loaders como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Samples de PE trojanizados que redirecionam `_security_init_cookie` para código de downloader antes de exibir um decoy document.<sup>[[5]](#references)</sup>
- DLL paths graváveis pelo user em %APPDATA%\Microsoft\Windows\Templates contendo msimg32.dll.<sup>[[1]](#references)</sup>

## Observações sobre OpSec fields

- KillDate: timestamp após o qual o agent expira automaticamente.<sup>[[1]](#references)</sup>
- WorkingTime: horas nas quais o agent deve estar ativo para se misturar à atividade comercial.<sup>[[1]](#references)</sup>

Esses fields podem ser usados para clustering e para explicar períodos de silêncio observados.

## YARA e indicadores estáticos

A Unit 42 publicou regras YARA básicas para beacons (C/C++ e Go) e constantes de API-hashing de loaders.<sup>[[1]](#references)</sup> Considere complementar com rules que procurem o layout [size|ciphertext|16-byte-key] próximo ao final de PE .rdata, as strings do default HTTP profile e markers mais recentes de server/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Um novo framework open-source utilizado em ataques do mundo real (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentação do Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting de um framework C2 open-source em escala (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper migra para AdaptixC2 e custom beacon listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de proteção de memória – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
