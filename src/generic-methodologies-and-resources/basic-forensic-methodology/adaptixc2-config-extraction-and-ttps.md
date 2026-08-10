# Extração de Configuração e TTPs do AdaptixC2

AdaptixC2 é um framework modular, open-source, de post-exploitation/C2 com beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e suporte a BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Como sua configuração empacotada com RC4 é incorporada e como extraí-la dos beacons
- Indicadores de rede/perfil para listeners HTTP/SMB/TCP
- TTPs comuns de loaders e persistence observados no mundo real, com links para páginas de técnicas relevantes do Windows

Versões upstream recentes também incluem listeners de beacon DNS/DoH e a família separada de Gopher agents/listeners. Portanto, a infraestrutura moderna do Adaptix pode expor mais do que as superfícies HTTP/SMB/TCP originais, mesmo quando um sample específico ainda usa o beacon agent clássico.<sup>[[2]](#references)</sup>

## Perfis e campos de beacon

O AdaptixC2 suporta três tipos principais de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web com servers/ports/SSL configuráveis, method, URI, headers, user-agent e um custom parameter name
- BEACON_SMB: C2 peer-to-peer por named pipe (intranet)
- BEACON_TCP: sockets diretos, opcionalmente com um marker prefixado para ofuscar o início do protocolo

Esses são os layouts de beacon documentados publicamente nas primeiras análises do Adaptix e ainda são o ponto de partida mais comum para a extração do lado do sample.<sup>[[1]](#references)</sup> No entanto, os builds upstream atuais também incluem os extenders `BeaconDNS` e Gopher no lado do server. Portanto, não presuma que toda implantação ativa do Adaptix exponha apenas infraestrutura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campos de perfil normalmente observados em configurações de beacon HTTP (após a decryption):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – usados para analisar os response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Builds recentes do BeaconHTTP também suportam a rotação selecionada pelo operator entre várias URIs, user-agents, Host headers e servers, com seleção sequencial ou aleatória.<sup>[[2]](#references)</sup> Do ponto de vista de hunting, isso significa que um único host infectado pode distribuir callbacks por vários caminhos e combinações de headers sem deixar de pertencer à família clássica de beacons empacotados com RC4.

Exemplo de perfil HTTP padrão (de um beacon build):<sup>[[1]](#references)</sup>
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

Quando o operador clica em Create no builder, o AdaptixC2 incorpora o profile criptografado como um tail blob no beacon. O formato é:<sup>[[1]](#references)</sup>
- 4 bytes: tamanho da configuração (uint32, little-endian)
- N bytes: dados de configuração criptografados com RC4
- 16 bytes: chave RC4

O loader do beacon copia a chave de 16 bytes do final e descriptografa com RC4 o bloco de N bytes in place:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicações práticas:<sup>[[1]](#references)</sup>
- Toda a estrutura geralmente fica dentro da seção .rdata do PE.
- A extração é determinística: ler o tamanho, ler o ciphertext desse tamanho, ler a chave de 16 bytes posicionada imediatamente depois e, então, fazer a descriptografia RC4.

## Fluxo de extração da configuração (defensores)

Escreva um extractor que imite a lógica do beacon:<sup>[[1]](#references)</sup>
1) Localize o blob dentro do PE (comumente em .rdata). Uma abordagem pragmática é examinar .rdata em busca de um layout plausível [size|ciphertext|16‑byte key] e tentar RC4.
2) Leia os primeiros 4 bytes → size (uint32 LE).
3) Leia os próximos N=size bytes → ciphertext.
4) Leia os 16 bytes finais → chave RC4.
5) Faça a descriptografia RC4 do ciphertext. Em seguida, analise o profile em texto claro como:
- escalares u32/boolean, conforme observado acima
- strings prefixadas por tamanho (tamanho u32 seguido pelos bytes; um NUL final pode estar presente)
- arrays: servers_count seguido por essa quantidade de pares [string, porta u32]

Prova de conceito mínima em Python (standalone, sem dependências externas) que funciona com um blob previamente extraído:
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
- Ao automatizar, use um PE parser para ler .rdata e aplique uma sliding window: para cada offset o, tente size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = os próximos 16 bytes; faça RC4-decrypt e verifique se os campos de string são decodificados como UTF-8 e se os comprimentos são razoáveis.
- Analise os perfis SMB/TCP seguindo as mesmas convenções de length-prefixed.

## Perfis de custom listener: não use hard-code apenas para o schema HTTP clássico

O formato de empacotamento externo (`u32 size | RC4 ciphertext | 16-byte key`) é reutilizável, portanto listeners customizados pelo ator podem manter o mesmo workflow de extração e alterar completamente o layout dos campos descriptografados.

Um bom exemplo recente é a campanha Tropic Trooper de março de 2026, na qual o Adaptix beacon extraído não continha um perfil HTTP/TCP padrão. Em vez disso, o blob descriptografado armazenava parâmetros de transporte do GitHub, como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por exemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estratégia prática de parser:
- Primeiro, detecte o blob RC4 externo exatamente como de costume.
- Após a descriptografia, escolha o schema com base em sentinel strings e na sanidade dos campos, em vez de forçar imediatamente o parser HTTP.
- Bons sentinels incluem `api.github.com`, `/issues?state=open`, verbos/URIs HTTP, strings no estilo named pipe ou arrays de server/port obviamente válidos.
- Se o parser HTTP falhar, mas o plaintext contiver strings UTF-8 coerentes e length-prefixed, mantenha o sample e tente schemas alternativos em vez de descartá-lo como false positive.

Nessa campanha, o custom listener usava GitHub issues como transporte de C2, e o beacon consultava `ipinfo.io` para descobrir seu IP externo, pois a API do GitHub não revela diretamente ao operador o endereço de origem da vítima.<sup>[[5]](#references)</sup>

## Network fingerprinting e hunting

HTTP:<sup>[[1]](#references)</sup>
- Comum: POST para URIs selecionadas pelo operador (por exemplo, /uri.php, /endpoint/api)
- Parâmetro de header customizado usado para o beacon ID (por exemplo, X‑Beacon‑Id, X‑App‑Id)
- User-agents imitando o Firefox 20 ou versões contemporâneas do Chrome
- Cadência de polling visível por meio de sleep_delay/jitter_delay
- Builds mais recentes podem alternar URIs, user-agents, headers Host e servers entre callbacks; portanto, faça o cluster com base em nomes de headers incomuns, padrões de tamanho de resposta, reutilização de TLS e timing, em vez de presumir um único par path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners de named pipe SMB para C2 em intranets onde a saída web é restrita
- TCP beacons podem prefixar alguns bytes antes do tráfego para ofuscar o início do protocolo

Defaults atuais do teamserver upstream
- O `profile.yaml` atualmente inclui o teamserver `0.0.0.0:4321`, o endpoint `/endpoint`, os nomes de arquivos de certificado/chave `server.rsa.crt` e `server.rsa.key`, e extenders para HTTP, SMB, TCP, DNS, Beacon agent e Gopher.<sup>[[2]](#references)</sup>
- Em rotas sem correspondência, o error handler padrão retorna `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- O corpo 404 padrão contém `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Scans em toda a Internet realizados em 2026 encontraram muitos teamservers expostos na porta `4321` e muitos beacon listeners na porta `43211`; portanto, ambas as portas são pivots iniciais úteis, mas não devem ser tratadas como exaustivas.<sup>[[4]](#references)</sup>

Fingerprints de DNS/DoH listener:<sup>[[4]](#references)</sup>
- O extender BeaconDNS atual responde autoritativamente (`AA=true`)
- Queries que não correspondem ao formato do protocolo do beacon — especialmente nomes com menos de 5 labels antes do domínio configurado — normalmente recebem como resposta `TXT "OK"`
- Se o TTL base configurado permanecer em zero, o listener usa uma base de 10 segundos e adiciona até 59 segundos de jitter
- Isso torna probes ativos com labels curtos úteis quando nenhum HTTP listener está exposto

## TTPs de loader e persistência observados em incidentes

Loaders de PowerShell in-memory:<sup>[[1]](#references)</sup>
- Fazem download de payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alocam memória unmanaged, copiam shellcode e alteram a proteção para 0x40 (PAGE_EXECUTE_READWRITE) por meio de VirtualProtect.<sup>[[7]](#references)</sup>
- Executam por meio de dynamic invocation do .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Loaders de shellcode staged / software assinado trojanizado:<sup>[[5]](#references)</sup>
- Uma cadeia do Tropic Trooper em 2026 usou um executável SumatraPDF trojanizado (loader TOSHIS) que redirecionava `_security_init_cookie` para código malicioso em vez de alterar o entry point do PE
- O loader resolvia APIs por meio de hashing Adler-32, fazia download de um PDF chamariz, obtinha shellcode de segundo estágio, descriptografava-o com AES-128-CBC por meio do WinCrypt (`CryptDeriveKey` a partir de uma seed hardcoded) e executava reflectively um Adaptix beacon na memória
- A persistência posteriormente passou a usar scheduled tasks com nomes aparentemente benignos, como `\MSDNSvc` ou `\MicrosoftUDN`, configuradas para relançar o agent aproximadamente a cada duas horas

Consulte estas páginas sobre execução in-memory e considerações de AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistência observados:<sup>[[1]](#references)</sup>
- Atalho da pasta Startup (.lnk) para relançar um loader no logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), frequentemente com nomes aparentemente benignos, como "Updater", para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack colocando msimg32.dll em %APPDATA%\Microsoft\Windows\Templates para processos suscetíveis

Análises detalhadas e verificações de técnicas:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideias de hunting
- PowerShell gerando transições RW→RX: VirtualProtect para PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Padrões de dynamic invocation (GetDelegateForFunctionPointer)
- Respostas HTTPS 404 sem correspondência contendo `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respostas DNS com `AA=true` e `TXT "OK"` para queries curtas em domínios suspeitos.<sup>[[4]](#references)</sup>
- Tráfego da API do GitHub para `/repos/<owner>/<repo>/issues` seguido por consultas a `ipinfo.io` na mesma cadeia de loader/beacon.<sup>[[5]](#references)</sup>
- .lnk de Startup nas pastas Startup do usuário ou comuns.<sup>[[1]](#references)</sup>
- Run keys suspeitas (por exemplo, "Updater") e nomes de loader como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Samples de PE trojanizados que redirecionam `_security_init_cookie` para código de downloader antes de exibir um documento chamariz.<sup>[[5]](#references)</sup>
- Caminhos de DLL graváveis pelo usuário em %APPDATA%\Microsoft\Windows\Templates contendo msimg32.dll.<sup>[[1]](#references)</sup>

## Notas sobre campos de OpSec

- KillDate: timestamp após o qual o agent expira automaticamente.<sup>[[1]](#references)</sup>
- WorkingTime: horários em que o agent deve estar ativo para se misturar à atividade comercial.<sup>[[1]](#references)</sup>

Esses campos podem ser usados para clustering e para explicar períodos de silêncio observados.

## YARA e indicadores estáticos

A Unit 42 publicou regras YARA básicas para beacons (C/C++ e Go) e constantes de API-hashing de loaders.<sup>[[1]](#references)</sup> Considere complementá-las com regras que procurem o layout [size|ciphertext|16‑byte‑key] próximo ao final de .rdata do PE, as strings do perfil HTTP padrão e markers mais recentes de server/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

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
