# Extração de configuração e TTPs do AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 é um framework modular e open source de pós-exploração/C2, com beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e suporte a BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Como a configuração empacotada com RC4 é incorporada e como extraí-la dos beacons
- Indicadores de rede/perfil para listeners HTTP/SMB/TCP
- TTPs comuns de loader e persistência observadas na natureza, com links para páginas relevantes sobre técnicas do Windows

As versões upstream recentes também incluem listeners de beacon DNS/DoH e a família separada de agentes/listeners Gopher; portanto, a infraestrutura Adaptix moderna pode expor mais do que as superfícies HTTP/SMB/TCP originais, mesmo quando uma amostra específica ainda usa o agente beacon clássico.<sup>[[2]](#references)</sup>

## Perfis e campos do Beacon

O AdaptixC2 oferece suporte a três tipos principais de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web com servidores/portas/SSL configuráveis, método, URI, headers, user-agent e um nome de parâmetro personalizado
- BEACON_SMB: C2 peer-to-peer por named pipe (intranet)
- BEACON_TCP: sockets diretos, opcionalmente com um marcador prefixado para ofuscar o início do protocolo

Esses são os layouts de beacon documentados publicamente nas primeiras análises do Adaptix e continuam sendo o ponto de partida mais comum para extração do lado da amostra.<sup>[[1]](#references)</sup> No entanto, as builds upstream atuais também incluem extensões `BeaconDNS` e Gopher no lado do servidor; portanto, não presuma que toda implantação ativa do Adaptix exponha apenas infraestrutura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campos típicos de perfil observados em configurações de beacon HTTP (após a descriptografia):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (strings prefixadas por comprimento)
- ans_pre_size (u32), ans_size (u32) – usados para analisar tamanhos de resposta
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

As builds recentes do BeaconHTTP também permitem que o operador selecione a rotação entre vários URIs, user-agents, headers Host e servidores, de forma sequencial ou aleatória.<sup>[[2]](#references)</sup> Do ponto de vista de hunting, isso significa que um único host infectado pode distribuir callbacks por vários caminhos e combinações de headers sem deixar de pertencer à família clássica de beacons empacotados com RC4.

Exemplo de perfil HTTP padrão (de uma build de beacon):<sup>[[1]](#references)</sup>

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

Quando o operador clica em Create no builder, AdaptixC2 incorpora o perfil criptografado como um blob no final do beacon. O formato é:<sup>[[1]](#references)</sup>
- 4 bytes: tamanho da configuração (uint32, little-endian)
- N bytes: dados da configuração criptografados com RC4
- 16 bytes: chave RC4

O loader do beacon copia a chave de 16 bytes do final e descriptografa com RC4 o bloco de N bytes in place:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implicações práticas:<sup>[[1]](#references)</sup>
- Toda a estrutura costuma estar na seção .rdata do PE.
- A extração é determinística: leia o tamanho, leia o ciphertext desse tamanho, leia a chave de 16 bytes posicionada logo depois e, em seguida, descriptografe com RC4.

## Fluxo de trabalho de extração da configuração (defensores)

Escreva um extractor que imite a lógica do beacon:<sup>[[1]](#references)</sup>
1) Localize o blob dentro do PE (geralmente em .rdata). Uma abordagem prática é procurar em .rdata um layout plausível [tamanho|ciphertext|chave de 16 bytes] e tentar RC4.
2) Leia os primeiros 4 bytes → tamanho (uint32 LE).
3) Leia os próximos N=size bytes → ciphertext.
4) Leia os últimos 16 bytes → chave RC4.
5) Descriptografe o ciphertext com RC4. Em seguida, analise o perfil em texto simples como:
   - escalares u32/boolean, conforme indicado acima
   - strings prefixadas pelo comprimento (comprimento u32 seguido dos bytes; pode haver um NUL final)
   - arrays: servers_count seguido desse número de pares [string, porta u32]

Prova de conceito mínima em Python (independente, sem dependências externas) que funciona com um blob pré-extraído:

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
- Ao automatizar, use um parser de PE para ler .rdata e aplique uma janela deslizante: para cada offset o, tente size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = os próximos 16 bytes; descriptografe com RC4 e verifique se os campos de texto são decodificados como UTF-8 e se os comprimentos são plausíveis.
- Analise os perfis SMB/TCP seguindo as mesmas convenções de comprimento prefixado.

## Perfis de listener personalizados: não limite o parser ao esquema HTTP clássico

O formato externo de empacotamento (`u32 size | RC4 ciphertext | 16-byte key`) pode ser reutilizado; assim, listeners personalizados por atores podem manter o mesmo fluxo de extração, mas alterar completamente o layout dos campos descriptografados.

Um bom exemplo recente é a campanha Tropic Trooper de março de 2026, na qual o Adaptix beacon extraído não continha um perfil HTTP/TCP padrão. Em vez disso, o blob descriptografado armazenava parâmetros de transporte do GitHub, como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por exemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estratégia prática para o parser:
- Primeiro, detecte o blob RC4 externo exatamente como de costume.
- Após a descriptografia, escolha o caminho com base em strings sentinela e na plausibilidade dos campos, em vez de forçar imediatamente o parser HTTP.
- Boas sentinelas incluem `api.github.com`, `/issues?state=open`, verbos/URIs HTTP, strings no estilo de named pipe ou arrays de servidor/porta obviamente válidos.
- Se o parser HTTP falhar, mas o texto claro contiver strings UTF-8 coerentes com comprimento prefixado, mantenha a amostra e tente esquemas alternativos em vez de descartá-la como falso positivo.

Nessa campanha, o listener personalizado usava issues do GitHub como transporte C2, e o beacon consultava `ipinfo.io` para descobrir seu IP externo, pois a API do GitHub não revela diretamente ao operador o endereço de origem da vítima.<sup>[[5]](#references)</sup>

## Fingerprinting de rede e hunting

HTTP:<sup>[[1]](#references)</sup>
- Comum: POST para URIs escolhidas pelo operador (por exemplo, /uri.php, /endpoint/api)
- Parâmetro de cabeçalho personalizado usado como ID do beacon (por exemplo, X‑Beacon‑Id, X‑App‑Id)
- User-agents que imitam o Firefox 20 ou versões contemporâneas do Chrome
- Cadência de polling visível por meio de sleep_delay/jitter_delay
- Versões mais recentes podem alternar URIs, user-agents, cabeçalhos Host e servidores entre callbacks; portanto, agrupe por nomes de cabeçalho incomuns, padrões de tamanho de resposta, reutilização de TLS e temporização, em vez de presumir um único par de caminho/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners SMB named pipe para C2 em intranets onde a saída para a web é restrita
- Beacons TCP podem acrescentar alguns bytes antes do tráfego para ofuscar o início do protocolo

Padrões atuais do teamserver upstream
- Atualmente, `profile.yaml` vem com teamserver em `0.0.0.0:4321`, endpoint `/endpoint`, nomes de arquivos de certificado/chave `server.rsa.crt` e `server.rsa.key`, além de extensões para HTTP, SMB, TCP, DNS, Beacon agent e Gopher.<sup>[[2]](#references)</sup>
- Para rotas sem correspondência, o handler de erro padrão retorna `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- O corpo 404 padrão contém `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Scans em toda a internet em 2026 encontraram muitos teamservers expostos na porta `4321` e muitos listeners de beacon na `43211`; portanto, ambas as portas são pivôs iniciais úteis, mas não devem ser consideradas exaustivas.<sup>[[4]](#references)</sup>

Fingerprints de listeners DNS/DoH:<sup>[[4]](#references)</sup>
- A extensão BeaconDNS atual responde de forma autoritativa (`AA=true`)
- Consultas que não correspondem ao formato do protocolo do beacon — em especial, nomes com menos de 5 labels antes do domínio configurado — costumam receber a resposta `TXT "OK"`
- Se o TTL base configurado permanecer em zero, o listener usa um valor base de 10 segundos e adiciona até 59 segundos de jitter
- Isso torna sondagens ativas com labels curtos úteis quando não há um listener HTTP exposto

## TTPs de loader e persistência observadas em incidentes

Loaders PowerShell em memória:<sup>[[1]](#references)</sup>
- Baixam payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alocam memória não gerenciada, copiam o shellcode e alteram a proteção para 0x40 (PAGE_EXECUTE_READWRITE) por meio de VirtualProtect.<sup>[[7]](#references)</sup>
- Executam por meio de invocação dinâmica do .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Loaders de shellcode em etapas / software assinado adulterado:<sup>[[5]](#references)</sup>
- Uma cadeia do Tropic Trooper em 2026 usou um executável SumatraPDF adulterado (loader TOSHIS) que redirecionava `_security_init_cookie` para código malicioso, em vez de alterar o ponto de entrada do PE
- O loader resolvia APIs por hashing Adler-32, baixava um PDF chamariz, obtinha shellcode de segundo estágio, descriptografava-o com AES-128-CBC por meio do WinCrypt (`CryptDeriveKey` a partir de uma seed codificada) e executava reflexivamente um Adaptix beacon em memória
- Depois, a persistência passou a usar tarefas agendadas com nomes aparentemente benignos, como `\MSDNSvc` ou `\MicrosoftUDN`, configuradas para relançar o agente aproximadamente a cada duas horas

Consulte estas páginas sobre execução em memória e considerações sobre AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistência observados:<sup>[[1]](#references)</sup>
- Atalho (.lnk) na pasta Startup para relançar um loader no logon
- Chaves Run do Registro (HKCU/HKLM ...\CurrentVersion\Run), frequentemente com nomes aparentemente benignos, como "Updater", para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- Sequestro da ordem de pesquisa de DLL ao colocar msimg32.dll em %APPDATA%\Microsoft\Windows\Templates para processos vulneráveis

Análises aprofundadas de técnicas e verificações:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideias para hunting
- PowerShell criando transições RW→RX: VirtualProtect para PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Padrões de invocação dinâmica (GetDelegateForFunctionPointer)
- Respostas HTTPS 404 sem correspondência com `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respostas DNS com `AA=true` e `TXT "OK"` para consultas curtas em domínios suspeitos.<sup>[[4]](#references)</sup>
- Tráfego da API do GitHub para `/repos/<owner>/<repo>/issues` seguido de consultas a `ipinfo.io` na mesma cadeia de loader/beacon.<sup>[[5]](#references)</sup>
- Arquivos .lnk na pasta Startup do usuário ou compartilhada.<sup>[[1]](#references)</sup>
- Chaves Run suspeitas (por exemplo, "Updater") e nomes de loader como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Amostras de PE adulteradas que redirecionam `_security_init_cookie` para código de download antes de exibir um documento chamariz.<sup>[[5]](#references)</sup>
- Caminhos de DLL graváveis pelo usuário em %APPDATA%\Microsoft\Windows\Templates contendo msimg32.dll.<sup>[[1]](#references)</sup>

## Observações sobre campos de OpSec

- KillDate: timestamp após o qual o agente expira por conta própria.<sup>[[1]](#references)</sup>
- WorkingTime: horários em que o agente deve estar ativo para se misturar à atividade comercial.<sup>[[1]](#references)</sup>

Esses campos podem ser usados para agrupar amostras e explicar períodos de inatividade observados.

## YARA e indicadores estáticos

A Unit 42 publicou regras YARA básicas para beacons (C/C++ e Go) e constantes de hashing de API usadas por loaders.<sup>[[1]](#references)</sup> Considere complementá-las com regras que procurem o layout [size|ciphertext|16-byte-key] próximo ao fim de .rdata do PE, as strings do perfil HTTP padrão e marcadores mais recentes de servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Uma nova framework open source explorada em ataques reais (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 no GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentação do Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting de uma framework C2 open source em grande escala (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper adota AdaptixC2 e um listener de beacon personalizado (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Documentação da Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Documentação da Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de proteção de memória – Documentação da Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Chaves Run do Registro/Pasta Startup](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
