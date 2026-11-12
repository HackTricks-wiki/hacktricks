# Extração de configuração e TTPs do AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 é um framework modular, open source de post-exploitation/C2 com beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e suporte a BOF.<sup>[[1]](#references)</sup> Esta página documenta:
- Como a configuração compactada com RC4 é incorporada e como extraí-la dos beacons
- Indicadores de rede/perfil para listeners HTTP/SMB/TCP
- TTPs comuns de loader e persistência observadas em campo, com links para páginas relevantes sobre técnicas do Windows

As versões upstream recentes também incluem listeners de beacon DNS/DoH e a família separada de agents/listeners Gopher, portanto a infraestrutura moderna do Adaptix pode expor mais do que as superfícies HTTP/SMB/TCP originais, mesmo quando uma amostra específica ainda usa o agent beacon clássico.<sup>[[2]](#references)</sup>

## Perfis e campos de beacon

O AdaptixC2 oferece suporte a três tipos principais de beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web com servidores/portas/SSL configuráveis, método, URI, headers, user-agent e um nome de parâmetro personalizado
- BEACON_SMB: C2 peer-to-peer com named pipe (intranet)
- BEACON_TCP: sockets diretos, opcionalmente com um marcador prefixado para ofuscar o início do protocolo

Esses são os layouts de beacon documentados publicamente nas primeiras análises do Adaptix e ainda são o ponto de partida mais comum para a extração do lado da amostra.<sup>[[1]](#references)</sup> No entanto, as builds upstream atuais também incluem extensores `BeaconDNS` e Gopher no lado do servidor, portanto, não presuma que toda implantação ativa do Adaptix exponha apenas infraestrutura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

O resumo dos campos e as amostras JSON a seguir descrevem o formato HTTP analisado em 2025; não são uma especificação de parser para builds upstream mais recentes. Campos típicos nessas amostras (após a descriptografia):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (strings com prefixo de comprimento)
- ans_pre_size (u32), ans_size (u32) – usados para analisar os tamanhos das respostas
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

As builds recentes de BeaconHTTP também permitem que o operador selecione a rotação entre várias URIs, user-agents, headers Host e servidores, com seleção sequencial ou aleatória.<sup>[[2]](#references)</sup> Do ponto de vista de threat hunting, isso significa que um único host infectado pode se comunicar por vários caminhos de callback e combinações de headers, sem deixar de usar a família clássica de beacons compactados com RC4.

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

Quando o operador clica em Create no builder, o AdaptixC2 compila o perfil criptografado no beacon. Não presuma que ele esteja no final do PE ou do shellcode: localize os bytes do perfil por meio da varredura de seções ou seguindo `getProfile()` no sample. O formato empacotado é:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
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
- Toda a estrutura costuma estar dentro da seção .rdata do PE.
- A extração é determinística: leia o tamanho, leia o texto cifrado desse tamanho, leia a chave de 16 bytes posicionada imediatamente depois e, em seguida, descriptografe com RC4.

## Fluxo de trabalho para extração da configuração (defensores)

Para a triagem geral da amostra antes de extrair o beacon, consulte [Malware Analysis](malware-analysis.md).

Escreva um extrator que imite a lógica do beacon:<sup>[[1]](#references)</sup>
1) Localize o blob dentro do PE (comumente em .rdata). Uma abordagem prática é examinar .rdata em busca de um layout plausível [tamanho|texto cifrado|chave de 16 bytes] e tentar RC4.
2) Leia os primeiros 4 bytes → tamanho (uint32 LE).
3) Leia os próximos N=size bytes → texto cifrado.
4) Leia os 16 bytes finais → chave RC4.
5) Descriptografe o texto cifrado com RC4. Em seguida, analise o perfil em texto simples como:
   - escalares u32/booleanos, conforme indicado acima
   - strings prefixadas por comprimento (comprimento u32 seguido por bytes; pode haver um NUL final)
   - arrays: servers_count seguido por esse número de pares [string, porta u32]

Prova de conceito em Python para HTTP legado (independente, sem dependências externas) para um blob extraído previamente na ordem de campos de 2025. Use o parser do esquema atual abaixo para builds recentes do stock:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Analisar os perfis HTTP e DNS atuais de fábrica

O upstream atual empacota primeiro seis valores `u32` little-endian: watermark/tipo do agent, data de encerramento, horário de funcionamento, sleep, jitter e watermark/tipo do listener. Os dados específicos de HTTP começam então com um flag SSL de um byte. Diferentemente do exemplo legado, há listas contadas de URI, user-agent e cabeçalhos Host, seguidas pelo modo de rotação e pelas configurações de proxy. Portanto, o parser legado começa a ler o flag SSL a partir do campo da data de encerramento e produz resultados incorretos nessas builds. Os comprimentos das strings e os valores inteiros neste perfil usam codificação little-endian; strings empacotadas incluem um NUL final quando não estão vazias.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Com os helpers `P` e `rc4` acima, use este parser no plaintext HTTP de fábrica descriptografado. Não inclua a chave RC4 em relatórios públicos: o perfil HTTP pode conter um nome de usuário e uma senha de proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Analisar um perfil plaintext HTTP atual de fábrica</summary>

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

Para um beacon DNS padrão, leia os mesmos seis campos `u32` comuns e, em seguida, as strings `domain`, `resolvers`, `doh_resolvers` e `qtype`, prefixadas pelo comprimento. Leia `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` e `dns_mode` como `u32` e, depois, a string do user-agent DoH, prefixada pelo comprimento. `dns_mode` distingue UDP, DoH e as duas direções de fallback. Este é um layout separado: não force o plaintext de DNS pelo parser HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Dicas:
- Ao automatizar, use um parser de PE para ler .rdata e, em seguida, aplique uma janela deslizante: para cada offset o, tente size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = os 16 bytes seguintes; descriptografe com RC4 e verifique se os campos de string são decodificados como UTF-8 e se os comprimentos são plausíveis.
- Analise perfis SMB/TCP seguindo as mesmas convenções de prefixo de comprimento.

## Perfis de listener personalizados: não codifique apenas o esquema HTTP clássico

O formato externo de empacotamento (`u32 size | RC4 ciphertext | 16-byte key`) é reutilizável, portanto, listeners personalizados por atores podem manter o mesmo fluxo de extração enquanto alteram completamente o layout dos campos descriptografados.

Um bom exemplo recente é a campanha Tropic Trooper de março de 2026, na qual o beacon Adaptix extraído não continha um perfil HTTP/TCP padrão. Em vez disso, o blob descriptografado armazenava parâmetros de transporte do GitHub, como:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (por exemplo, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Estratégia prática para o parser:
- Primeiro, detecte o blob RC4 externo exatamente como de costume.
- Após a descriptografia, escolha o parser com base em strings sentinela e na plausibilidade dos campos, em vez de forçar imediatamente o parser HTTP.
- Boas sentinelas incluem `api.github.com`, `/issues?state=open`, verbos/URIs HTTP, strings no formato de named pipe ou arrays de servidor/porta obviamente válidos.
- Se o parser HTTP falhar, mas o plaintext contiver strings UTF-8 coerentes prefixadas pelo comprimento, preserve a amostra e tente esquemas alternativos em vez de descartá-la como falso positivo.

Nessa campanha, o listener personalizado usava issues do GitHub como transporte de C2, e o beacon consultava `ipinfo.io` para descobrir seu IP externo, pois a API do GitHub não revela diretamente ao operador o endereço de origem da vítima.<sup>[[5]](#references)</sup> Para um handshake separado baseado em issue e arquivo de repositório, consulte [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Fingerprinting de rede e hunting

HTTP:<sup>[[1]](#references)</sup>
- Comum: POST para URIs selecionadas pelo operador (por exemplo, /uri.php, /endpoint/api)
- Parâmetro de cabeçalho personalizado usado para o ID do beacon (por exemplo, X‑Beacon‑Id, X‑App‑Id)
- User-agents que imitam o Firefox 20 ou versões contemporâneas do Chrome
- Cadência de polling visível por meio de sleep_delay/jitter_delay
- Versões mais recentes podem alternar URIs, user-agents, cabeçalhos Host e servidores entre callbacks; portanto, agrupe com base em nomes de cabeçalho incomuns, padrões de tamanho de resposta, reutilização de TLS e temporização, em vez de presumir um único par de caminho/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners SMB named pipe para C2 de intranet quando a saída web é restrita
- Beacons TCP podem acrescentar alguns bytes antes do tráfego para ofuscar o início do protocolo

Padrões atuais do teamserver upstream
- Atualmente, `profile.yaml` vem com teamserver em `0.0.0.0:4321`, endpoint `/endpoint`, nomes de arquivos de certificado/chave `server.rsa.crt` e `server.rsa.key`, além de extenders para HTTP, SMB, TCP, DNS, agente Beacon e Gopher.<sup>[[2]](#references)</sup>
- Para rotas não correspondentes, o handler de erro padrão retorna `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- O corpo padrão do 404 contém `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Varreduras em toda a Internet em 2026 encontraram muitos teamservers expostos na porta `4321` e muitos listeners de beacon na porta `43211`; portanto, ambas as portas são pontos de partida úteis para pivots, mas não devem ser consideradas exaustivas.<sup>[[4]](#references)</sup>

Fingerprinting de listeners DNS/DoH:<sup>[[4]](#references)</sup>
- O extender BeaconDNS atual responde autoritativamente (`AA=true`)
- Consultas que não correspondem ao formato do protocolo do beacon — em especial, nomes com menos de 5 labels antes do domínio configurado — geralmente recebem como resposta `TXT "OK"`
- Se o TTL base configurado permanecer em zero, o listener usa uma base de 10 segundos e adiciona até 59 segundos de jitter
- Isso torna sondagens ativas com labels curtos úteis quando nenhum listener HTTP está exposto

## TTPs de loaders e persistência observadas em incidentes

Loaders PowerShell em memória:<sup>[[1]](#references)</sup>
- Baixam payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alocam memória não gerenciada, copiam shellcode e alteram a proteção para 0x40 (PAGE_EXECUTE_READWRITE) por meio de VirtualProtect.<sup>[[7]](#references)</sup>
- Executam por invocação dinâmica de .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Loaders de shellcode staged / software assinado trojanizado:<sup>[[5]](#references)</sup>
- Uma cadeia Tropic Trooper de 2026 usou um executável SumatraPDF trojanizado (loader TOSHIS) que redirecionava `_security_init_cookie` para código malicioso, em vez de modificar o ponto de entrada do PE
- O loader resolvia APIs por hashing Adler-32, baixava um PDF chamariz, obtinha shellcode de segundo estágio, descriptografava-o com AES-128-CBC por meio do WinCrypt (`CryptDeriveKey` a partir de uma seed hardcoded) e executava reflexivamente um beacon Adaptix em memória
- Mais tarde, a persistência passou a usar tarefas agendadas com nomes aparentemente legítimos, como `\MSDNSvc` ou `\MicrosoftUDN`, configuradas para iniciar novamente o agente aproximadamente a cada duas horas

Consulte estas páginas sobre execução em memória e considerações sobre AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mecanismos de persistência observados:<sup>[[1]](#references)</sup>
- Atalho (.lnk) na pasta Startup para iniciar novamente um loader no logon
- Chaves Run do Registro (HKCU/HKLM ...\CurrentVersion\Run), geralmente com nomes aparentemente legítimos, como "Updater", para iniciar loader.ps1.<sup>[[10]](#references)</sup>
- Hijack da ordem de busca de DLL ao colocar msimg32.dll em %APPDATA%\Microsoft\Windows\Templates para processos vulneráveis

Análises aprofundadas de técnicas e verificações:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideias para hunting
- PowerShell iniciando transições RW→RX: VirtualProtect para PAGE_EXECUTE_READWRITE dentro de powershell.exe.<sup>[[8]](#references)</sup>
- Padrões de invocação dinâmica (GetDelegateForFunctionPointer)
- Respostas 404 HTTPS sem correspondência com `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Respostas DNS com `AA=true` e `TXT "OK"` para consultas curtas em domínios suspeitos.<sup>[[4]](#references)</sup>
- Tráfego da API do GitHub para `/repos/<owner>/<repo>/issues`, seguido de consultas a `ipinfo.io` pela mesma cadeia de loader/beacon.<sup>[[5]](#references)</sup>
- Arquivo .lnk na pasta Startup do usuário ou na pasta Startup comum.<sup>[[1]](#references)</sup>
- Chaves Run suspeitas (por exemplo, "Updater") e nomes de loaders como update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Amostras de PE trojanizadas que redirecionam `_security_init_cookie` para código de downloader antes de exibir um documento chamariz.<sup>[[5]](#references)</sup>
- Caminhos de DLL graváveis pelo usuário em %APPDATA%\Microsoft\Windows\Templates contendo msimg32.dll.<sup>[[1]](#references)</sup>

## Observações sobre campos de OpSec

- KillDate: timestamp após o qual o agente expira automaticamente.<sup>[[1]](#references)</sup>
- WorkingTime: horários em que o agente deve estar ativo para se misturar à atividade comercial.<sup>[[1]](#references)</sup>

Esses campos podem ser usados para clustering e para explicar períodos de inatividade observados.

## YARA e indicadores estáticos

A Unit 42 publicou regras YARA básicas para beacons (C/C++ e Go) e constantes de hashing de API de loaders.<sup>[[1]](#references)</sup> Considere complementar com regras que procurem o layout [size|ciphertext|16-byte-key] perto do final de PE .rdata, as strings do perfil HTTP padrão e indicadores mais recentes de servidor/listener, como `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Um novo framework open-source usado em ataques no mundo real (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentação do Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting de um framework C2 open-source em larga escala (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper adota AdaptixC2 e listener de beacon personalizado (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de proteção de memória – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Chaves Run do Registro/Pasta Startup](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Geração de perfil AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser de perfil de beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Geração de perfil DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Empacotamento de perfil AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
