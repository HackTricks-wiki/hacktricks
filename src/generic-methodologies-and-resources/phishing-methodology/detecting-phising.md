# Detectando Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página principal deste post, você pode encontrar essas informações; portanto, se não estiver ciente de quais técnicas estão sendo usadas hoje, recomendo acessar a página principal e ler pelo menos essa seção.

Este post baseia-se na ideia de que os **atacantes tentarão, de alguma forma, imitar ou usar o nome de domínio da vítima**. Se o seu domínio se chama `example.com` e você sofrer phishing usando, por algum motivo, um nome de domínio completamente diferente, como `youwonthelottery.com`, estas técnicas não irão descobri-lo.

## Variações de nomes de domínio

É relativamente **fácil** **descobrir** essas tentativas de **phishing** que usarão um nome de **domínio semelhante** dentro do e-mail.\
Basta **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se estão **registrados**, ou simplesmente verificar se existe algum **IP** usando-os.

### Encontrando domínios suspeitos

Para essa finalidade, você pode usar qualquer uma das seguintes ferramentas. Observe que essas ferramentas também executarão solicitações DNS automaticamente para verificar se o domínio possui algum IP atribuído a ele:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Dica: se você gerar uma lista de candidatos, também a alimente com os logs do seu resolvedor DNS para detectar **consultas NXDOMAIN originadas de dentro da sua organização** (usuários tentando acessar um typo antes que o atacante realmente o registre). Faça sinkhole ou bloqueie previamente esses domínios, se a política permitir.

### Bitflipping

**Você pode encontrar uma breve explicação dessa técnica na página principal. Ou ler a pesquisa original em** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios bit-flipping relacionados à vítima para redirecionar usuários legítimos para a infraestrutura deles**.<sup>[[1]](#references)</sup>

**Todos os possíveis nomes de domínio bit-flipping também devem ser monitorados.**

Se você também precisar considerar homoglyph/IDN lookalikes (por exemplo, misturando caracteres Latinos/Cirílicos), verifique:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Verificações básicas

Depois de obter uma lista de possíveis nomes de domínio suspeitos, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se estão usando algum formulário de login semelhante** ao de alguém do domínio da vítima.\
Você também pode verificar a porta 3333 para ver se está aberta e executando uma instância de `gophish`.\
Também é interessante saber **há quanto tempo cada domínio suspeito descoberto existe**; quanto mais recente, maior o risco.\
Você também pode obter **screenshots** da página web HTTP e/ou HTTPS suspeita para verificar se ela é suspeita e, nesse caso, **acessá-la para analisá-la mais detalhadamente**.

### Verificações avançadas

Se quiser ir um passo além, recomendo **monitorar esses domínios suspeitos e procurar mais alguns** de tempos em tempos (todos os dias? isso leva apenas alguns segundos/minutos). Você também deve **verificar** as **portas** abertas dos IPs relacionados e **procurar instâncias de `gophish` ou ferramentas semelhantes** (sim, os atacantes também cometem erros), além de **monitorar as páginas web HTTP e HTTPS dos domínios e subdomínios suspeitos** para verificar se copiaram algum formulário de login das páginas web da vítima.\
Para **automatizar isso**, recomendo manter uma lista dos formulários de login dos domínios da vítima, fazer spider das páginas web suspeitas e comparar cada formulário de login encontrado dentro dos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, pode tentar **enviar credenciais falsas** e **verificar se ele está redirecionando você para o domínio da vítima**.

---

### Hunting por favicon e web fingerprints (Shodan/ZoomEye/Censys)

Muitos kits de phishing reutilizam favicons da marca que estão imitando. Scanners de toda a Internet calculam um MurmurHash3 do favicon codificado em base64. Você pode gerar o hash e fazer pivot nele:

Exemplo em Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar o Shodan: `http.favicon.hash:309020573`
- Com ferramentas: confira ferramentas da comunidade, como favfreak, para gerar hashes e dorks para Shodan/ZoomEye/Censys.

Notas
- Favicons são reutilizados; trate as correspondências como pistas e valide o conteúdo e os certificados antes de agir.
- Combine com heurísticas de idade do domínio e palavras-chave para obter maior precisão.

### Busca de telemetria de URLs (urlscan.io)

O `urlscan.io` armazena screenshots históricos, DOM, requisições e metadados TLS de URLs enviadas. Você pode buscar por abuso de marca e clones:<sup>[[2]](#references)</sup>

Exemplos de consultas (UI ou API):
- Encontrar sósias, excluindo seus domínios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontrar sites que fazem hotlink dos seus assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restringir aos resultados recentes: append `AND date:>now-7d`

Exemplo de API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
No JSON, faça uma pivotagem por:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para identificar certificados muito novos em lookalikes
- valores de `task.source`, como `certstream-suspicious`, para relacionar as descobertas ao monitoramento de CT

### Idade do domínio via RDAP (scriptável)

O RDAP retorna eventos de criação em formato legível por máquina. Útil para sinalizar **domínios recém-registrados (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriqueça seu pipeline marcando domínios com categorias de idade de registro (por exemplo, <7 dias, <30 dias) e priorize a triagem de acordo com isso.

### TLS/JAx fingerprints para identificar infraestrutura AiTM

O phishing de credenciais moderno usa cada vez mais reverse proxies **Adversary-in-the-Middle (AiTM)** (por exemplo, Evilginx) para roubar session tokens. Você pode adicionar detecções no lado da rede:

- Registre fingerprints TLS/HTTP (JA3/JA4/JA4S/JA4H) no egress. Algumas builds do Evilginx foram observadas com valores JA4 estáveis de cliente/servidor. Gere alertas apenas para fingerprints conhecidos como maliciosos, tratando-os como um sinal fraco, e sempre confirme com informações de conteúdo e do domínio.<sup>[[3]](#references)</sup>
- Registre proativamente os metadados dos certificados TLS (emissor, quantidade de SANs, uso de wildcard, validade) para lookalike hosts descobertos via CT ou urlscan e correlacione-os com a idade do DNS e a geolocalização.

> Nota: trate fingerprints como enriquecimento, não como bloqueadores únicos; os frameworks evoluem e podem randomizar ou ofuscar esses dados.

### Nomes de domínio usando keywords

A página principal também menciona uma técnica de variação de nome de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Não é possível usar a abordagem anterior de "Brute-Force", mas na prática é **possível descobrir essas tentativas de phishing** também graças ao certificate transparency. Sempre que um certificado é emitido por uma CA, os detalhes são publicados. Isso significa que, lendo ou monitorando o certificate transparency, é **possível encontrar domínios que usam uma keyword dentro do nome**. Por exemplo, se um atacante gerar um certificado para [https://paypal-financial.com](https://paypal-financial.com), ao analisar o certificado será possível encontrar a keyword "paypal" e saber que um email suspeito está sendo usado.

A publicação [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugere que você pode usar o Censys para pesquisar certificados relacionados a uma keyword específica e filtrar por data (apenas certificados "novos") e pelo emissor da CA "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

No entanto, você pode fazer "a mesma coisa" usando o serviço web gratuito [**crt.sh**](https://crt.sh). Você pode **pesquisar pela keyword** e **filtrar** os resultados **por data e CA**, se desejar.

![Domain names using keywords - Certificate Transparency: However, you can do "the same" using the free web crt.sh . You can search for the keyword and the filter the results by date and...](<../../images/image (519).png>)

Usando esta última opção, você pode até utilizar o campo Matching Identities para verificar se alguma identidade do domínio real corresponde a algum dos domínios suspeitos (observe que um domínio suspeito pode ser um falso positivo).

**Outra alternativa** é o excelente projeto chamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). O CertStream fornece um stream em tempo real de certificados recém-gerados, que você pode usar para detectar keywords especificadas em (quase) tempo real. Na verdade, existe um projeto chamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que faz exatamente isso.

Dica prática: ao fazer a triagem de resultados do CT, priorize NRDs, registrars não confiáveis/desconhecidos, WHOIS com privacy-proxy e certificados com horários `NotBefore` muito recentes. Mantenha uma allowlist dos seus domínios/marcas para reduzir o ruído.

#### **Novos domínios**

**Uma última alternativa** é reunir uma lista de **domínios recém-registrados** para alguns TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornece esse serviço) e **verificar as keywords nesses domínios**. No entanto, domínios longos geralmente usam um ou mais subdomínios; portanto, a keyword não aparecerá dentro do FLD e você não conseguirá encontrar o subdomínio de phishing.

Heurística adicional: trate determinados **TLDs que usam extensões de arquivo** (por exemplo, `.zip`, `.mov`) com suspeita adicional nos alertas. Eles são frequentemente confundidos com nomes de arquivos em lures; combine o sinal do TLD com keywords de marcas e a idade do NRD para obter maior precisão.

## Referências

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
