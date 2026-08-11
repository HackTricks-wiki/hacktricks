# Detectando Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página pai deste post, você pode encontrar essas informações; portanto, se não estiver ciente de quais técnicas estão sendo usadas hoje, recomendo acessar a página pai e ler pelo menos essa seção.

Este post baseia-se na ideia de que os **atacantes tentarão, de alguma forma, imitar ou usar o nome de domínio da vítima**. Se o seu domínio se chama `example.com` e você for vítima de phishing usando, por algum motivo, um nome de domínio completamente diferente, como `youwonthelottery.com`, estas técnicas não irão descobri-lo.

## Variações do nome de domínio

É relativamente **fácil** **descobrir** essas tentativas de **phishing** que usarão um nome de **domínio semelhante** dentro do e-mail.\
Basta **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se estão **registrados** ou simplesmente verificar se existe algum **IP** usando-os.

### Encontrando domínios suspeitos

Para essa finalidade, você pode usar qualquer uma das seguintes ferramentas. Ambas resolvem os domínios candidatos para verificar se estão em uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Dica: Se você gerar uma lista de candidatos, também a envie aos seus logs de resolução DNS para detectar **consultas NXDOMAIN originadas dentro da sua organização** (usuários tentando acessar um typo antes que o atacante realmente o registre). Faça sinkhole ou bloqueie previamente esses domínios, se a política permitir.

### Bitflipping

**Para uma breve explicação, consulte a página pai; para a pesquisa primária sobre bitsquatting em Windows.com, consulte o [write-up de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) e o [relatório da BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o máximo possível de domínios de bit-flipping relacionados à vítima para redirecionar usuários legítimos para a infraestrutura deles**.<sup>[[1]](#references)[[2]](#references)</sup>

**Todos os possíveis nomes de domínio de bit-flipping também devem ser monitorados.**

Se você também precisar considerar homoglyph/IDN lookalikes (por exemplo, misturando caracteres latinos e cirílicos), consulte:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Verificações básicas

Depois de obter uma lista de possíveis nomes de domínio suspeitos, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se estão usando algum formulário de login semelhante** ao de algum domínio da vítima.\
Você também pode verificar a porta 3333 para ver se está aberta e executando uma instância do `gophish`.\
Também é interessante saber **há quanto tempo cada domínio suspeito descoberto existe**; quanto mais recente, maior o risco.\
Você também pode obter **screenshots** da página web suspeita em HTTP e/ou HTTPS para verificar se ela é suspeita e, nesse caso, **acessá-la para analisá-la mais profundamente**.

### Verificações avançadas

Se quiser ir um passo além, recomendo **monitorar esses domínios suspeitos e procurar mais alguns** de tempos em tempos (todos os dias? isso leva apenas alguns segundos/minutos). Você também deve **verificar** as **portas** abertas dos IPs relacionados e **procurar instâncias do `gophish` ou de ferramentas semelhantes** (sim, os atacantes também cometem erros), além de **monitorar as páginas web HTTP e HTTPS dos domínios e subdomínios suspeitos** para verificar se copiaram algum formulário de login das páginas web da vítima.\
Para **automatizar isso**, recomendo manter uma lista dos formulários de login dos domínios da vítima, fazer spidering das páginas web suspeitas e comparar cada formulário de login encontrado nos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, pode tentar **enviar credenciais falsas** e **verificar se há um redirecionamento para o domínio da vítima**.

---

### Hunting por favicon e web fingerprints (Shodan/Censys)

Muitos kits de phishing reutilizam favicons da marca que estão imitando. O Shodan calcula o hash dos dados do favicon codificados em base64 usando MurmurHash3, enquanto o Censys expõe seus próprios campos de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Você pode gerar um hash compatível com o Shodan e fazer pivoting usando-o:

Exemplo em Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar o Shodan: `http.favicon.hash:309020573`
- Com ferramentas: consulte ferramentas da comunidade, como favfreak, para calcular hashes e gerar dorks do Shodan.<sup>[[16]](#references)</sup>

Notas
- Favicons são reutilizados; trate as correspondências como pistas e valide o conteúdo e os certificados antes de agir.
- Combine com heurísticas de idade do domínio e palavras-chave para obter maior precisão.

### Busca de telemetria de URLs (urlscan.io)

O `urlscan.io` armazena screenshots históricos, DOM, requisições e metadados de TLS de URLs enviadas. Você pode buscar abusos de marca e clones:<sup>[[8]](#references)</sup>

Exemplos de consultas (UI ou API):
- Encontrar sites semelhantes, excluindo seus domínios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontrar sites que fazem hotlink dos seus assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restringir aos resultados recentes: acrescentar `AND date:>now-7d`

Exemplo de API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
A partir do JSON, faça pivot em:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para identificar certificados muito novos em lookalikes
- valores de `task.source` como `certstream-suspicious` para vincular as descobertas ao monitoramento de CT

### Idade do domínio via RDAP (scriptável)

O RDAP retorna eventos de registro legíveis por máquinas. Útil para sinalizar **domínios recém-registrados (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriqueça seu pipeline marcando os domínios com categorias de idade de registro (por exemplo, <7 dias, <30 dias) e priorize a triagem de acordo com isso.

### Fingerprints TLS/JAx para identificar infraestrutura AiTM

O phishing de credenciais pode usar reverse proxies **Adversary-in-the-Middle (AiTM)** (por exemplo, Evilginx) para roubar tokens de sessão.<sup>[[11]](#references)</sup> Você pode adicionar detecções no nível da rede:

- Registre fingerprints TLS/HTTP (JA3/JA4/JA4S/JA4H) na saída da rede. Algumas versões do Evilginx foram observadas com valores JA4 estáveis de cliente/servidor. Gere alertas para fingerprints conhecidos como maliciosos apenas como um sinal fraco e sempre confirme com informações de conteúdo e domínio.<sup>[[12]](#references)</sup>
- Registre proativamente os metadados dos certificados TLS (emissor, quantidade de SANs, uso de wildcard, validade) para hosts semelhantes descobertos via CT ou urlscan e correlacione-os com a idade do DNS e a geolocalização.

> Observação: trate os fingerprints como enriquecimento, não como bloqueadores únicos; os frameworks evoluem e podem randomizar ou ofuscar os fingerprints.

### Nomes de domínio usando keywords

A página principal também menciona uma técnica de variação de nome de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Os logs de Certificate Transparency (CT) expõem as identidades dos certificados; portanto, pesquisar nomes de Subject ou SAN por keywords de marcas pode revelar domínios semelhantes (por exemplo, um certificado para `paypal-financial.com` expõe a keyword `paypal`). Filtre os resultados por data de emissão e CA quando for útil e valide os candidatos, pois correspondências de keywords podem gerar falsos positivos.<sup>[[13]](#references)</sup>

O [write-up original sobre busca de domínios de phishing](https://0xpatrik.com/phishing-domains/) de Patrik Hudak demonstra esse fluxo de trabalho no Censys, incluindo filtros para data e emissor do certificado, como Let's Encrypt.<sup>[[13]](#references)</sup>

![Resultados de busca de certificados no Censys usados para identificar domínios semelhantes](<../../images/image (1115).png>)

Você também pode usar o serviço gratuito [**crt.sh**](https://crt.sh) para pesquisar uma keyword e filtrar os resultados por data e CA.<sup>[[13]](#references)</sup>

![Busca de keywords no crt.sh por identidades de certificados suspeitas](<../../images/image (519).png>)

O campo Matching Identities pode ajudar a comparar identidades do domínio real com domínios suspeitos, mas trate as correspondências como indícios, não como prova.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) transmite atualizações de CT quase em tempo real, e [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consome esse fluxo para pontuar nomes de certificados suspeitos.<sup>[[14]](#references)[[15]](#references)</sup>

Dica prática: ao fazer a triagem de ocorrências de CT, priorize NRDs, registradores não confiáveis/desconhecidos, WHOIS com privacy proxy e certificados com horários `NotBefore` muito recentes. Mantenha uma allowlist dos seus domínios/marcas para reduzir o ruído.

#### **Novos domínios**

Uma segunda opção é coletar domínios registrados recentemente por TLD (por exemplo, via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) e filtrar por keywords de marcas. Isso não identifica phishing hospedado em subdomínios quando a keyword não está presente no domínio registrado.<sup>[[13]](#references)</sup>

Heurística adicional: trate determinados **TLDs de extensões de arquivo** (por exemplo, `.zip`, `.mov`) com suspeita adicional nos alertas. Eles são frequentemente confundidos com nomes de arquivos em iscas; combine o sinal do TLD com keywords de marcas e a idade do NRD para obter maior precisão.

## References

- [1] [Remy Hax – Bitsquatting do Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Sequestro do tráfego para o windows.com da Microsoft com bit flipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Análise aprofundada: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentação do mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Conjunto de dados de propriedades web da plataforma](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referência da Search API](https://urlscan.io/docs/search/)
- [9] [Ajuda do Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Respostas JSON para o Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Táticas de tokens: como prevenir, detectar e responder ao roubo de tokens cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Fingerprinting de rede JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Encontrando phishing: ferramentas e técnicas](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Apresentando o CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
