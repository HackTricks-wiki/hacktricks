# Detectando phishing

{{#include ../../banners/hacktricks-training.md}}

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página principal desta publicação, você encontra essas informações. Portanto, se não conhece as técnicas usadas hoje, recomendo acessar a página principal e ler pelo menos essa seção.

Esta publicação parte da ideia de que os **atacantes tentarão, de alguma forma, imitar ou usar o nome de domínio da vítima**. Se o seu domínio se chama `example.com` e você for alvo de phishing usando, por algum motivo, um nome de domínio completamente diferente, como `youwonthelottery.com`, estas técnicas não vão detectá-lo.

## Variações de nomes de domínio

É relativamente **fácil** **descobrir** tentativas de **phishing** que usam um nome de **domínio semelhante** no e-mail.\
Basta **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se estão **registrados** ou simplesmente verificar se algum **IP** os está usando.

### Encontrar domínios suspeitos

Para isso, você pode usar qualquer uma das seguintes ferramentas. Ambas resolvem os domínios candidatos para verificar se estão em uso.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Dica: se você gerar uma lista de candidatos, também envie-a aos logs do seu resolvedor DNS para detectar **consultas NXDOMAIN originadas de dentro da sua organização** (usuários tentando acessar um domínio digitado incorretamente antes que o atacante o registre). Coloque esses domínios em um sinkhole ou bloqueie-os antecipadamente, se a política permitir.

### Bitflipping

**Para uma breve explicação, consulte a página principal; para a pesquisa primária sobre bitsquatting no Windows.com, consulte o [artigo de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) e a [reportagem do BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios com bit-flipping relacionados à vítima para redirecionar usuários legítimos para a infraestrutura deles**.<sup>[[1]](#references)[[2]](#references)</sup>

**Todos os nomes de domínio possíveis gerados por bit-flipping também devem ser monitorados.**

Se você também precisar considerar sósias com homoglifos/IDN (por exemplo, misturando caracteres latinos e cirílicos), consulte:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Verificações básicas

Depois de ter uma lista de possíveis nomes de domínio suspeitos, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se estão usando algum formulário de login semelhante ao de alguém do domínio da vítima**.\
Você também pode verificar se a porta 3333 está aberta e executando uma instância do `gophish`.\
Também é interessante saber **a idade de cada domínio suspeito encontrado**; quanto mais recente, maior o risco.\
Você também pode obter **capturas de tela** das páginas web suspeitas HTTP e/ou HTTPS para verificar se são suspeitas e, nesse caso, **acessá-las para analisá-las mais a fundo**.

### Verificações avançadas

Se quiser ir um passo além, recomendo **monitorar esses domínios suspeitos e procurar outros de tempos em tempos** (todos os dias? leva apenas alguns segundos/minutos). Você também deve **verificar** as **portas** abertas dos IPs relacionados e **procurar instâncias de `gophish` ou ferramentas semelhantes** (sim, os atacantes também cometem erros) e **monitorar as páginas web HTTP e HTTPS dos domínios e subdomínios suspeitos** para ver se copiaram algum formulário de login das páginas web da vítima.\
Para **automatizar isso**, recomendo manter uma lista dos formulários de login dos domínios da vítima, rastrear as páginas web suspeitas e comparar cada formulário de login encontrado nos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, pode tentar **enviar credenciais falsas** e **verificar se há um redirecionamento para o domínio da vítima**.

---

### Busca por favicon e impressões digitais da web (Shodan/Censys)

Muitos kits de phishing reutilizam os favicons da marca que estão imitando. O Shodan calcula um hash dos dados do favicon codificados em base64 usando MurmurHash3, enquanto o Censys expõe seus próprios campos de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Você pode gerar um hash compatível com o Shodan e usá-lo para buscar outros resultados relacionados:

Exemplo em Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Consulte o Shodan: `http.favicon.hash:309020573`
- Com ferramentas: confira ferramentas da comunidade, como favfreak, para calcular hashes e gerar dorks do Shodan.<sup>[[16]](#references)</sup>

Observações
- Favicons são reutilizados; trate as correspondências como pistas e valide o conteúdo e os certificados antes de agir.
- Combine heurísticas de idade do domínio e palavras-chave para obter mais precisão.

### Busca de telemetria de URLs (urlscan.io)

`urlscan.io` armazena capturas de tela históricas, DOM, requisições e metadados TLS de URLs enviadas. Você pode buscar casos de abuso de marca e clones:<sup>[[8]](#references)</sup>

Consultas de exemplo (interface ou API):
- Encontrar sites semelhantes, excluindo seus domínios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontrar sites que incorporam seus recursos: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restringir aos resultados recentes: acrescente `AND date:>now-7d`

Exemplo de API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

A partir do JSON, investigue:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para identificar certificados muito recentes em domínios semelhantes
- valores de `task.source`, como `certstream-suspicious`, para associar as descobertas ao monitoramento de CT

### Idade do domínio via RDAP (automatizável por script)

O RDAP retorna eventos de registro legíveis por máquina. É útil para sinalizar **domínios recém-registrados (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Enriqueça seu pipeline marcando domínios com faixas de idade de registro (por exemplo, <7 dias, <30 dias) e priorize a triagem de acordo.

### Impressões digitais TLS/JAx para identificar infraestrutura AiTM

O phishing de credenciais pode usar proxies reversos **Adversary-in-the-Middle (AiTM)** (por exemplo, Evilginx) para roubar tokens de sessão.<sup>[[11]](#references)</sup> Você pode adicionar detecções no lado da rede:

- Registre impressões digitais TLS/HTTP (JA3/JA4/JA4S/JA4H) no tráfego de saída. Algumas builds do Evilginx foram observadas com valores JA4 de cliente/servidor estáveis. Gere alertas apenas para impressões digitais conhecidas como maliciosas, considerando-as um sinal fraco, e sempre confirme com informações sobre o conteúdo e os domínios.<sup>[[12]](#references)</sup>
- Registre proativamente metadados de certificados TLS (emissor, número de SANs, uso de wildcard, validade) para hosts semelhantes descobertos via CT ou urlscan e correlacione-os com a idade do DNS e a geolocalização.

> Nota: trate as impressões digitais como enriquecimento, não como único critério de bloqueio; os frameworks evoluem e podem randomizar ou ofuscar essas informações.

### Nomes de domínio com palavras-chave

A página principal também menciona uma técnica de variação de nomes de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Os logs de Certificate Transparency (CT) expõem as identidades dos certificados. Assim, buscar palavras-chave de marcas nos nomes Subject ou SAN pode revelar domínios semelhantes (por exemplo, um certificado para `paypal-financial.com` expõe a palavra-chave `paypal`). Quando for útil, filtre os resultados pela data de emissão e pela CA e valide os candidatos, pois correspondências de palavras-chave podem gerar falsos positivos.<sup>[[13]](#references)</sup>

O [artigo original de Patrik Hudak sobre busca de domínios de phishing](https://0xpatrik.com/phishing-domains/) demonstra esse fluxo de trabalho no Censys, incluindo filtros para a data e o emissor do certificado, como Let's Encrypt.<sup>[[13]](#references)</sup>

![Resultados de busca de certificados no Censys usados para identificar domínios semelhantes](<../../images/image (1115).png>)

Você também pode usar o serviço gratuito [**crt.sh**](https://crt.sh) para pesquisar uma palavra-chave e filtrar os resultados por data e CA.<sup>[[13]](#references)</sup>

![Busca de palavras-chave no crt.sh por identidades de certificados suspeitas](<../../images/image (519).png>)

O campo Matching Identities pode ajudar a comparar identidades do domínio legítimo com as de domínios suspeitos, mas considere as correspondências como pistas, não como prova.<sup>[[13]](#references)</sup>

O [*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) transmite atualizações de CT quase em tempo real, e o [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consome esse fluxo para atribuir pontuações a nomes de certificados suspeitos.<sup>[[14]](#references)[[15]](#references)</sup>

Dica prática: ao fazer a triagem de resultados de CT, priorize NRDs, registradores não confiáveis/desconhecidos, WHOIS com proxy de privacidade e certificados com horários `NotBefore` muito recentes. Mantenha uma lista de permissões com os domínios/marcas que você possui para reduzir o ruído.

#### **Novos domínios**

Outra opção é coletar domínios recém-registrados por TLD (por exemplo, via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) e filtrar por palavras-chave de marcas. Isso não detecta phishing hospedado em subdomínios quando a palavra-chave não aparece no domínio registrado.<sup>[[13]](#references)</sup>

Heurística adicional: considere determinados **TLDs de extensão de arquivo** (por exemplo, `.zip`, `.mov`) especialmente suspeitos nos alertas. Eles são frequentemente confundidos com nomes de arquivos em iscas; combine o sinal do TLD com palavras-chave de marcas e a idade do NRD para obter maior precisão.

## References

- [1] [Remy Hax – Bitsquatting em Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Sequestro do tráfego para windows.com da Microsoft com bit flipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Análise aprofundada: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentação do mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Conjunto de dados de propriedades web da plataforma](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Referência da API de busca](https://urlscan.io/docs/search/)
- [9] [Ajuda do Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Respostas JSON para o Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Táticas de tokens: como prevenir, detectar e responder ao roubo de tokens na nuvem](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Blog da APNIC – Impressão digital de rede JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Encontrando phishing: ferramentas e técnicas](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Apresentando o CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
