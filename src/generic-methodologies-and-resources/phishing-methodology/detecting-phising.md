# Detectando Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introdução

Para detectar uma tentativa de phishing é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página pai deste post, você pode encontrar essa informação, então se você não está ciente de quais técnicas são usadas hoje eu recomendo que vá à página pai e leia pelo menos essa seção.

Este post é baseado na ideia de que os **atacantes tentarão de alguma forma imitar ou usar o nome de domínio da vítima**. Se o seu domínio se chama `example.com` e você é phishado usando um nome de domínio completamente diferente por alguma razão como `youwonthelottery.com`, essas técnicas não irão revelar.

## Variações de nomes de domínio

É meio **fácil** **descobrir** aquelas tentativas de **phishing** que vão usar um **domínio similar** dentro do email.\
Basta **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se ele está **registrado** ou apenas checar se há algum **IP** usando-o.

### Encontrando domínios suspeitos

Para esse propósito, você pode usar qualquer uma das seguintes ferramentas. Note que essas ferramentas também irão realizar requisições DNS automaticamente para checar se o domínio tem algum IP atribuído:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Dica: Se você gerar uma lista de candidatos, também alimente-a nos seus logs de resolver DNS para detectar buscas NXDOMAIN de dentro da sua org (usuários tentando alcançar um erro de digitação antes do atacante realmente registrá-lo). Faça sinkhole ou bloqueie preventivamente esses domínios se a política permitir.

### Bitflipping

**Você pode encontrar uma breve explicação desta técnica na página pai. Ou leia a pesquisa original em** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Atacantes podem registrar quantos domínios bit-flipping relacionados à vítima quanto possível para redirecionar usuários legítimos para sua infraestrutura**.

**Todos os possíveis nomes de domínio bit-flipping também devem ser monitorados.**

Se você também precisa considerar lookalikes homoglyph/IDN (por exemplo, misturar caracteres Latin/Cyrillic), verifique:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Verificações básicas

Uma vez que você tenha uma lista de nomes de domínio potencialmente suspeitos você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se estão usando algum formulário de login similar** ao de algum domínio da vítima.\
Você também poderia checar a porta 3333 para ver se está aberta e rodando uma instância de `gophish`.\
Também é interessante saber **quão antigo cada domínio suspeito descoberto é**, quanto mais jovem, mais arriscado.\
Você também pode obter **capturas de tela** da página web HTTP e/ou HTTPS suspeita para ver se é suspeita e, nesse caso, **acessá-la para olhar mais a fundo**.

### Verificações avançadas

Se você quiser ir um passo além eu recomendaria **monitorar esses domínios suspeitos e procurar por mais** de vez em quando (todo dia? leva apenas alguns segundos/minutos). Você também deveria **verificar** as **portas abertas** dos IPs relacionados e **procurar por instâncias de `gophish` ou ferramentas similares** (sim, atacantes também cometem erros) e **monitorar as páginas HTTP e HTTPS dos domínios e subdomínios suspeitos** para ver se copiaram algum formulário de login das páginas da vítima.\
Para **automatizar isso** eu recomendaria ter uma lista de formulários de login dos domínios da vítima, spiderar as páginas suspeitas e comparar cada formulário de login encontrado dentro dos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, você pode tentar **enviar credenciais inválidas** e **checar se está redirecionando você para o domínio da vítima**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Many phishing kits reuse favicons from the brand they impersonate. Internet-wide scanners compute a MurmurHash3 of the base64-encoded favicon. You can generate the hash and pivot on it:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Consultar o Shodan: `http.favicon.hash:309020573`
- Com ferramentas: use ferramentas da comunidade como favfreak para gerar hashes e dorks para Shodan/ZoomEye/Censys.

Notas
- Favicons são reutilizados; trate correspondências como pistas e valide o conteúdo e os certificados antes de agir.
- Combine com heurísticas de idade do domínio e palavras-chave para maior precisão.

### Investigação de telemetria de URL (urlscan.io)

`urlscan.io` armazena capturas de tela históricas, DOM, requisições e metadados TLS das URLs submetidas. Você pode investigar abuso de marca e clones:

Example queries (UI or API):
- Encontre similares excluindo seus domínios legítimos: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Encontre sites que fazem hotlink aos seus ativos: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrinja a resultados recentes: acrescente `AND date:>now-7d`

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
A partir do JSON, foque em:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` para identificar certificados muito novos usados em lookalikes
- `task.source` com valores como `certstream-suspicious` para vincular as descobertas ao monitoramento CT

### Idade do domínio via RDAP (scriptável)

O RDAP retorna eventos de criação legíveis por máquina. Útil para sinalizar **domínios recém-registrados (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enriqueça seu pipeline marcando domínios com faixas de idade de registro (por exemplo, <7 dias, <30 dias) e priorize a triagem de acordo.

### TLS/JAx fingerprints to spot AiTM infrastructure

O phishing de credenciais moderno usa cada vez mais **Adversary-in-the-Middle (AiTM)** reverse proxies (por exemplo, Evilginx) para roubar session tokens. Você pode adicionar detecções no lado da rede:

- Registre TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) na saída de rede. Algumas builds do Evilginx foram observadas com valores JA4 cliente/servidor estáveis. Gere alertas apenas para fingerprints conhecidos como maliciosos como um sinal fraco e sempre confirme com análise de conteúdo e inteligência de domínio.
- Registre proativamente metadados de certificados TLS (issuer, contagem de SAN, uso de wildcard, validade) para hosts lookalike descobertos via CT ou urlscan e correlate com idade do DNS e geolocalização.

> Nota: Trate fingerprints como enriquecimento, não como bloqueadores exclusivos; frameworks evoluem e podem randomizar ou ofuscar.

### Domain names using keywords

A página principal também menciona uma técnica de variação de nome de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

#### Certificate Transparency

Não é possível adotar a abordagem anterior "Brute-Force", mas na verdade é **possível descobrir essas tentativas de phishing** também graças ao Certificate Transparency. Toda vez que um certificado é emitido por uma CA, os detalhes são tornados públicos. Isso significa que, ao ler o Certificate Transparency ou mesmo monitorá-lo, é **possível encontrar domínios que estão usando uma palavra-chave dentro do seu nome**. Por exemplo, se um atacante gera um certificado de [https://paypal-financial.com](https://paypal-financial.com), ao ver o certificado é possível encontrar a palavra-chave "paypal" e saber que um e-mail suspeito está sendo usado.

O post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugere que você pode usar Censys para buscar certificados contendo uma palavra-chave específica e filtrar por data (apenas certificados "novos") e pelo emissor CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

No entanto, você pode fazer "o mesmo" usando a web gratuita [**crt.sh**](https://crt.sh). Você pode **buscar pela palavra-chave** e **filtrar** os resultados **por data e CA** se quiser.

![](<../../images/image (519).png>)

Usando essa última opção você pode até usar o campo Matching Identities para ver se alguma identidade do domínio real bate com algum dos domínios suspeitos (note que um domínio suspeito pode ser um falso positivo).

**Outra alternativa** é o fantástico projeto chamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fornece um stream em tempo real de certificados recém-gerados que você pode usar para detectar palavras-chave especificadas em (quase) tempo real. Na verdade, existe um projeto chamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que faz exatamente isso.

Dica prática: ao triar hits de CT, priorize NRDs, registrars não confiáveis/desconhecidos, WHOIS com proxy de privacidade e certs com `NotBefore` muito recentes. Mantenha uma allowlist dos seus domínios/marcas para reduzir ruído.

#### **Novos domínios**

**Uma última alternativa** é coletar uma lista de **domínios recém-registrados** para alguns TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornece esse serviço) e **verificar palavras-chave nesses domínios**. No entanto, domínios longos geralmente usam um ou mais subdomínios, portanto a palavra-chave não aparecerá dentro do FLD e você não conseguirá encontrar o subdomínio de phishing.

Heurística adicional: trate certos **file-extension TLDs** (por exemplo, `.zip`, `.mov`) com suspeita adicional nos alertas. Estes costumam ser confundidos com nomes de arquivo em iscas; combine o sinal do TLD com palavras-chave da marca e idade NRD para melhor precisão.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
