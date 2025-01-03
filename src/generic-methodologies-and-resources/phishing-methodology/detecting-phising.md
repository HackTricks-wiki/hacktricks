# Detectando Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introdução

Para detectar uma tentativa de phishing, é importante **entender as técnicas de phishing que estão sendo usadas atualmente**. Na página principal deste post, você pode encontrar essas informações, então, se você não está ciente de quais técnicas estão sendo usadas hoje, recomendo que você vá para a página principal e leia pelo menos essa seção.

Este post é baseado na ideia de que os **atacantes tentarão de alguma forma imitar ou usar o nome de domínio da vítima**. Se seu domínio se chama `example.com` e você é alvo de phishing usando um nome de domínio completamente diferente, como `youwonthelottery.com`, essas técnicas não vão descobri-lo.

## Variações de nomes de domínio

É meio **fácil** **descobrir** aquelas tentativas de **phishing** que usarão um **nome de domínio similar** dentro do e-mail.\
Basta **gerar uma lista dos nomes de phishing mais prováveis** que um atacante pode usar e **verificar** se está **registrado** ou apenas verificar se há algum **IP** usando-o.

### Encontrando domínios suspeitos

Para isso, você pode usar qualquer uma das seguintes ferramentas. Observe que essas ferramentas também realizarão solicitações DNS automaticamente para verificar se o domínio tem algum IP atribuído a ele:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Você pode encontrar uma breve explicação dessa técnica na página principal. Ou ler a pesquisa original em** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Por exemplo, uma modificação de 1 bit no domínio microsoft.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar o maior número possível de domínios de bit-flipping relacionados à vítima para redirecionar usuários legítimos para sua infraestrutura**.

**Todos os possíveis nomes de domínio de bit-flipping também devem ser monitorados.**

### Verificações básicas

Uma vez que você tenha uma lista de nomes de domínio potencialmente suspeitos, você deve **verificá-los** (principalmente as portas HTTP e HTTPS) para **ver se estão usando algum formulário de login similar** ao de algum domínio da vítima.\
Você também pode verificar a porta 3333 para ver se está aberta e executando uma instância de `gophish`.\
É interessante saber **quão antigos são cada um dos domínios suspeitos descobertos**, quanto mais jovem, mais arriscado é.\
Você também pode obter **capturas de tela** da página da web suspeita em HTTP e/ou HTTPS para ver se é suspeita e, nesse caso, **acessá-la para dar uma olhada mais profunda**.

### Verificações avançadas

Se você quiser ir um passo além, eu recomendaria que você **monitore esses domínios suspeitos e busque mais** de vez em quando (todo dia? só leva alguns segundos/minutos). Você também deve **verificar** as **portas** abertas dos IPs relacionados e **procurar instâncias de `gophish` ou ferramentas similares** (sim, os atacantes também cometem erros) e **monitorar as páginas da web HTTP e HTTPS dos domínios e subdomínios suspeitos** para ver se copiaram algum formulário de login das páginas da web da vítima.\
Para **automatizar isso**, eu recomendaria ter uma lista de formulários de login dos domínios da vítima, rastrear as páginas da web suspeitas e comparar cada formulário de login encontrado dentro dos domínios suspeitos com cada formulário de login do domínio da vítima usando algo como `ssdeep`.\
Se você localizou os formulários de login dos domínios suspeitos, pode tentar **enviar credenciais falsas** e **verificar se está redirecionando você para o domínio da vítima**.

## Nomes de domínio usando palavras-chave

A página principal também menciona uma técnica de variação de nome de domínio que consiste em colocar o **nome de domínio da vítima dentro de um domínio maior** (por exemplo, paypal-financial.com para paypal.com).

### Transparência de Certificado

Não é possível adotar a abordagem anterior de "Força Bruta", mas é **possível descobrir tais tentativas de phishing** também graças à transparência de certificado. Sempre que um certificado é emitido por uma CA, os detalhes são tornados públicos. Isso significa que, ao ler a transparência de certificado ou até mesmo monitorá-la, é **possível encontrar domínios que estão usando uma palavra-chave dentro de seu nome**. Por exemplo, se um atacante gera um certificado de [https://paypal-financial.com](https://paypal-financial.com), ao ver o certificado, é possível encontrar a palavra-chave "paypal" e saber que um e-mail suspeito está sendo usado.

O post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugere que você pode usar o Censys para procurar certificados que afetam uma palavra-chave específica e filtrar por data (apenas "novos" certificados) e pelo emissor CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

No entanto, você pode fazer "o mesmo" usando o site gratuito [**crt.sh**](https://crt.sh). Você pode **procurar pela palavra-chave** e **filtrar** os resultados **por data e CA**, se desejar.

![](<../../images/image (519).png>)

Usando essa última opção, você pode até usar o campo Identidades Correspondentes para ver se alguma identidade do domínio real corresponde a algum dos domínios suspeitos (note que um domínio suspeito pode ser um falso positivo).

**Outra alternativa** é o fantástico projeto chamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). O CertStream fornece um fluxo em tempo real de certificados recém-gerados que você pode usar para detectar palavras-chave especificadas em (quase) tempo real. De fato, há um projeto chamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que faz exatamente isso.

### **Novos domínios**

**Uma última alternativa** é reunir uma lista de **domínios recém-registrados** para alguns TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fornece tal serviço) e **verificar as palavras-chave nesses domínios**. No entanto, domínios longos geralmente usam um ou mais subdomínios, portanto, a palavra-chave não aparecerá dentro do FLD e você não conseguirá encontrar o subdomínio de phishing.

{{#include ../../banners/hacktricks-training.md}}
