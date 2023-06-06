# Certificados

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## O que é um Certificado

Em criptografia, um **certificado de chave pública**, também conhecido como **certificado digital** ou **certificado de identidade**, é um documento eletrônico usado para provar a propriedade de uma chave pública. O certificado inclui informações sobre a chave, informações sobre a identidade do proprietário (chamado de sujeito) e a assinatura digital de uma entidade que verificou o conteúdo do certificado (chamado de emissor). Se a assinatura for válida e o software que examina o certificado confiar no emissor, ele poderá usar essa chave para se comunicar com segurança com o sujeito do certificado.

Em um esquema típico de [infraestrutura de chave pública](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI), o emissor do certificado é uma [autoridade de certificação](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), geralmente uma empresa que cobra dos clientes para emitir certificados para eles. Por outro lado, em um esquema de [rede de confiança](https://en.wikipedia.org/wiki/Web\_of\_trust), os indivíduos assinam as chaves uns dos outros diretamente, em um formato que desempenha uma função semelhante à de um certificado de chave pública.

O formato mais comum para certificados de chave pública é definido por [X.509](https://en.wikipedia.org/wiki/X.509). Como o X.509 é muito geral, o formato é ainda mais restrito por perfis definidos para determinados casos de uso, como [Infraestrutura de Chave Pública (X.509)](https://en.wikipedia.org/wiki/PKIX) conforme definido no RFC 5280.

## Campos Comuns do x509

* **Número da Versão:** Versão do formato x509.
* **Número de Série**: Usado para identificar exclusivamente o certificado nos sistemas de uma CA. Em particular, isso é usado para rastrear informações de revogação.
* **Sujeito**: A entidade a que um certificado pertence: uma máquina, um indivíduo ou uma organização.
  * **Nome Comum**: Domínios afetados pelo certificado. Pode ser 1 ou mais e pode conter caracteres curinga.
  * **País (C)**: País
  * **Nome Distinto (DN)**: O sujeito completo: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
  * **Localidade (L)**: Localização local
  * **Organização (O)**: Nome da organização
  * **Unidade Organizacional (OU)**: Divisão de uma organização (como "Recursos Humanos").
  * **Estado ou Província (ST, S ou P)**: Lista de nomes de estados ou províncias
* **Emissor**: A entidade que verificou as informações e assinou o certificado.
  * **Nome Comum (CN)**: Nome da autoridade de certificação
  * **País (C)**: País da autoridade de certificação
  * **Nome Distinto (DN)**: Nome distinto da autoridade de certificação
  * **Localidade (L)**: Localização local onde a organização pode ser encontrada.
  * **Organização (O)**: Nome da organização
  * **Unidade Organizacional (OU)**: Divisão de uma organização
#### **Formato DER**

* O formato DER é a forma binária do certificado
* Todos os tipos de certificados e chaves privadas podem ser codificados no formato DER
* Certificados formatados em DER não contêm as declarações "BEGIN CERTIFICATE/END CERTIFICATE"
* Certificados formatados em DER geralmente usam as extensões ".cer" e ".der"
* DER é tipicamente usado em plataformas Java

#### **Formato P7B/PKCS#7**

* O formato PKCS#7 ou P7B é armazenado no formato Base64 ASCII e tem uma extensão de arquivo .p7b ou .p7c
* Um arquivo P7B contém apenas certificados e certificados de cadeia (CA intermediários), não a chave privada
* As plataformas mais comuns que suportam arquivos P7B são o Microsoft Windows e o Java Tomcat

#### **Formato PFX/P12/PKCS#12**

* O formato PKCS#12 ou PFX/P12 é um formato binário para armazenar o certificado do servidor, certificados intermediários e a chave privada em um único arquivo criptografável
* Esses arquivos geralmente têm extensões como .pfx e .p12
* Eles são tipicamente usados em máquinas Windows para importar e exportar certificados e chaves privadas

### Conversões de formatos

**Converter x509 para PEM**
```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
#### **Converter PEM para DER**

Para converter um certificado PEM para o formato DER, basta usar o seguinte comando:

```
openssl x509 -outform der -in certificate.pem -out certificate.der
```

Isso irá gerar um arquivo `certificate.der` no formato DER a partir do arquivo `certificate.pem` no formato PEM.
```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
**Converter DER para PEM**

Para converter um certificado DER para PEM, você pode usar o seguinte comando:

```
openssl x509 -inform der -in certificate.der -out certificate.pem
```

Substitua `certificate.der` pelo nome do seu certificado DER e `certificate.pem` pelo nome que você deseja dar ao seu certificado PEM convertido.
```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
**Converter PEM para P7B**

**Nota:** O formato PKCS#7 ou P7B é armazenado em formato ASCII Base64 e tem uma extensão de arquivo .p7b ou .p7c. Um arquivo P7B contém apenas certificados e cadeias de certificados (ACs intermediárias), não a chave privada. As plataformas mais comuns que suportam arquivos P7B são o Microsoft Windows e o Java Tomcat.
```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
**Converter PKCS7 para PEM**

Para converter um certificado PKCS7 para o formato PEM, você pode usar o seguinte comando:

```
openssl pkcs7 -print_certs -in certificate.p7b -out certificate.pem
```

Isso irá extrair todos os certificados do arquivo PKCS7 e salvá-los em um arquivo PEM.
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Converter pfx para PEM**

**Nota:** O formato PKCS#12 ou PFX é um formato binário para armazenar o certificado do servidor, certificados intermediários e a chave privada em um único arquivo criptografável. Arquivos PFX geralmente têm extensões como .pfx e .p12. Arquivos PFX são tipicamente usados em máquinas Windows para importar e exportar certificados e chaves privadas.
```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
**Converter PFX para PKCS#8**\
**Nota:** Isso requer 2 comandos

**1- Converter PFX para PEM**
```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
**2- Converter PEM para PKCS8**

Para converter um arquivo PEM para PKCS8, você pode usar o OpenSSL com o seguinte comando:

```
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private.pk8
```

Isso converterá o arquivo `private.pem` para o formato PKCS8 e o salvará como `private.pk8`.
```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
**Converter P7B para PFX**\
**Nota:** Isso requer 2 comandos

1- **Converter P7B para CER**
```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
**2- Converter CER e Chave Privada para PFX**

Para converter um certificado CER e sua chave privada em um arquivo PFX, você pode usar o OpenSSL. Primeiro, certifique-se de ter o OpenSSL instalado em seu sistema. Em seguida, execute o seguinte comando:

```
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.cer
```

Substitua `privateKey.key` pelo caminho para sua chave privada e `certificate.cer` pelo caminho para o certificado CER. O comando acima criará um arquivo `certificate.pfx` que contém o certificado e a chave privada.
```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.io/) para construir e automatizar facilmente fluxos de trabalho alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
