# Persistência de Conta AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Roubo de Credenciais de Usuário Ativo via Certificados - PERSIST1

Se o usuário tiver permissão para solicitar um certificado que permita autenticação de domínio, um invasor pode **solicitá-lo** e **roubá-lo** para **manter** a **persistência**.

O modelo **`Usuário`** permite isso e vem por **padrão**. No entanto, ele pode estar desativado. Portanto, o [**Certify**](https://github.com/GhostPack/Certify) permite que você encontre certificados válidos para persistir:
```
Certify.exe find /clientauth
```
Observe que um **certificado pode ser usado para autenticação** como aquele usuário enquanto o certificado estiver **válido**, **mesmo** se o usuário **alterar** sua **senha**.

A partir da interface gráfica é possível solicitar um certificado com `certmgr.msc` ou via linha de comando com `certreq.exe`.

Usando o [**Certify**](https://github.com/GhostPack/Certify), você pode executar:
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
O resultado será um bloco de texto formatado em `.pem` contendo o **certificado** + **chave privada**.
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Para **usar esse certificado**, pode-se então **fazer o upload** do arquivo `.pfx` para um alvo e **usá-lo com** [**Rubeus**](https://github.com/GhostPack/Rubeus) para **solicitar um TGT** para o usuário inscrito, enquanto o certificado for válido (o tempo de vida padrão é de 1 ano):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Combinado com a técnica descrita na seção [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), um invasor também pode obter persistentemente o **hash NTLM da conta**, que o invasor poderia usar para autenticar via **pass-the-hash** ou **quebrar** para obter a **senha em texto plano**. \
Este é um método alternativo de **roubo de credenciais de longo prazo** que não toca no LSASS e é possível a partir de um contexto **não elevado**.
{% endhint %}

## Persistência de Máquina via Certificados - PERSIST2

Se um modelo de certificado permitir **Computadores de Domínio** como princípios de inscrição, um invasor pode **inscrever a conta de máquina de um sistema comprometido**. O modelo padrão **`Machine`** corresponde a todas essas características.

Se um **invasor elevar privilégios** em um sistema comprometido, o invasor pode usar a conta **SYSTEM** para se inscrever em modelos de certificado que concedem privilégios de inscrição a contas de máquina (mais informações em [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Você pode usar o [**Certify**](https://github.com/GhostPack/Certify) para obter um certificado para a conta de máquina, elevando automaticamente para SYSTEM com:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Observe que, com acesso a um certificado de conta de máquina, o invasor pode então **autenticar-se no Kerberos** como a conta da máquina. Usando **S4U2Self**, um invasor pode então obter um **ticket de serviço Kerberos para qualquer serviço no host** (por exemplo, CIFS, HTTP, RPCSS, etc.) como qualquer usuário.

Isso, em última análise, dá a um ataque um método de persistência de máquina.

## Persistência de Conta via Renovação de Certificado - PERSIST3

Os modelos de certificado têm um **Período de Validade** que determina por quanto tempo um certificado emitido pode ser usado, bem como um **período de renovação** (geralmente 6 semanas). Este é um período de **tempo antes** do certificado **expirar** em que uma **conta pode renová-lo** a partir da autoridade de certificação emissora.

Se um invasor comprometer um certificado capaz de autenticação de domínio por meio de roubo ou inscrição maliciosa, o invasor pode **autenticar-se no AD durante o período de validade do certificado**. O invasor, no entanto, pode **renovar o certificado antes da expiração**. Isso pode funcionar como uma abordagem de **persistência estendida** que **impede a solicitação de inscrições de ticket adicionais**, o que **pode deixar artefatos** no próprio servidor CA. 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
