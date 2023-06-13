# macOS MDM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Conceitos básicos

### O que é MDM (Mobile Device Management)?

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) é uma tecnologia comumente usada para **administrar dispositivos de computação de usuários finais** como telefones celulares, laptops, desktops e tablets. No caso das plataformas Apple como iOS, macOS e tvOS, refere-se a um conjunto específico de recursos, APIs e técnicas usadas pelos administradores para gerenciar esses dispositivos. O gerenciamento de dispositivos via MDM requer um servidor MDM comercial ou de código aberto compatível que implemente suporte para o [Protocolo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf).

* Uma maneira de alcançar o **gerenciamento centralizado de dispositivos**
* Requer um **servidor MDM** que implemente suporte para o protocolo MDM
* O servidor MDM pode **enviar comandos MDM**, como limpeza remota ou "instale esta configuração"

### Conceitos básicos do que é DEP (Device Enrolment Program)?

O [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) é um serviço oferecido pela Apple que **simplifica** o **registro** do Mobile Device Management (MDM) oferecendo **configuração sem toque** de dispositivos iOS, macOS e tvOS. Ao contr
### **Passo 7: Escutando comandos MDM**

* Após a verificação do MDM ser concluída, o fornecedor pode **emitir notificações push usando APNs**
* Ao receber, é tratado pelo **`mdmclient`**
* Para buscar comandos MDM, é enviada uma solicitação para ServerURL
* Faz uso do payload MDM previamente instalado:
  * **`ServerURLPinningCertificateUUIDs`** para fixar a solicitação
  * **`IdentityCertificateUUID`** para certificado de cliente TLS

## Ataques

### Matrícula de dispositivos em outras organizações

Como comentado anteriormente, para tentar matricular um dispositivo em uma organização, **apenas um número de série pertencente a essa organização é necessário**. Uma vez matriculado, várias organizações instalarão dados sensíveis no novo dispositivo: certificados, aplicativos, senhas WiFi, configurações VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Portanto, este pode ser um ponto de entrada perigoso para atacantes se o processo de matrícula não estiver corretamente protegido:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

## **Referências**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
