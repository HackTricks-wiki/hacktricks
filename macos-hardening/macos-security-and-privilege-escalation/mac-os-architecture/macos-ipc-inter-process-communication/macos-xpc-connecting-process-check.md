# Verificação de Conexão XPC do macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Verificação de Conexão XPC

Quando uma conexão é estabelecida com um serviço XPC, o servidor verificará se a conexão é permitida. Estas são as verificações que normalmente são realizadas:

1. Verificar se o **processo de conexão é assinado com um certificado assinado pela Apple** (apenas fornecido pela Apple).
   * Se isso **não for verificado**, um atacante pode criar um **certificado falso** para corresponder a qualquer outra verificação.
2. Verificar se o processo de conexão é assinado com o **certificado da organização** (verificação do ID da equipe).
   * Se isso **não for verificado**, **qualquer certificado de desenvolvedor** da Apple pode ser usado para assinar e se conectar ao serviço.
3. Verificar se o processo de conexão **contém um ID de pacote apropriado**.
4. Verificar se o processo de conexão tem um **número de versão de software apropriado**.
   * Se isso **não for verificado**, clientes antigos e inseguros, vulneráveis à injeção de processo, podem ser usados para se conectar ao serviço XPC, mesmo com as outras verificações em vigor.
5. Verificar se o processo de conexão tem uma **autorização** que permite que ele se conecte ao serviço. Isso é aplicável para binários da Apple.
6. A **verificação** deve ser **baseada** no **token de auditoria do cliente conectado** em vez de seu **PID** (ID do processo), pois o primeiro impede ataques de reutilização de PID.
   * Os desenvolvedores raramente usam a chamada de API de token de auditoria, pois ela é **privada**, então a Apple pode **alterá-la** a qualquer momento. Além disso, o uso de API privada não é permitido em aplicativos da Mac App Store.

Para obter mais informações sobre a verificação de ataque de reutilização de PID:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

### Trustcache - Prevenção de Ataques de Downgrade

Trustcache é um método defensivo introduzido em máquinas Apple Silicon que armazena um banco de dados de CDHSAH de binários da Apple, para que apenas binários não modificados permitidos possam ser executados. Isso impede a execução de versões de downgrade.

### Exemplos de Código

O servidor implementará esta **verificação** em uma função chamada **`shouldAcceptNewConnection`**.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    //Check connection
    return YES;
}
```
{% endcode %}

O objeto NSXPCConnection tem uma propriedade **privada** chamada **`auditToken`** (a que deve ser usada, mas pode mudar) e uma propriedade **pública** chamada **`processIdentifier`** (a que não deve ser usada).

O processo de conexão pode ser verificado com algo como: 

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);
```
Se um desenvolvedor não quiser verificar a versão do cliente, ele poderia verificar que o cliente não é vulnerável à injeção de processo pelo menos: 

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page. 
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
    return Yes; // Accept connection
}
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
