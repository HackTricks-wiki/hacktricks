# Inscrição de Dispositivos em Outras Organizações

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

O Apple Automated Device Enrollment (anteriormente DEP) começa identificando um dispositivo atribuído a uma organização. A pesquisa de 2018 resumida aqui mostrou que ter conhecimento de um número de série atribuído era suficiente para recuperar os enrollment profiles de algumas organizações, pois essas organizações não exigiam autenticação adicional adequada. Essa é uma descoberta histórica, não uma afirmação de que todo MDM atual possa ser associado usando apenas um número de série. Os profiles podem conter certificados, aplicativos, segredos de Wi-Fi, configurações de VPN e outras configurações sensíveis.<sup>[[1]](#references)[[2]](#references)</sup>

**O texto a seguir é um resumo da pesquisa [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consulte-a para obter mais detalhes técnicos!**<sup>[[1]](#references)</sup>

## Visão geral da análise binária do DEP e do MDM

A pesquisa analisou binários associados ao DEP e ao MDM nas versões do macOS atuais naquela época. Os nomes e as responsabilidades dos componentes podem mudar entre as versões:

- **`mdmclient`**: Comunica-se com servidores MDM e aciona check-ins do DEP nas versões do macOS anteriores à 10.13.4.
- **`profiles`**: Gerencia Configuration Profiles e aciona check-ins do DEP nas versões 10.13.4 e posteriores do macOS.
- **`cloudconfigurationd`**: Gerencia as comunicações com a API do DEP e recupera Device Enrollment profiles.

Os check-ins do DEP utilizam as funções `CPFetchActivationRecord` e `CPGetActivationRecord` do framework privado Configuration Profiles para buscar o Activation Record, com `CPFetchActivationRecord` coordenando-se com `cloudconfigurationd` por meio de XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering do protocolo Tesla e do esquema Absinthe

O check-in do DEP envolve o envio, pelo `cloudconfigurationd`, de um payload JSON criptografado e assinado para _iprofiles.apple.com/macProfile_. O payload inclui o número de série do dispositivo e a ação "RequestProfileConfiguration". O esquema de criptografia usado é chamado internamente de "Absinthe". Desvendar esse esquema é complexo e envolve diversas etapas, o que levou à exploração de métodos alternativos para inserir números de série arbitrários na solicitação do Activation Record.<sup>[[1]](#references)</sup>

## Proxying de solicitações do DEP

As tentativas de interceptar e modificar solicitações do DEP para _iprofiles.apple.com_ usando ferramentas como Charles Proxy foram dificultadas pela criptografia do payload e pelas medidas de segurança SSL/TLS. No entanto, habilitar a configuração `MCCloudConfigAcceptAnyHTTPSCertificate` permite ignorar a validação do certificado do servidor, embora a natureza criptografada do payload ainda impeça a modificação do número de série sem a chave de descriptografia.<sup>[[1]](#references)</sup>

## Instrumentação de binários do sistema que interagem com o DEP

Instrumentar binários do sistema, como `cloudconfigurationd`, exige desabilitar o System Integrity Protection (SIP) no macOS. Com o SIP desabilitado, ferramentas como o LLDB podem ser usadas para anexar-se a processos do sistema e potencialmente modificar o número de série usado nas interações com a API do DEP. Esse método é preferível, pois evita as complexidades relacionadas a entitlements e code signing.<sup>[[1]](#references)</sup>

**Explorando a instrumentação de binários:**
Modificar o payload da solicitação do DEP antes da serialização JSON em `cloudconfigurationd` mostrou-se eficaz. O processo envolveu:

1. Anexar o LLDB ao `cloudconfigurationd`.
2. Localizar o ponto em que o número de série do sistema é obtido.
3. Injetar um número de série arbitrário na memória antes que o payload fosse criptografado e enviado.

Esse método permitiu aos pesquisadores recuperar DEP profiles para números de série fornecidos e atribuídos. Ele não tornou válido um número de série arbitrário não atribuído.<sup>[[1]](#references)</sup>

### Automatizando a instrumentação com Python

O processo de exploração foi automatizado usando Python com a API do LLDB, tornando viável injetar programaticamente números de série arbitrários e recuperar os DEP profiles correspondentes.<sup>[[1]](#references)</sup>

### Possíveis impactos das vulnerabilidades do DEP e do MDM

A pesquisa destacou preocupações significativas de segurança:

1. **Divulgação de informações**: Ao fornecer um número de série registrado no DEP, é possível recuperar informações organizacionais sensíveis contidas no DEP profile.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
