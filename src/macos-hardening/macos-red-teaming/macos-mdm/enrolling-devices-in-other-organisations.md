# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

O Apple Automated Device Enrollment (anteriormente DEP) começa identificando um dispositivo atribuído a uma organização. A pesquisa de 2018 resumida aqui mostrou que conhecer um número de série atribuído era suficiente para recuperar os enrollment profiles de algumas organizações, porque essas organizações não exigiam autenticação adicional adequada. Esta é uma descoberta histórica, não uma afirmação de que todo MDM atual possa ser integrado usando apenas um número de série. Os profiles podem conter certificados, aplicativos, segredos de Wi-Fi, configurações de VPN e outras configurações sensíveis.<sup>[[1]](#references)[[2]](#references)</sup>

**A seguir está um resumo da pesquisa [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consulte-a para obter mais detalhes técnicos!**<sup>[[1]](#references)</sup>

## Visão geral da análise binária de DEP e MDM

A pesquisa analisou binários associados ao DEP e ao MDM nas versões do macOS atuais na época. Os nomes e as responsabilidades dos componentes podem mudar entre as releases:

- **`mdmclient`**: Comunica-se com servidores MDM e aciona check-ins do DEP nas versões do macOS anteriores à 10.13.4.
- **`profiles`**: Gerencia Configuration Profiles e aciona check-ins do DEP nas versões 10.13.4 e posteriores do macOS.
- **`cloudconfigurationd`**: Gerencia as comunicações da API do DEP e recupera os Device Enrollment profiles.

Os check-ins do DEP utilizam as funções `CPFetchActivationRecord` e `CPGetActivationRecord` do framework privado Configuration Profiles para obter o Activation Record, com `CPFetchActivationRecord` coordenando-se com o `cloudconfigurationd` por meio de XPC.<sup>[[1]](#references)</sup>

## Engenharia reversa do protocolo Tesla e do esquema Absinthe

O check-in do DEP envolve o `cloudconfigurationd` enviando um payload JSON criptografado e assinado para _iprofiles.apple.com/macProfile_. O payload inclui o número de série do dispositivo e a ação "RequestProfileConfiguration". O esquema de criptografia utilizado é chamado internamente de "Absinthe". Desvendar esse esquema é complexo e envolve inúmeras etapas, o que levou à exploração de métodos alternativos para inserir números de série arbitrários na solicitação do Activation Record.<sup>[[1]](#references)</sup>

## Proxying de solicitações do DEP

As tentativas de interceptar e modificar solicitações do DEP para _iprofiles.apple.com_ usando ferramentas como Charles Proxy foram dificultadas pela criptografia do payload e pelas medidas de segurança SSL/TLS. No entanto, habilitar a configuração `MCCloudConfigAcceptAnyHTTPSCertificate` permite contornar a validação do certificado do servidor, embora a natureza criptografada do payload ainda impeça a modificação do número de série sem a chave de descriptografia.<sup>[[1]](#references)</sup>

## Instrumentação de binários do sistema que interagem com o DEP

Instrumentar binários do sistema como o `cloudconfigurationd` exige a desativação do System Integrity Protection (SIP) no macOS. Com o SIP desativado, ferramentas como o LLDB podem ser usadas para anexar-se a processos do sistema e potencialmente modificar o número de série utilizado nas interações com a API do DEP. Esse método é preferível porque evita as complexidades de entitlements e code signing.<sup>[[1]](#references)</sup>

**Explorando a instrumentação binária:**
Modificar o payload da solicitação do DEP antes da serialização JSON no `cloudconfigurationd` mostrou-se eficaz. O processo envolveu:

1. Anexar o LLDB ao `cloudconfigurationd`.
2. Localizar o ponto em que o número de série do sistema é obtido.
3. Injetar um número de série arbitrário na memória antes que o payload seja criptografado e enviado.

Esse método permitiu aos pesquisadores recuperar DEP profiles para números de série fornecidos e atribuídos. Ele não tornou válido um número de série arbitrário não atribuído.<sup>[[1]](#references)</sup>

### Automatizando a instrumentação com Python

O processo de exploração foi automatizado usando Python com a API do LLDB, tornando viável injetar programaticamente números de série arbitrários e recuperar os DEP profiles correspondentes.<sup>[[1]](#references)</sup>

## Revisão de 2025: Rogue Enrollment a partir de uma VM

A pesquisa apresentada na Black Hat Asia 2025 demonstrou que o problema original de limite de confiança ainda pode ser relevante na **camada MDM**: em vez de aplicar patch no `cloudconfigurationd` com LLDB, os pesquisadores executaram o macOS no QEMU/KVM com OpenCore e forneceram a identidade candidata por meio do SMBIOS da VM. A stack de enrollment não modificada do macOS então realizou a troca criptografada com a Apple. Portanto, serials divulgados publicamente e candidatos com aparência válida podem ser testados sem possuir o Mac físico correspondente; um resultado positivo ainda exige que o serial esteja atribuído a uma organização e que o caminho de enrollment da organização tenha autenticação insuficiente.<sup>[[3]](#references)</sup>

Para um dispositivo de laboratório autorizado, os valores relevantes de `PlatformInfo` do OpenCore incluem um modelo de produto e um serial (em implantações reais, o ROM e o UUID também devem permanecer internamente consistentes):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
A mesma pesquisa identificou o estado `CheckProfilesFetchRateLimit` no arquivo privado `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Como a verificação era mantida no cliente, modificar os valores de tempo armazenados a anulava. Esses caminhos não são documentados e dependem da versão, mas são pivôs úteis de reversing ao avaliar uma build atual do macOS:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
O segundo artefato pode divulgar o activation record armazenado em cache, incluindo se o fluxo usa uma `ConfigurationURL` direta ou uma `ConfigurationWebURL` autenticada. Teste tanto o fluxo anunciado quanto quaisquer endpoints legados de enrollment específicos do MDM: habilitar SSO apenas no fluxo web principal não protege um endpoint direto paralelo. Para obter a sequência completa do protocolo, consulte a [visão geral do macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Busca de Segredos Pós-Enrollment

Um enrollment não autorizado é apenas o ponto de entrada. Após o enrollment, inspecione todos os profiles entregues, bootstrap policies, configurações de package repository, scripts de instalação de agents e itens de self-service. A pesquisa de 2025 recuperou exemplos de credenciais de Wi-Fi, senhas compartilhadas de administradores locais, URLs assinadas de cloud storage, URLs de webhook, dados de ativação de security agents e credenciais de MDM/API. Uma credencial de API do tenant em um script entregue pode transformar um único endpoint não autorizado em controle sobre outros dispositivos gerenciados; portanto, pesquise tanto no sistema de arquivos ativo quanto no conteúdo de policies baixado ou armazenado em cache.<sup>[[3]](#references)</sup>

Os alvos úteis para análise incluem:<sup>[[3]](#references)</sup>

- Payloads `.mobileconfig` instalados e o banco de dados de Configuration Profiles.
- Scripts e packages de PreStage/bootstrap que criam contas ou instalam agents de EDR/VPN.
- URLs de Munki ou de outros package repositories, especialmente strings de consulta contendo assinaturas no estilo bearer/SAS.
- Catálogos de self-service e suas APIs de policy subjacentes, incluindo rotas legadas que podem não aplicar a policy de SSO do enrollment.
- Histórico do shell e saída de policy armazenada em cache em busca de `password`, `token`, `secret`, `Authorization`, hostnames de webhook e endpoints de API de fornecedores.

### Reforçando o Limite de Confiança

Trate um número de série como um atributo de inventário/roteamento, **não** como prova de posse. Exija autenticação do usuário para enrollment e self-service, gere senhas exclusivas de administrador local por dispositivo e nunca inclua credenciais de API do tenant ou segredos reutilizáveis de infraestrutura em profiles ou scripts. Mantenha qualquer bootstrap token inevitável com curta duração e restrito à única ação e ao dispositivo que está sendo provisionado.<sup>[[3]](#references)</sup>

Em Macs com Apple silicon executando macOS 14 ou posterior, o Managed Device Attestation pode vincular criptograficamente a identidade ao Secure Enclave. Sua attestation baseada na raiz da Apple pode transportar um nonce novo, além do número de série, UDID, versão do sistema operacional, estado do SIP e estado do secure boot; o ACME pode então emitir uma identidade de cliente vinculada ao hardware. Use essa identidade para proteger o canal MDM e controlar certificados de alto valor, acesso VPN e outros recursos, mantendo também uma autenticação de usuário separada, pois a attestation do dispositivo comprova o dispositivo, e não o operador.<sup>[[4]](#references)</sup>

## Impactos Potenciais das Vulnerabilidades de DEP e MDM

A pesquisa destacou preocupações significativas de segurança:

1. **Divulgação de Informações**: Ao fornecer um número de série registrado no DEP, é possível recuperar informações organizacionais sensíveis contidas no profile do DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM: talvez — Segurança do Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Síndrome do Impostor: Hacking de Apple MDMs usando Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
