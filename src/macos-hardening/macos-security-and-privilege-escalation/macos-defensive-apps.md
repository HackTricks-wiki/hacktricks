# Aplicativos defensivos do macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitora cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexões silenciosamente e alertar), ele **exibirá um alerta** sempre que uma nova conexão for estabelecida. Ele também conta com uma GUI muito boa para visualizar todas essas informações.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall da Objective-See. É um firewall básico que alertará sobre conexões suspeitas (ele possui uma GUI, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de persistência

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplicativo da Objective-See que procura em vários locais onde o **malware pode estar persistindo** (é uma ferramenta de execução única, não um serviço de monitoramento).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Semelhante ao KnockKnock, monitorando processos que geram persistência.

## Detecção de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplicativo da Objective-See para encontrar **keyloggers** que instalam "event taps" do teclado.

## Telemetria de endpoint / controle de execução

- [**Santa**](https://santa.dev/): Sistema de autorização e monitoramento de binários para macOS. Ele usa um cliente do **Endpoint Security** para autorizar eventos de **`exec`** antes que o código seja executado, por isso é comum em frotas corporativas focadas em **allowlisting/denylisting**, em vez de apenas na detecção pós-execução.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Ferramenta de análise dinâmica para macOS semelhante ao Procmon. Ela ingere **telemetria do Endpoint Security** (eventos relacionados a processos, arquivos, interprocessos, login e XProtect) e é útil para entender o que um sensor maduro baseado em ES pode realmente observar.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Ferramentas leves da Objective-See para telemetria de **processos**, **arquivos** e **DNS**. Em versões modernas do macOS, elas têm pré-requisitos adicionais, como **root**, **Acesso Total ao Disco no Terminal** ou aprovação de **System/Network Extension**. Para mais ideias de instrumentação, consulte [esta outra página sobre inspeção, debugging e fuzzing de aplicativos macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triagem rápida de ferramentas defensivas

A maioria dos produtos modernos de segurança para macOS é executada como alguma combinação de **System Extensions / clientes do Endpoint Security**, **agentes/daemons do launchd** e aplicativos com **Acesso Total ao Disco**. Uma checklist rápida para o operador:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
Se `systemextensionsctl list` mostrar um sensor como **`[activated enabled]`**, geralmente é o indicador mais rápido de que a extensão está realmente ativa. No **macOS 15 Sequoia e posteriores**, o MDM também pode marcar extensões de segurança específicas como **não removíveis pela interface**, portanto, "desativá-la nas Configurações do Sistema" já não é uma suposição segura. Para detalhes internos, consulte [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetria nativa recente que os defensores podem usar

Versões recentes do macOS tornaram alguns bypasses anteriormente difíceis de detectar, acionados pelo usuário, muito mais ruidosos para as blue teams:

- **macOS 15+**: clientes do Endpoint Security podem receber eventos **`gatekeeper_user_override`**, portanto, bypasses manuais do Gatekeeper podem ser registrados centralmente.
- As ferramentas atuais do Endpoint Security do macOS também podem ingerir eventos de **detecção de malware do XProtect**, facilitando a confirmação do que a Apple já detectou no endpoint.
- **macOS 15.4+**: o Endpoint Security adiciona **`tcc_modify`**, finalmente oferecendo aos defensores uma forma compatível de monitorar **concessões/revogações do TCC**, em vez de extrair informações dos logs de depuração do TCC.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Isto é útil tanto para defensores quanto para red teamers que realizam autoavaliações: se o alvo tiver uma stack baseada em ES madura, **cadeias de bypass de Gatekeeper / TCC aprovadas pelo usuário podem estar muito mais visíveis do que costumavam estar**. Para obter contexto sobre essas proteções, consulte [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) e [TCC](macos-security-protections/macos-tcc/README.md).

## Referências


- [1] [Objective-See - Acreditar é fazer TCCing! A Apple finalmente adiciona eventos de TCC ao Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Apresentando: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
