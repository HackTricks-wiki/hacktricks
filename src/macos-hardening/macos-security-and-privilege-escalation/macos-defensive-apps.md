# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Ele monitorará cada conexão feita por cada processo. Dependendo do modo (permitir conexões silenciosamente, negar conexões silenciosamente e alertar), ele **mostrará um alerta** toda vez que uma nova conexão for estabelecida. Ele também tem uma GUI muito boa para ver todas essas informações.
- [**LuLu**](https://objective-see.org/products/lulu.html): firewall da Objective-See. Este é um firewall básico que irá alertá-lo sobre conexões suspeitas (ele tem uma GUI, mas não é tão sofisticada quanto a do Little Snitch).

## Detecção de persistência

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): aplicação da Objective-See que vai procurar em vários locais onde **malware poderia estar persistindo** (é uma ferramenta de uso único, não um serviço de monitoramento).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Como o KnockKnock, monitorando processos que geram persistência.

## Detecção de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): aplicação da Objective-See para encontrar **keyloggers** que instalam "event taps" do teclado

## Telemetria de endpoint / controle de execução

- [**Santa**](https://santa.dev/): Sistema de autorização binária e monitoramento para macOS. Ele usa um cliente de **Endpoint Security** para autorizar eventos de **`exec`** antes da execução do código, então é comum em frotas corporativas focadas em **allowlisting/denylisting** em vez de apenas detecção pós-execução.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): ferramenta de análise dinâmica para macOS, tipo Procmon. Ele ingere **telemetria de Endpoint Security** (eventos de processo, arquivo, interprocesso, login e relacionados ao XProtect) e é útil para entender o que um sensor maduro baseado em ES realmente consegue observar.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): ferramentas leves da Objective-See para telemetria de **processo**, **arquivo** e **DNS**. Em macOS modernos, elas têm pré-requisitos extras como **root**, **Terminal Full Disk Access** ou aprovação de **System/Network Extension**. Para mais ideias de instrumentação, veja [esta outra página sobre inspeção/debugging e fuzzing de apps no macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triagem rápida de tooling defensivo

A maioria dos produtos modernos de segurança para macOS roda como alguma combinação de **System Extensions / Endpoint Security clients**, **launchd agents/daemons** e aplicações com **Full Disk Access**. Uma checklist rápida do operador:
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
If `systemextensionsctl list` mostrar um sensor como **`[activated enabled]`**, geralmente é o indicador mais rápido de que a extensão está realmente ativa. No **macOS 15 Sequoia e posteriores**, o MDM também pode marcar extensões de segurança específicas como **não removíveis pela UI**, então "desativá-la em System Settings" já não é uma suposição segura. Para detalhes internos, veja [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetria nativa recente que defensores podem consumir

Versões recentes do macOS tornaram alguns bypasses acionados pelo usuário, antes irritantes de detectar, muito mais barulhentos para blue teams:

- **macOS 15+**: clientes de Endpoint Security podem receber eventos **`gatekeeper_user_override`**, então bypasses manuais de Gatekeeper podem ser registrados centralmente.
- **As ferramentas atuais de Endpoint Security no macOS** também podem ingerir eventos de **detecção de malware do XProtect**, facilitando confirmar o que a Apple já detectou no endpoint.
- **macOS 15.4+**: Endpoint Security adiciona **`tcc_modify`**, que finalmente dá aos defensores uma forma suportada de monitorar **concessões/revogação de TCC** em vez de extrair logs de debug do TCC.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Isso é útil tanto para defensores quanto para red teamers fazendo autoavaliação: se o alvo tiver uma stack madura baseada em ES, **cadeias de bypass de Gatekeeper / TCC aprovadas pelo usuário podem ser muito mais visíveis do que antes**. Para contexto sobre essas proteções, veja [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) e [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
