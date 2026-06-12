# Windows Service Triggers: Enumeração e abuso

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers permitem que o Service Control Manager (SCM) inicie/pare um serviço quando uma condição ocorre (por exemplo, um endereço IP fica disponível, uma conexão a um named pipe é tentada, um evento ETW é publicado). Mesmo quando você não tem direitos SERVICE_START em um serviço alvo, ainda pode ser possível iniciá-lo ao fazer seu trigger disparar.

Esta página foca em enumeração amigável para atacante e em formas de baixo atrito para ativar triggers comuns.

> Tip: Iniciar um serviço privilegiado nativo (por exemplo, RemoteRegistry, WebClient/WebDAV, EFS) pode expor novos listeners RPC/named-pipe e desbloquear cadeias adicionais de abuso.

## Enumerating Service Triggers

- sc.exe (local)
- Listar os triggers de um serviço: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Triggers ficam em: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Chame QueryServiceConfig2 com SERVICE_CONFIG_TRIGGER_INFO (8) para recuperar SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] and SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- O SCM pode ser consultado remotamente para obter informações de trigger usando MS‑SCMR. O Titanis da TrustedSec expõe isso: `Scm.exe qtriggers`.
- Impacket define as estruturas em msrpc MS-SCMR; você pode implementar uma consulta remota usando isso.
- PowerShell (bulk enumeration)
- Liste rapidamente todos os serviços que expõem uma chave `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programmatic)
- O módulo `NtObjectManager` de James Forshaw expõe `Get-Win32ServiceTrigger` para analisar metadados de trigger sem precisar extrair a saída do `sc.exe`.

## High-Value Trigger Types and How to Activate Them

### Network Endpoint Triggers

Estes iniciam um serviço quando um cliente tenta falar com um endpoint IPC. Úteis para usuários low-priv porque o SCM iniciará automaticamente o serviço antes que seu client consiga realmente conectar.

- Named pipe trigger
- Behavior: Uma tentativa de conexão de client para \\.\pipe\<PipeName> faz o SCM iniciar o serviço para que ele possa começar a escutar.
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Internals note: named-pipe triggers são suportados por `npsvctrig.sys`, um minifiltro de filesystem que monitora aberturas contra nomes de pipe registrados no trigger. É por isso que a tentativa de abertura pode iniciar o serviço mesmo antes de o próprio serviço criar/escutar o pipe.
- See also: Named Pipe Client Impersonation for post-start abuse.

- RPC endpoint trigger (Endpoint Mapper)
- Behavior: Consultar o Endpoint Mapper (EPM, TCP/135) por um UUID de interface associado a um serviço faz o SCM iniciá-lo para que ele possa registrar seu endpoint.
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Um serviço pode registrar um trigger vinculado a um provider/evento ETW. Se não houver filtros adicionais (keyword/level/binary/string) configurados, qualquer evento desse provider iniciará o serviço.

- Example (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- List trigger: `sc.exe qtriggerinfo webclient`
- Verify provider is registered: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitir eventos correspondentes normalmente requer código que registre logs nesse provider; se não houver filtros, qualquer evento serve.
- Minimal C shape for firing the provider (when no additional ETW filters are configured):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtypes: Machine/User. Em hosts unidos a um domínio onde a policy correspondente existe, o trigger roda no boot. `gpupdate` sozinho não vai disparar sem mudanças, mas:

- Activation: `gpupdate /force`
- Se o tipo de policy relevante existir, isso faz o trigger disparar de forma confiável e iniciar o serviço.

### IP Address Available

Dispara quando o primeiro IP é obtido (ou o último é perdido). Frequentemente dispara no boot.

- Activation: Alterne a conectividade para disparar novamente, por exemplo:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Inicia um serviço quando uma interface de dispositivo correspondente chega. Se nenhum item de dados for especificado, qualquer dispositivo que corresponda ao GUID do subtype do trigger fará o trigger disparar. Avaliado no boot e em hot-plug.

- Activation: Conecte/insira um dispositivo (físico ou virtual) que corresponda ao class/hardware ID especificado pelo subtype do trigger.

### Domain Join State

Apesar da redação confusa do MSDN, isso avalia o estado do domínio no boot:
- DOMAIN_JOIN_GUID → inicia o serviço se estiver domain-joined
- DOMAIN_LEAVE_GUID → inicia o serviço somente se NÃO estiver domain-joined

### System State Change – WNF (undocumented)

Alguns serviços usam triggers não documentados baseados em WNF (SERVICE_TRIGGER_TYPE 0x7). A ativação exige publicar o estado WNF relevante; os detalhes dependem do state name. Contexto de pesquisa: Windows Notification Facility internals.

### Aggregate Service Triggers (undocumented)

Observados no Windows 11 para alguns serviços (por exemplo, CDPSvc). A configuração agregada fica em:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

O valor Trigger de um serviço é um GUID; a subkey com esse GUID define o evento agregado. Disparar qualquer evento constituinte inicia o serviço.

### Firewall Port Event (quirks and DoS risk)

Um trigger escopado para uma porta/protocolo específica foi observado iniciando com qualquer mudança de regra de firewall (disable/delete/add), e não apenas para a porta especificada. Pior, configurar uma porta sem um protocolo pode corromper o startup do BFE entre reboots, causando falhas em cascata em muitos serviços e quebrando o gerenciamento do firewall. Trate com extremo cuidado.

## Practical Workflow

1) Enumere triggers em serviços interessantes (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se existir um Network Endpoint trigger:
- Named pipe → tente uma abertura de client para \\.\pipe\<PipeName>
- RPC endpoint → faça uma lookup no Endpoint Mapper para o UUID da interface

3) Se existir um trigger ETW:
- Verifique provider e filters com `sc.exe qtriggerinfo`; se não houver filters, qualquer evento desse provider iniciará o serviço

4) Para triggers Group Policy/IP/Device/Domain:
- Use alavancas do ambiente: `gpupdate /force`, altere NICs, faça hot-plug de devices, etc.

## Related

- Após iniciar um serviço privilegiado via um Named Pipe trigger, você pode conseguir impersonate-lo:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Quick command recap

- List triggers (local): `sc.exe qtriggerinfo <Service>`
- Registry view: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW provider check (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Operator Notes

- Verifique primeiro o start type do serviço com `sc.exe qc <Service>`. Se estiver `DISABLED`, disparar o trigger não basta; você precisa primeiro encontrar uma forma de alterar a configuração.
- Serviços iniciados por trigger podem parar novamente após ficarem idle. Se sua ação seguinte depender de um listener de vida curta (RPC/named pipe/WebDAV), dispare e consuma imediatamente.
- `sc.exe qtriggerinfo` não entende completamente todo tipo de trigger não documentado. Para aggregate triggers em builds mais novos do Windows, confirme o GUID de suporte e os eventos constituintes em `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Detection and Hardening Notes

- Faça baseline e audit de TriggerInfo em todos os serviços. Revise também HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents para aggregate triggers.
- Monitore lookups suspeitos de EPM para UUIDs de serviços privilegiados e tentativas de conexão a named-pipes que precedem o start de serviços.
- Restrinja quem pode modificar service triggers; trate falhas inesperadas do BFE após mudanças de trigger como suspeitas.

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)
- [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
