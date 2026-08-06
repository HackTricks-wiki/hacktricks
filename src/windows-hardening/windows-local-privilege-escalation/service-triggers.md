# Windows Service Triggers: Enumeração e Abuso

{{#include ../../banners/hacktricks-training.md}}

Os Windows Service Triggers permitem que o Service Control Manager (SCM) inicie ou pare um serviço quando uma condição ocorre (por exemplo, um endereço IP fica disponível, uma conexão com um named pipe é tentada ou um evento ETW é publicado). Mesmo quando você não possui direitos `SERVICE_START` em um serviço-alvo, ainda pode conseguir iniciá-lo fazendo com que seu trigger seja acionado.<sup>[[1]](#references)</sup>

Esta página concentra-se em enumeração favorável ao atacante e em formas simples de ativar triggers comuns.

> Dica: iniciar um serviço privilegiado integrado (por exemplo, RemoteRegistry, WebClient/WebDAV, EFS) pode expor novos listeners RPC/named-pipe e possibilitar outras cadeias de abuso.

## Enumerando Service Triggers

- sc.exe (local)
- Listar os triggers de um serviço: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Os triggers ficam em: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Fazer dump recursivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Chamar QueryServiceConfig2 com SERVICE_CONFIG_TRIGGER_INFO (8) para recuperar SERVICE_TRIGGER_INFO.
- Docs: QueryServiceConfig2[W/A] e SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA<sup>[[2]](#references)</sup>
- RPC via MS-SCMR (remoto)
- O SCM pode ser consultado remotamente para obter informações de triggers usando MS-SCMR. O Titanis, da TrustedSec, expõe isso: `Scm.exe qtriggers`.
- O Impacket define as estruturas em msrpc MS-SCMR; você pode implementar uma consulta remota usando essas estruturas.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
- PowerShell (enumeração em massa)
- Listar rapidamente todos os serviços que expõem uma chave `TriggerInfo`:
```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
Where-Object { Test-Path "$($_.PSPath)\TriggerInfo" } |
ForEach-Object { sc.exe qtriggerinfo $_.PSChildName }
```
- PowerShell (programático)
- O módulo `NtObjectManager`, de James Forshaw, expõe `Get-Win32ServiceTrigger` para analisar metadados de triggers sem extrair a saída do `sc.exe`.

## Tipos de Trigger de Alto Valor e Como Ativá-los

### Network Endpoint Triggers

Eles iniciam um serviço quando um client tenta se comunicar com um endpoint IPC. São úteis para usuários com poucos privilégios porque o SCM inicia automaticamente o serviço antes que o client consiga se conectar de fato.<sup>[[1]](#references)</sup>

- Named pipe trigger
- Comportamento: uma tentativa de conexão do client com \\.\pipe\<PipeName> faz com que o SCM inicie o serviço para que ele comece a escutar.
- Ativação (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Nota sobre os internals: os named-pipe triggers são implementados por `npsvctrig.sys`, um minifilter de sistema de arquivos que monitora aberturas contra nomes de pipes de trigger registrados. Por isso, a tentativa de abertura pode iniciar o serviço mesmo antes de o próprio serviço ter criado ou começado a escutar no pipe.<sup>[[5]](#references)</sup>
- Consulte também: Named Pipe Client Impersonation para abuso pós-inicialização.

- RPC endpoint trigger (Endpoint Mapper)
- Comportamento: consultar o Endpoint Mapper (EPM, TCP/135) em busca de uma interface UUID associada a um serviço faz com que o SCM o inicie para que ele possa registrar seu endpoint.
- Ativação (Impacket):
```bash
# Consulta o EPM local; substitua UUID pelo GUID da interface do serviço
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

Um serviço pode registrar um trigger vinculado a um provider/evento ETW. Se nenhum filtro adicional (keyword/level/binary/string) estiver configurado, qualquer evento desse provider iniciará o serviço.<sup>[[1]](#references)</sup>

- Exemplo (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}<sup>[[6]](#references)</sup>
- Listar o trigger: `sc.exe qtriggerinfo webclient`
- Verificar se o provider está registrado: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- A emissão de eventos correspondentes normalmente exige código que registre eventos nesse provider; se não houver filtros, qualquer evento será suficiente.
- Estrutura C mínima para disparar o provider (quando nenhum filtro ETW adicional estiver configurado):
```c
GUID g = {0x22B6D684,0xFA63,0x4578,{0x87,0xC9,0xEF,0xFC,0xBE,0x66,0x43,0xC7}};
REGHANDLE h; EVENT_DESCRIPTOR d;
EventRegister(&g, NULL, NULL, &h);
EventDescCreate(&d, 1, 0, 0, 4, 0, 0, 0);
EventWrite(h, &d, 0, NULL);
EventUnregister(h);
```

### Group Policy Triggers

Subtipos: Machine/User. Em hosts ingressados em um domínio onde a política correspondente existe, o trigger é executado na inicialização. Apenas `gpupdate` não o acionará sem alterações, mas:<sup>[[1]](#references)</sup>

- Ativação: `gpupdate /force`
- Se o tipo de política relevante existir, isso fará o trigger ser acionado de forma confiável e iniciará o serviço.

### IP Address Available

É acionado quando o primeiro IP é obtido (ou o último é perdido). Frequentemente é acionado na inicialização.<sup>[[1]](#references)</sup>

- Ativação: alternar a conectividade para acioná-lo novamente, por exemplo:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

Inicia um serviço quando uma interface de dispositivo correspondente é detectada. Se nenhum item de dados for especificado, qualquer dispositivo correspondente ao GUID do subtipo do trigger acionará o trigger. É avaliado na inicialização e quando ocorre hot-plug.<sup>[[1]](#references)</sup>

- Ativação: conectar/inserir um dispositivo (físico ou virtual) que corresponda à classe/ID de hardware especificado pelo subtipo do trigger.

### Domain Join State

Apesar da redação confusa do MSDN, isso avalia o estado do domínio na inicialização:<sup>[[1]](#references)</sup>
- DOMAIN_JOIN_GUID → inicia o serviço se o host estiver ingressado em um domínio
- DOMAIN_LEAVE_GUID → inicia o serviço somente se o host NÃO estiver ingressado em um domínio

### System State Change – WNF (undocumented)

Alguns serviços usam triggers baseados em WNF não documentados (SERVICE_TRIGGER_TYPE 0x7). A ativação exige a publicação do estado WNF relevante; os detalhes dependem do nome do estado. Contexto de pesquisa: internals do Windows Notification Facility.

### Aggregate Service Triggers (undocumented)

Observados no Windows 11 para alguns serviços (por exemplo, CDPSvc). A configuração agregada é armazenada em:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

O valor Trigger de um serviço é um GUID; a subchave com esse GUID define o evento agregado. Acionar qualquer evento constituinte inicia o serviço.<sup>[[1]](#references)</sup>

### Firewall Port Event (quirks and DoS risk)

Foi observado que um trigger associado a uma porta/protocolo específico é iniciado por qualquer alteração em uma regra de firewall (desabilitar/excluir/adicionar), e não apenas pela porta especificada. Pior ainda, configurar uma porta sem um protocolo pode corromper a inicialização do BFE após reinicializações, causando falhas em cascata em muitos serviços e interrompendo o gerenciamento do firewall. Tenha extrema cautela.<sup>[[1]](#references)</sup>

## Fluxo de Trabalho Prático

1) Enumerar triggers em serviços interessantes (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se existir um Network Endpoint trigger:
- Named pipe → tentar uma abertura de client para \\.\pipe\<PipeName>
- RPC endpoint → realizar uma consulta ao Endpoint Mapper para o UUID da interface

3) Se existir um ETW trigger:
- Verificar o provider e os filtros com `sc.exe qtriggerinfo`; se não houver filtros, qualquer evento desse provider iniciará o serviço

4) Para triggers de Group Policy/IP/Device/Domain:
- Usar mecanismos ambientais: `gpupdate /force`, alternar NICs, conectar dispositivos via hot-plug etc.

## Relacionado

- Depois de iniciar um serviço privilegiado por meio de um Named Pipe trigger, talvez seja possível personificá-lo:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Resumo rápido dos comandos

- Listar triggers (local): `sc.exe qtriggerinfo <Service>`
- Visualização no Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remoto (Titanis): `Scm.exe qtriggers`
- Verificação do provider ETW (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Gotchas / Notas para Operadores

- Verifique primeiro o tipo de inicialização do serviço com `sc.exe qc <Service>`. Se estiver `DISABLED`, acionar o trigger não será suficiente; primeiro será necessário encontrar uma forma de alterar a configuração.
- Serviços iniciados por trigger podem parar novamente depois de ficarem ociosos. Se sua ação subsequente depender de um listener de curta duração (RPC/named pipe/WebDAV), acione o trigger e consuma-o imediatamente.
- `sc.exe qtriggerinfo` não compreende completamente todos os tipos de trigger não documentados. Para aggregate triggers em versões mais recentes do Windows, confirme o GUID subjacente e os eventos constituintes em `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents`.

## Notas de Detecção e Hardening

- Crie uma baseline e audite o TriggerInfo de todos os serviços. Revise também `HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents` em busca de aggregate triggers.
- Monitore consultas EPM suspeitas para UUIDs de serviços privilegiados e tentativas de conexão com named pipes que precedam a inicialização de serviços.
- Restrinja quem pode modificar service triggers; trate falhas inesperadas do BFE após alterações em triggers como suspeitas.

## Referências
- [1] [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [2] [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [3] [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [4] [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [5] [Reversing npsvctrig.sys - Named Pipe Service Triggers (Inbits)](https://inbits-sec.com/posts/npsvctrig-notes/)
- [6] [Starting WebClient Service Programmatically (Tyranid)](https://www.tiraniddo.dev/2015/03/starting-webclient-service.html)

{{#include ../../banners/hacktricks-training.md}}
