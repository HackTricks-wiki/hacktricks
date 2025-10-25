# Gatilhos de Serviço do Windows: Enumeração e Abuso

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers permitem que o Service Control Manager (SCM) inicie/pare um serviço quando uma condição ocorre (ex.: um endereço IP fica disponível, uma conexão a um named pipe é tentada, um evento ETW é publicado). Mesmo quando você não tem direitos SERVICE_START sobre um serviço alvo, ainda pode ser capaz de iniciá‑lo fazendo com que seu gatilho dispare.

Esta página foca na enumeração amigável ao atacante e em maneiras de baixa fricção para ativar gatilhos comuns.

> Dica: Iniciar um serviço privilegiado embutido (ex.: RemoteRegistry, WebClient/WebDAV, EFS) pode expor novos listeners RPC/named‑pipe e desbloquear cadeias de abuso adicionais.

## Enumerando Gatilhos de Serviço

- sc.exe (local)
- Listar os gatilhos de um serviço: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- Os gatilhos ficam em: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- Dump recursivo: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- Chame QueryServiceConfig2 com SERVICE_CONFIG_TRIGGER_INFO (8) para recuperar SERVICE_TRIGGER_INFO.
- Documentação: QueryServiceConfig2[W/A] e SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remoto)
- O SCM pode ser consultado remotamente para buscar info de gatilho usando MS‑SCMR. O Titanis da TrustedSec expõe isso: `Scm.exe qtriggers`.
- Impacket define as estruturas em msrpc MS‑SCMR; você pode implementar uma consulta remota usando essas estruturas.

## Tipos de Gatilho de Alto Valor e Como Ativá‑los

### Gatilhos de Endpoint de Rede

Estes iniciam um serviço quando um cliente tenta falar com um endpoint IPC. Útil para usuários com poucas permissões porque o SCM iniciará automaticamente o serviço antes que seu cliente consiga realmente conectar.

- Gatilho de named pipe
- Comportamento: Uma tentativa de conexão de cliente a \\.\pipe\<PipeName> faz o SCM iniciar o serviço para que ele comece a escutar.
- Ativação (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- Veja também: Named Pipe Client Impersonation para abuso pós‑início.

- Gatilho de endpoint RPC (Endpoint Mapper)
- Comportamento: Consultar o Endpoint Mapper (EPM, TCP/135) por um interface UUID associado a um serviço faz o SCM iniciá‑lo para que ele registre seu endpoint.
- Ativação (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Gatilhos Personalizados (ETW)

Um serviço pode registrar um gatilho vinculado a um provedor/evento ETW. Se nenhum filtro adicional (keyword/level/binary/string) estiver configurado, qualquer evento daquele provedor irá iniciar o serviço.

- Exemplo (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- Listar gatilho: `sc.exe qtriggerinfo webclient`
- Verificar se o provedor está registrado: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- Emitir eventos correspondentes normalmente requer código que registre para esse provedor; se não houver filtros, qualquer evento é suficiente.

### Gatilhos de Group Policy

Subtipos: Machine/User. Em hosts ingressados no domínio onde a política correspondente existe, o gatilho roda na inicialização. `gpupdate` sozinho não disparará sem mudanças, mas:

- Ativação: `gpupdate /force`
- Se o tipo de política relevante existir, isso causa de forma confiável o gatilho disparar e iniciar o serviço.

### Disponibilidade de Endereço IP

Dispara quando o primeiro IP é obtido (ou o último é perdido). Frequentemente dispara na inicialização.

- Ativação: Alternar conectividade para retrigger, ex.:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Chegada de Interface de Dispositivo

Inicia um serviço quando uma interface de dispositivo correspondente chega. Se nenhum data item estiver especificado, qualquer dispositivo que corresponda ao GUID do subtipo do gatilho disparará o gatilho. Avaliado na inicialização e ao hot‑plug.

- Ativação: Anexe/insira um dispositivo (físico ou virtual) que corresponda à class/hardware ID especificada pelo subtipo do gatilho.

### Estado de Associação ao Domínio

Apesar da redação confusa na MSDN, isso avalia o estado do domínio na inicialização:
- DOMAIN_JOIN_GUID → iniciar o serviço se associado ao domínio
- DOMAIN_LEAVE_GUID → iniciar o serviço apenas se NÃO estiver associado ao domínio

### Mudança do Estado do Sistema – WNF (não documentado)

Alguns serviços usam gatilhos baseados em WNF não documentados (SERVICE_TRIGGER_TYPE 0x7). A ativação requer publicar o estado WNF relevante; os detalhes dependem do nome do estado. Contexto de pesquisa: internals do Windows Notification Facility.

### Gatilhos de Serviço Agregados (não documentados)

Observado no Windows 11 para alguns serviços (ex.: CDPSvc). A configuração agregada é armazenada em:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

O valor Trigger de um serviço é um GUID; a subchave com esse GUID define o evento agregado. Disparar qualquer evento constitutivo inicia o serviço.

### Evento de Porta de Firewall (peculiaridades e risco de DoS)

Um gatilho com escopo para uma porta/protocolo específico foi observado iniciando em qualquer alteração de regra de firewall (desabilitar/excluir/adicionar), não apenas na porta especificada. Pior, configurar uma porta sem protocolo pode corromper o startup do BFE através de reboots, causando uma cascata de falhas em muitos serviços e quebrando o gerenciamento do firewall. Trate com extrema cautela.

## Fluxo de Trabalho Prático

1) Enumere gatilhos em serviços interessantes (RemoteRegistry, WebClient, EFS, …):
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Se existir um Network Endpoint trigger:
- Named pipe → tente uma abertura cliente em \\.\pipe\<PipeName>
- RPC endpoint → faça uma consulta no Endpoint Mapper pelo interface UUID

3) Se existir um ETW trigger:
- Verifique o provedor e filtros com `sc.exe qtriggerinfo`; se não houver filtros, qualquer evento daquele provedor iniciará o serviço

4) Para gatilhos de Group Policy/IP/Device/Domain:
- Use alavancas ambientais: `gpupdate /force`, desative/ative NICs, hot‑plug de dispositivos, etc.

## Relacionado

- Após iniciar um serviço privilegiado via um Named Pipe trigger, você pode ser capaz de impersoná‑lo:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## Recapitulação rápida de comandos

- Listar gatilhos (local): `sc.exe qtriggerinfo <Service>`
- Visualizar no Registry: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remoto (Titanis): `Scm.exe qtriggers`
- Verificação de provedor ETW (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## Notas de Detecção e Endurecimento

- Estabeleça baseline e audite TriggerInfo across services. Também revise HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents para gatilhos agregados.
- Monitore por consultas EPM suspeitas por UUIDs de serviços privilegiados e tentativas de conexão a named‑pipe que precedem inícios de serviço.
- Restrinja quem pode modificar gatilhos de serviço; trate falhas inesperadas do BFE após mudanças em gatilhos como suspeitas.

## Referências
- [Há mais de uma forma de acionar um serviço do Windows (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [Função QueryServiceConfig2 (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (enumeração de gatilhos SCM)](https://github.com/trustedsec/Titanis)
- [Exemplo BOF do Cobalt Strike – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
