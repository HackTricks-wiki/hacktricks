# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#3f17" id="3f17"></a>

**Consulta la publicación original para [obtener toda la información sobre esta técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En resumen, controlar el **`msDS-KeyCredentialLink`** de un usuario o equipo puede permitir que un atacante agregue una credencial de clave, se autentique como ese objeto mediante PKINIT y, cuando el KDC y la cuenta admitan los flujos necesarios, use el ticket resultante con `S4U2Self`/user-to-user para recuperar el hash NT del objeto.<sup>[[1]](#references)</sup>

La publicación describe un método para configurar **credenciales de autenticación con clave pública y privada** y obtener un **Service Ticket** único que incluye el hash NTLM del objetivo. Este proceso utiliza el NTLM_SUPPLEMENTAL_CREDENTIAL cifrado dentro del Privilege Attribute Certificate (PAC), que se puede descifrar.<sup>[[1]](#references)</sup>

### Requisitos

Para aplicar esta técnica, deben cumplirse ciertas condiciones:<sup>[[1]](#references)</sup>

- Se necesita al menos un Domain Controller con Windows Server 2016.
- El Domain Controller debe tener instalado un certificado digital de autenticación de servidor.
- El esquema del directorio debe incluir `msDS-KeyCredentialLink`; los requisitos prácticos de la plataforma descritos por la investigación son un DC con Windows Server 2016 o posterior y un certificado compatible con PKINIT en el KDC. Verifica la combinación de esquemas/DC del dominio, en lugar de asumir que la etiqueta del nivel funcional del dominio determina por sí sola si es explotable.
- Se necesita una cuenta con derechos delegados para modificar el atributo msDS-KeyCredentialLink del objeto objetivo.

## Abuso

El abuso de Key Trust en objetos de equipo abarca más pasos que obtener un Ticket Granting Ticket (TGT) y el hash NTLM. Entre las opciones se incluyen:<sup>[[1]](#references)</sup>

1. Crear un **RC4 silver ticket** para actuar como usuarios privilegiados en el host previsto.
2. Usar el TGT con **S4U2Self** para suplantar a **usuarios privilegiados**, lo que requiere modificar el Service Ticket para agregar una clase de servicio al nombre del servicio.

Una ventaja importante del abuso de Key Trust es que se limita a la clave privada generada por el atacante, evita la delegación a cuentas potencialmente vulnerables y no requiere crear una cuenta de equipo, que podría ser difícil de eliminar.<sup>[[1]](#references)</sup>

## Herramientas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker usa DSInternals para manipular `msDS-KeyCredentialLink` desde C#. Whisker y su equivalente en Python, **pyWhisker**, permiten agregar, enumerar, eliminar y borrar credenciales de clave.<sup>[[2]](#references)[[4]](#references)</sup>

Las funciones de **Whisker** incluyen:

- **Add**: Genera un par de claves y agrega una credencial de clave.
- **List**: Muestra todas las entradas de credenciales de clave.
- **Remove**: Elimina una credencial de clave especificada.
- **Clear**: Borra todas las credenciales de clave, lo que podría interrumpir el uso legítimo de WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker lleva este flujo de trabajo a los **sistemas tipo UNIX** con Impacket y PyDSInternals, e incluye operaciones para listar, agregar y eliminar, así como importar y exportar JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera objetos del dominio sobre los que el operador tiene permisos como `GenericWrite`/`GenericAll`, intenta agregar key credentials de forma amplia e incluye modos de limpieza y recursivos. El spraying amplio es disruptivo y llamativo; usa objetivos explícitos y conserva cada DeviceID agregado para poder eliminarlo con precisión.<sup>[[3]](#references)</sup>

ADWS puede transportar la escritura de key credentials cuando se filtra LDAP directo. Consulta el [flujo de trabajo de SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Abuso de Key Trust Account Mapping para tomar el control de una cuenta](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker: herramienta para tomar el control de cuentas de AD mediante la manipulación de msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray: herramienta para propagar Shadow Credentials por un dominio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker: versión en Python de la herramienta Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki de SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
