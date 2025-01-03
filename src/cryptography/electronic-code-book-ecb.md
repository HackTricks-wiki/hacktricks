{{#include ../banners/hacktricks-training.md}}

# ECB

(ECB) Libro de Códigos Electrónicos - esquema de cifrado simétrico que **reemplaza cada bloque del texto claro** por el **bloque de texto cifrado**. Es el esquema de cifrado **más simple**. La idea principal es **dividir** el texto claro en **bloques de N bits** (depende del tamaño del bloque de datos de entrada, algoritmo de cifrado) y luego cifrar (descifrar) cada bloque de texto claro utilizando la única clave.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Usar ECB tiene múltiples implicaciones de seguridad:

- **Se pueden eliminar bloques del mensaje cifrado**
- **Se pueden mover bloques del mensaje cifrado**

# Detección de la vulnerabilidad

Imagina que inicias sesión en una aplicación varias veces y **siempre obtienes la misma cookie**. Esto se debe a que la cookie de la aplicación es **`<nombredeusuario>|<contraseña>`**.\
Luego, generas dos nuevos usuarios, ambos con la **misma contraseña larga** y **casi** el **mismo** **nombre de usuario**.\
Descubres que los **bloques de 8B** donde la **info de ambos usuarios** es la misma son **iguales**. Luego, imaginas que esto podría ser porque **se está utilizando ECB**.

Como en el siguiente ejemplo. Observa cómo estas **2 cookies decodificadas** tienen varias veces el bloque **`\x23U\xE45K\xCB\x21\xC8`**.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Esto se debe a que el **nombre de usuario y la contraseña de esas cookies contenían varias veces la letra "a"** (por ejemplo). Los **bloques** que son **diferentes** son bloques que contenían **al menos 1 carácter diferente** (quizás el delimitador "|" o alguna diferencia necesaria en el nombre de usuario).

Ahora, el atacante solo necesita descubrir si el formato es `<username><delimiter><password>` o `<password><delimiter><username>`. Para hacer eso, puede **generar varios nombres de usuario** con nombres de usuario y contraseñas **similares y largos hasta que encuentre el formato y la longitud del delimitador:**

| Longitud del nombre de usuario: | Longitud de la contraseña: | Longitud del nombre de usuario+contraseña: | Longitud de la cookie (después de decodificar): |
| ------------------------------- | -------------------------- | ------------------------------------------- | ------------------------------------------------ |
| 2                               | 2                          | 4                                           | 8                                                |
| 3                               | 3                          | 6                                           | 8                                                |
| 3                               | 4                          | 7                                           | 8                                                |
| 4                               | 4                          | 8                                           | 16                                               |
| 7                               | 7                          | 14                                          | 16                                               |

# Explotación de la vulnerabilidad

## Eliminando bloques enteros

Conociendo el formato de la cookie (`<username>|<password>`), para suplantar el nombre de usuario `admin`, crea un nuevo usuario llamado `aaaaaaaaadmin` y obtén la cookie y decodifícalo:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Podemos ver el patrón `\x23U\xE45K\xCB\x21\xC8` creado anteriormente con el nombre de usuario que contenía solo `a`.\
Luego, puedes eliminar el primer bloque de 8B y obtendrás una cookie válida para el nombre de usuario `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Moviendo bloques

En muchas bases de datos es lo mismo buscar `WHERE username='admin';` o `WHERE username='admin    ';` _(Nota los espacios extra)_

Así que, otra forma de suplantar al usuario `admin` sería:

- Generar un nombre de usuario que: `len(<username>) + len(<delimiter) % len(block)`. Con un tamaño de bloque de `8B` puedes generar un nombre de usuario llamado: `username       `, con el delimitador `|` el fragmento `<username><delimiter>` generará 2 bloques de 8Bs.
- Luego, generar una contraseña que llenará un número exacto de bloques conteniendo el nombre de usuario que queremos suplantar y espacios, como: `admin   `

La cookie de este usuario va a estar compuesta por 3 bloques: los primeros 2 son los bloques del nombre de usuario + delimitador y el tercero de la contraseña (que está simulando el nombre de usuario): `username       |admin   `

**Luego, solo reemplaza el primer bloque con el último y estarás suplantando al usuario `admin`: `admin          |username`**

## Referencias

- [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](<http://cryptowiki.net/index.php?title=Electronic_Code_Book_(ECB)>)

{{#include ../banners/hacktricks-training.md}}
