# Número de serie de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los dispositivos Apple posteriores a 2010 tienen números de serie compuestos por **12 caracteres alfanuméricos**, donde cada segmento transmite información específica:

- **Primeros 3 caracteres**: Indican el **lugar de fabricación**.
- **Caracteres 4 y 5**: Indican el **año y la semana de fabricación**.
- **Caracteres 6 a 8**: Sirven como **identificador único** de cada dispositivo.
- **Últimos 4 caracteres**: Especifican el **número de modelo**.

Por ejemplo, el número de serie **C02L13ECF8J2** sigue esta estructura.

### **Lugares de fabricación (primeros 3 caracteres)**

Ciertos códigos representan fábricas específicas:

- **FC, F, XA/XB/QP/G8**: Diversos lugares en EE. UU.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Checa.
- **SG/E**: Singapur.
- **MB**: Malasia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwán.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes lugares en China.
- **C0, C3, C7**: Ciudades específicas de China.
- **RM**: Dispositivos reacondicionados.

### **Año de fabricación (4.º carácter)**

Este carácter varía de la 'C' (que representa la primera mitad de 2010) a la 'Z' (segunda mitad de 2019), donde diferentes letras indican distintos períodos semestrales.

### **Semana de fabricación (5.º carácter)**

Los dígitos del 1 al 9 corresponden a las semanas 1 a 9. Las letras de la C a la Y (excepto las vocales y la 'S') representan las semanas 10 a 27. Para la segunda mitad del año, se suma 26 a este número.

{{#include ../../../banners/hacktricks-training.md}}
