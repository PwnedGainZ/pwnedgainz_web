---
{"dg-publish":true,"permalink":"/programacion-web/obfuscacion/decodificacion/","dgPassFrontmatter":true}
---


---

Después de hacer el ejercicio en la sección anterior, tenemos un extraño bloque de texto que parece estar codificado:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ curl http:/SERVER_IP:PORT/serial.php -X POST -d "param1=sample"

ZG8gdGhlIGV4ZXJjaXNlLCBkb24ndCBjb3B5IGFuZCBwYXN0ZSA7KQo=
```

Este es otro aspecto importante de la ofuscación a la que nos referimos en `More Obfuscation`en el `Advanced Obfuscation`Sección. Muchas técnicas pueden ofuscar aún más el código y hacerlo menos legible por los humanos y menos detectable por los sistemas. Por esa razón, muy a menudo encontrarás código ofuscado que contiene bloques de texto codificados que se decodifican en la ejecución. Cubriremos 3 de los métodos de codificación de texto más utilizados:

- `base64`
- `hex`
- `rot13`

---

## Base64

`base64`La codificación se utiliza generalmente para reducir el uso de caracteres especiales, como cualquier personaje codificado en `base64`estaría representada en caracteres alfanuméricos, además de `+`y `/`Sólo. Independientemente de la entrada, incluso si está en formato binario, la base resultante64 encadenada sólo los usaría.

#### Spotting Base64

`base64`Las cuerdas codificadas se detectan fácilmente ya que sólo contienen caracteres alfanuméricos. Sin embargo, la característica más distintiva de `base64`es su acolchado usando `=`caracteres. La longitud de `base64`Las cuerdas codificadas tienen que estar en un múltiplo de 4. Si la salida resultante es de sólo 3 caracteres de largo, por ejemplo, un extra `=`se añade como relleno, y así es.

#### Base64 Encode

Para codar cualquier texto en `base64`en Linux, podemos hacernos eco de él y entubarlo con '`|`a `base64`:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo https://www.hackthebox.eu/ | base64

aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K
```

#### Base64 Decode

Si queremos decodificar a alguno `base64`cuerda codificado, podemos usar `base64 -d`, según se indica:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d

https://www.hackthebox.eu/
```


![Pasted image 20240824165120.png](/img/user/imgs/Pasted%20image%2020240824165120.png)

---

## Hex

Otro método de codificación común es `hex`codificación, que codifica cada personaje en su `hex`orden en el `ASCII`mesa. Por ejemplo, `a`es `61`en hex, `b`es `62`, `c`es `63`, y así es así. Puedes encontrar el lleno. `ASCII`mesa en Linux utilizando el `man ascii`comando.

#### Spotting Hex

Cualquier cuerda codificada en `hex`estaría compuesto sólo por personajes hex, que son 16 caracteres solamente: 0-9 y a-f. Eso hace que manchar. `hex`cuerdas codificadas tan fáciles como el manchado `base64`cuerdas codificadas.

#### Hex Encode

Para codar cualquier cuerda en `hex`en Linux, podemos usar el `xxd -p`orden:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo https://www.hackthebox.eu/ | xxd -p

68747470733a2f2f7777772e6861636b746865626f782e65752f0a
```

#### Hex Decode

Descodificar un `hex`cuerda codificado, podemos usar el `xxd -p -r`orden:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r

https://www.hackthebox.eu/
```

---

## César/Rot13

Otra técnica común -y muy antigua- de codificación es un cifrado César, que cambia cada letra por un número fijo. Por ejemplo, cambiar por 1 personaje hace `a`se convierten `b`, y `b`se convierte `c`, y así es así. Muchas variaciones del cifrado César utilizan un número diferente de turnos, el más común de los cuales es `rot13`, que cambia cada personaje 13 veces adelante.

#### Spotting Caesar/Rot13

Aunque este método de codificación hace que cualquier texto se vea aleatorio, todavía es posible detectarlo porque cada personaje está mapeado a un personaje específico. Por ejemplo, en `rot13`, `http://www`se convierte `uggc://jjj`, que todavía guarda algunos semezcos y puede ser reconocido como tal.

#### Rot13 Encode

No hay un comando específico en Linux que hacer `rot13`Codificación. Sin embargo, es bastante fácil crear nuestro propio comando para hacer el cambio de carácter:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

uggcf://jjj.unpxgurobk.rh/
```

#### Rot13 Decodificado

Podemos utilizar el mismo comando anterior para decodificar rot.13 también:

Decodificación

```shell-session
zunderrubb@htb[/htb]$ echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

https://www.hackthebox.eu/
```

Otra opción para codar/decodificar rot.13 sería el uso de una herramienta en línea, como [rot.13](https://rot13.com/).

---

## Otros tipos de codificación

Hay cientos de otros métodos de codificación que podemos encontrar en línea. Aunque estos son los más comunes, a veces nos encontraremos con otros métodos de codificación, que pueden requerir cierta experiencia para identificar y decodificar.

`If you face any similar types of encoding, first try to determine the type of encoding, and then look for online tools to decode it.`

Algunas herramientas pueden ayudarnos a determinar automáticamente el tipo de codificación, como [el identificador de cifrado](https://www.boxentriq.com/code-breaking/cipher-identifier). Pruebe las cuerdas codificados de arriba con [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier), para ver si puede identificar correctamente el método de codificación.

Aparte de la codificación, muchas herramientas de ofuscación utilizan el cifrado, que está codificando una cadena usando una clave, lo que puede hacer que el código ofuscado sea muy difícil de ingeniería inversa y deobfuscar, especialmente si la clave de descifrado no se almacena dentro del propio script