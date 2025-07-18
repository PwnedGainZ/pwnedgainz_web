---
{"dg-publish":true,"permalink":"/programacion-web/obfuscacion/obfuscacion-de-codigo-basica/"}
---


--------------------

-----------------

# Obfuscación básica

---

La ofuscación en código generalmente no se hace manualmente, ya que hay muchas herramientas para varios idiomas que hacen la ofuscación automatizada de código. Muchas herramientas en línea se pueden encontrar para hacerlo, aunque muchos actores maliciosos y desarrolladores profesionales desarrollan sus propias herramientas de ofuscación para hacer más difícil desobfuscar.

---

## Ejecutado código JavaScript

Tomemos como ejemplo la siguiente línea de código e intentemos ofuscarlo:

Código: javascript

```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

Primero, probemos ejecutar este código en texto claro, para verlo funcionar en acción. Podemos ir a[JSConsole](https://jsconsole.com), pegar el código y golpear entrar, y ver su salida:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_jsconsole_1_1.jpg)

Vemos que esta línea de impresión de código `HTB JavaScript Deobfuscation Module`, que se hace utilizando la `console.log()`función.

---

## Minificando el código JavaScript

Una forma común de reducir la legibilidad de un fragmento de código JavaScript mientras lo mantiene completamente funcional es la minificación de JavaScript. `Code minification`significa tener todo el código en una sola línea (a menudo muy larga). `Code minification`es más útil para el código más largo, ya que si nuestro código sólo consinaba en una sola línea, no se vería muy diferente cuando se minifica.

Muchas herramientas pueden ayudarnos a minificar el código JavaScript, como [javascript-minifier](https://javascript-minifier.com/). Simplemente copiamos nuestro código, y hacemos clic `Minify`, y obtenemos la salida minificada a la derecha:

![](https://academy.hackthebox.com/storage/modules/41/js_minify_1.jpg)

Una vez más, podemos copiar el código minificado a [JSConsole](https://jsconsole.com), y ejecutarlo, y vemos que funciona como se esperaba. Por lo general, el código de JavaScript minificado se guarda con la extensión `.min.js`.

Nota: La minificación del código no es exclusiva de JavaScript, y se puede aplicar a muchos otros idiomas, como se puede ver en [javascript-mínificador](https://javascript-minifier.com/).

---

## Embalaje código JavaScript

Ahora, dejemos desactivar nuestra línea de código para que sea más oscuro y difícil de leer. Primero, intentaremos [que BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) ofusque nuestro código:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_obfuscator.jpg)

Código: javascript

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

Vemos que nuestro código se volvió mucho más ofuscado y difícil de leer. Podemos copiar este código en [https://jsconsole.com](https://jsconsole.com), para verificar que todavía hace su función principal:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_jsconsole_3_1.jpg)

Vemos que conseremos la misma salida.

Nota: El tipo anterior de ofuscación se conoce como "empaquetado", que suele ser reconocible a partir de los seis argumentos de función utilizados en la función inicial "function(p,a,c,k,e,d) ".

A `packer`herramienta de ofuscación generalmente intenta convertir todas las palabras y símbolos del código en una lista o un diccionario y luego se refiere a ellos usando el `(p,a,c,k,e,d)`función para reconstruir el código original durante la ejecución. El `(p,a,c,k,e,d)`puede ser diferente de una empaqueta a otra. Sin embargo, por lo general contiene un cierto orden en el que las palabras y los símbolos del código original fueron empaquetado para saber cómo ordenarlos durante la ejecución.

Mientras que un empaquetar hace un gran trabajo reduciendo la legibilidad del código, todavía podemos ver sus principales cadenas escritas en texto claro, que puede revelar algo de su funcionalidad. Por eso es posible que queramos buscar mejores maneras de ofuscar nuestro código.