---
{"dg-publish":true,"permalink":"/programacion-web/obfuscacion/desofuscacion/","dgPassFrontmatter":true}
---


---

Ahora que entendemos cómo funciona la ofuscación de código, empecemos nuestro aprendizaje hacia la desobfuscación. Así como hay herramientas para ofuscar código automáticamente, hay herramientas para embellecer y desobfuscar el código automáticamente.

---

## embellecer

Vemos que el código actual que tenemos está escrito en una sola línea. Esto se conoce como `Minified JavaScript`código. Para formatear correctamente el código, tenemos que `Beautify`nuestro código. El método más básico para hacerlo es a través de nuestro `Browser Dev Tools`.

Por ejemplo, si estábamos usando Firefox, podemos abrir el depurador del navegador con [ `CTRL+SHIFT+Z`], y luego haga clic en nuestro script `secret.js`. Esto mostrará el guión en su formato original, pero podemos hacer clic en el '`{ }`botón en la parte inferior, que `Pretty Print`el script en su formato de JavaScript adecuado: ![](https://academy.hackthebox.com/storage/modules/41/js_deobf_pretty_print.jpg)

Además, podemos utilizar muchas herramientas en línea o plugins de editor de código, como [Prettier](https://prettier.io/playground/) o [Beautifier](https://beautifier.io/). Vamos a copiar el `secret.js`Escrido:

Código: javascript

```javascript
eval(function (p, a, c, k, e, d) { e = function (c) { return c.toString(36) }; if (!''.replace(/^/, String)) { while (c--) { d[c.toString(a)] = k[c] || c.toString(a) } k = [function (e) { return d[e] }]; e = function () { return '\\w+' }; c = 1 }; while (c--) { if (k[c]) { p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c]) } } return p }('g 4(){0 5="6{7!}";0 1=8 a();0 2="/9.c";1.d("e",2,f);1.b(3)}', 17, 17, 'var|xhr|url|null|generateSerial|flag|HTB|flag|new|serial|XMLHttpRequest|send|php|open|POST|true|function'.split('|'), 0, {}))
```

Podemos ver que ambos sitios web hacen un buen trabajo en el formato del código:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_prettier_1.jpg)

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_beautifier_1.jpg)

Sin embargo, el código todavía no es muy fácil de leer. Esto se debe a que el código que estamos tratando no sólo fue minificado sino también ofuscado. Por lo tanto, simplemente formatear o embellecer el código no será suficiente. Para ello, necesitaremos herramientas para desobfuscar el código.

---

## Deobfusca

Podemos encontrar muchas buenas herramientas en línea para desobfuscar el código JavaScript y convertirlo en algo que podamos entender. Una buena herramienta es [UnPacker](https://matthewfl.com/unPacker.html). Vamos a intentar copiar nuestro código above-obfuscado y ejecutarlo en UnPacker haciendo clic en el `UnPack`botón.

Sugerido: Asegúrese de no dejar ninguna línea vacía antes del script, ya que puede afectar el proceso de desobsección y dar resultados inexactos.

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_unpacker_1.jpg)

Podemos ver que esta herramienta hace un trabajo mucho mejor en desobfuscar el código JavaScript y nos dio una salida que podemos entender:

Código: javascript

```javascript
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```

Como se mencionó anteriormente, el método de ofuscación antes utilizado es `packing`. Otra forma de `unpacking`dicho código es para encontrar la `return`valor al final y uso `console.log`imprimirlo en vez de ejecutarlo.

---

## Ingeniería inversa

Aunque estas herramientas están haciendo un buen trabajo hasta ahora en la limpieza del código en algo que podemos entender, una vez que el código se vuelve más ofuscado y codificado, se volvería mucho más difícil para las herramientas automatizadas limpiarlo. Esto es especialmente cierto si el código fue ofuscado usando una herramienta de ofuscación personalizada.

Tendríamos que ingeniar manualmente el código para entender cómo fue ofuscado y su funcionalidad para tales casos. Si está interesado en saber más sobre la desoblación e ingeniería inversa avanzada de JavaScript, puede consultar el módulo [Secure Coding 101](https://academy.hackthebox.com/module/details/38), que debe cubrir a fondo este tema.

![Pasted image 20240824162752.png](/img/user/imgs/Pasted%20image%2020240824162752.png)