---
{"dg-publish":true,"permalink":"/programacion-web/obfuscacion/ofuscacion-avanzada/","dgPassFrontmatter":true}
---


-----------

-------------

# Obfuscación avanzada

---

Hasta ahora, hemos sido capaces de hacer que nuestro código se desconecte y más difícil de leer. Sin embargo, el código todavía contiene cadenas en texto claro, que puede revelar su funcionalidad original. En esta sección, probaremos un par de herramientas que deben ofuscar completamente el código y ocultar cualquier remanencia de su funcionalidad original.

---

## Obfuscator

Visitemos [https://obfuscator.io](https://obfuscator.io). Antes de hacer clic `obfuscate`, vamos a cambiar `String Array Encoding`a `Base64`, como se ve a continuación:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_obfuscator_2.jpg)

Ahora, podemos pegar nuestro código y hacer clic`obfuscate`:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_obfuscator_1.jpg)

Conseguimos el siguiente código:

Código: javascript

```javascript
var _0x1ec6=['Bg9N','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu='];(function(_0x13249d,_0x1ec6e5){var _0x14f83b=function(_0x3f720f){while(--_0x3f720f){_0x13249d['push'](_0x13249d['shift']());}};_0x14f83b(++_0x1ec6e5);}(_0x1ec6,0xb4));var _0x14f8=function(_0x13249d,_0x1ec6e5){_0x13249d=_0x13249d-0x0;var _0x14f83b=_0x1ec6[_0x13249d];if(_0x14f8['eOTqeL']===undefined){var _0x3f720f=function(_0x32fbfd){var _0x523045='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=',_0x4f8a49=String(_0x32fbfd)['replace'](/=+$/,'');var _0x1171d4='';for(var _0x44920a=0x0,_0x2a30c5,_0x443b2f,_0xcdf142=0x0;_0x443b2f=_0x4f8a49['charAt'](_0xcdf142++);~_0x443b2f&&(_0x2a30c5=_0x44920a%0x4?_0x2a30c5*0x40+_0x443b2f:_0x443b2f,_0x44920a++%0x4)?_0x1171d4+=String['fromCharCode'](0xff&_0x2a30c5>>(-0x2*_0x44920a&0x6)):0x0){_0x443b2f=_0x523045['indexOf'](_0x443b2f);}return _0x1171d4;};_0x14f8['oZlYBE']=function(_0x8f2071){var _0x49af5e=_0x3f720f(_0x8f2071);var _0x52e65f=[];for(var _0x1ed1cf=0x0,_0x79942e=_0x49af5e['length'];_0x1ed1cf<_0x79942e;_0x1ed1cf++){_0x52e65f+='%'+('00'+_0x49af5e['charCodeAt'](_0x1ed1cf)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x52e65f);},_0x14f8['qHtbNC']={},_0x14f8['eOTqeL']=!![];}var _0x20247c=_0x14f8['qHtbNC'][_0x13249d];return _0x20247c===undefined?(_0x14f83b=_0x14f8['oZlYBE'](_0x14f83b),_0x14f8['qHtbNC'][_0x13249d]=_0x14f83b):_0x14f83b=_0x20247c,_0x14f83b;};console[_0x14f8('0x0')](_0x14f8('0x1'));
```

Este código obviamente está más ofuscado, y no podemos ver ningún remanso de nuestro código original. Ahora podemos intentar ejecutarlo en [https://jsconsole.com](https://jsconsole.com) para verificar que todavía cumple con su función original. Trate de jugar con la configuración de ofuscación en [https://obfuscator.io](https://obfuscator.io) para generar aún más código ofuscado, y luego intenta volver a ejecutarlo en [https://jsconsole.com](https://jsconsole.com) para verificar que todavía realiza su función original.

---

## Más Obfuscación

Ahora deberíamos tener una idea clara de cómo funciona la ofuscación de código. Todavía hay muchas variaciones de las herramientas de ofuscación de código, cada una de las cuales ofusca el código de manera diferente. Tome el siguiente código de JavaScript, por ejemplo:

Código: javascript

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(!
...SNIP...
[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]](!+[]+!+[]+[+[]])))()
```

Todavía podemos ejecutar este código, y todavía llevaría a cabo su función original:

![](https://academy.hackthebox.com/storage/modules/41/js_deobf_jsf.jpg)

**Nota:** El código anterior se cortó como el código completo es demasiado largo, pero el código completo debe ejecutarse con éxito.

Podemos intentar ofuscar el código usando la misma herramienta en [JSF](http://www.jsfuck.com), y luego volver a ejecutarlo. Notaremos que el código puede tomar algún tiempo para ejecutar, lo que muestra cómo la ofuscación de código podría afectar el rendimiento, como se mencionó anteriormente.

Hay muchos otros ofusores de JavaScript, como [JJ Encode](https://utf-8.jp/public/jjencode.html) o [AA Encode](https://utf-8.jp/public/aaencode.html). Sin embargo, tales ofuscadores suelen hacer que la ejecución/compilación de código sea muy lenta, por lo que no se recomienda ser utilizado a menos que por una razón obvia, como eludir filtros web o restricciones.