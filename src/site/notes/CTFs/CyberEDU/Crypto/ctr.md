---
{"dg-publish":true,"permalink":"/ct-fs/cyber-edu/crypto/ctr/","dgPassFrontmatter":true}
---

![Pasted image 20250718020014.png](/img/user/Pasted%20image%2020250718020014.png)

El ejercicio nos da lo siguiente el siguiente texto crt.txt:

``` c
f24e8c4bb594b2590edc658609608f16
efef303f8c14cbcfa6709e080f07adca
900ff15e9d2dce91713e75b37407d7bb
e535e1e2fd66dc05ccf916a76c6ebb2d
2b44cf03027b86ccd1014a06018a282b
f95bf57fca9123b0cbded807a6e7d0f1
137ea638993cac62e12f4d17b30409bf
285fdb0309759ad9ef1d460824853036
e22723808b814a7ae986bf180274bb89
22d3d6161739dbcd665d3132be0b6a52
070e642508c0d983b635d0033a4f528c
dfbc1c2625738c6622d98f505c6ee50d
191279301cf3dfb4bb22eb0b20586faf
9f9ebabb333403f6f571511aca57d94e
0ccb77d32a36dc1f30701fcbe021c126
1d10c078b60a7dae3b11329ee8c3a803
e6313f8f8f874e70dcadae000165ac8c
edd1a4a02ee9eea96d298860334b29bd
d8ba13da058f95d5ce0a8f81ed8af4bb
0409da74bc0758a92a212e8bcdccaa0f
cdb909db058e87f4e613939aea82d3a7
5979e82195fc2aec434cadcf5f0dfb18
1315df6ea91544ab0f183794d7ccab0a
e52a24919a9a4573dfb6b51e1478a78f
1578b7359e26ab64d1334111840313b0
f45514c91492814d890fcf90235b25ee
f55e0ac1038e80599907ce9b3d5332f2
ccad0b38307c96440ec3885d467bdd10
fa5df47dce8b3e95ebcfdd16a9e7fff7
051e703e1cefd3bdb522f70729566fb3
4d60ed3787d72ae640669ac74902ee36
8d82abb22e0909dcf562750ccf41f163
c3bb12cc029297cecf0b9986f088efba
09167f2a11d0f0a6ba35c517194d639b
0918732210c5f0a8b63dc40219436f93
1d0cdb74b41c44b40101338ecac5ab15
fd550ad20a979440950decb82a4030ff
3fc4d70d1c38d6fa63762e36a215574a
cc907b6807597f0171c9b8db6ebb7d52
0fd77fd82537d52b0f610fdffc39f42e
5b7ce0259be22aec434ea8c75b03e518
edd5a7a437feefb87b159d42224d2bbe
3241c4040b379cd1f5134406038c152f
5e68e7279ffc2af84d71bafa4c08e310
debc12c0008d93f3c8119bbcea99cfb8
e5401ac5128ea05b9e06ea811a4220e3
09d26ac02f14d00f026c20d0fd34c814
dfbc08352774974538ed94475379da0b
08d377cc302bda1a0f571ed0e426cd21
e551f67bce8013bafecdce169efac9e2
0b10d87aa32958a92a0d048ecacda73c
05d26ed13a18d00b13792cd0f925dd18
235ed8040d63aad7ee1a4b162f843331
8693b2a72c2402eff8794d05da56c043
0712662d17c0d5b2bc1fd4023a5e7f9a
2452de1e0f6e81dbde175b1b0c9f2f3c
f5561ec5018c90589f06e5810a5424e3
e23337968b976e78fcb7a209257da89c
8083b8be282414e9e8735401da40c653
4f71fc3f8af92de56167a8c2590ff916
e12d338c949a4e70dbb1a2031a78ac8c
363bcf22a91ff317f4bc8c6c9f513256
8292bfb3250619c8f4697a1cdb40fa6c
ceb91b312268947727de98574776f408
d4947b6807417b0171c9a0df6ebb7d4a
2958ca02436998d1e91d5c0a09a32f38
f84908c517b28c5b9907c38c3f5726ce
c0ba1fc61992b8e8d810899bc982dfbb
2acf3469113253e3b899cd5aeb174dfd
```

Esto lo podemos interpretar como bloques cifrados en hexadecimal, probablemente parte de un mensaje cifrado con AES en modo bloque. Algunas cosas que podemos inferir con bastante certeza.

Cada linea es un bloque de 32 caracteres hexadecimales, lo que equivale a:
- 32 caracteres hexadecimales = 16 bytes
- Y 16 bytes = 128 bits
Esto es exactamente el size de bloque de AES. Entonces, estos datos muy probablemente provienen de un cifrado AES-128, en algun modo de operacion por bloques, como:

- ECB (Electronic Code Book)
- CBD (Cipher Block Chaining)
- CTR (Counter Mode)
- OFB o CFB

## Que es AES-CTR?

``` python
AES-CTR convierte el cifrado en bloque en un cifrado de flujo:

keystream_i = AES(Nonce || Counter_i)
ciphertext_i = plaintext_i XOR keystream_i

Entonces, para poder descifrar:

plaintext_i = ciphertext_i XOR keystream_i
```

Como el cifrado se hace por bloques, cada bloque tiene un keystream unico (derivado del contador).

Cada linea del ctr.txt tiene:
- 
