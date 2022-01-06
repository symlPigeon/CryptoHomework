### PA1 option

Write a program that allows you to crack ciphertexts generated using a Vigenere-like cipher, where byte-wise XOR is used instead of addition modulo 26.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f|  ==> cipher
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              xor
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|w|x|y|z|w|x|y|z|w|x|y|z|w|x|y|z|  ==> 4 bytes key, repeat for 4 times
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 | divide
			 v
|0| xor |w|, |4| xor |w|, ...
|1| xor |x|, |5| xor |x|, ...
......
```

