CryptPE -- An encryption tool for PE binaries

How to use
----------

Just running "Build solution" will first create an example executable
(testbin.exe) and encrypt it. This is probably not what you want.

To encrypt a binary of your choice:
- Build mkbintable.exe
- Run mkbintable on the desired binary to compress and encrypt it
- Store the output in cryptpe\bintable.h
- Build cryptpe.exe - This is the final encrypted executable

License
-------

The majority of CryptPE is licensed unter the WTFPL (see license.txt).
Loader.c is a modified version of MemoryModule.c, part of MemoryModule,
written by Joachim Bauch. It is licensed unter the MPL.