# pgp
PGP - rfc 4880 api

## Parameters used to encrypt and decrypt secret keys

    #{ password => "Hello" }

Set encryption password, this is the only required parameter for encryption.

    #{ cipher => Cihper }

Cipher is one of des3 | blowfish | aes\_128 | aes\_192 | aes\_256 (default is des3)

Set password to key transformation

    #{ s2k => S2K }

S2K is either {simple, Hash} | {salted,Hash,Salt} | {salted,Hash,Salt,Count}
Where Hash is one of the hash algorithms md5, sha, ripemd160, sha256, sha384, sah512, sha224, ( default is {simple, md5} )

Checksum data 

    #{ checksum => Check }

where Check is one of none | checksum | hash, default (hash)
When specified checksum is the 16-bit internet checksum (sum bytes mod 65536)
and hash is the 20 bytes sha-1 hash.
