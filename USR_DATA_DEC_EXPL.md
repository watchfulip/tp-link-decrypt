In the firmware signatures, you may find a `squashfs-root` or similar directory that contains system executables. 
One interesting one is `/etc/uc_convert`, which accesses the `/etc/usr_conf_data` file. 
Upon examination, it was discovered that it generates a DES key to decrypt this file so that the device can use the data it contains for user authentication and other operations.
If we look at the logic of interaction between the client and the camera, we can see that when granting access to the video stream, the user undergoes Digest authentication.
Digest authentication has several types, each of which depends on the `qop` parameter passed by the server and the mode of *MD5* hashing algorithm.
The general form of response generation looks like `respone=MD5(HA1:middle:HA2)`.
As you can see, the response is formed of three parts, each of which is generated according to the following logic:
- HA1:
    - If the algorithm mode is not specified or is declared as MD5, then `HA1=MD5(username:realm:password)`
	- If the hashing algorithm mode is MD5-sess, then `HA1=(MD5(username:realm:password):nonce:cnonce)`
- HA2:
    - If the qop parameter is not specified or is equal to "auth", then `HA2=MD5(method:digestURI)`
    - If the qop parameter is "auth-int", then `HA2=MD5(method:digestURI:MD5(entityBody))`
- Middle:
    - If the qop parameter is "auth" or "auth-int", then `middle=nonce:nonceCount:clientNonce:qop`. Then the response will be produced as follows: 
`response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)`
    - If the qop parameter is not specified, then `middle=nonce`, so the response is generated using the `MD5(HA1:nonce:HA2)` formula.

In our case, the device transmits: 
    - realm = TP-LINK IP-Camera
    - algorithm = MD5
    - qop = auth
    - nonce = <some string>
The client sends:
    - response = <result of auth>
    - uri = /stream
    - realm = <same realm>
    - qop = auth
    - nonce = <some string>
    - cnonce = <some string>
    - nc = <some string>

So the response output will be calculated as `response = MD5(MD5(username:realm:password):nonce:nonceCount:cnonce:qop:MD5(method:digestURI))`.
All parameters except password are passed in plaintext. It is in the file usr_conf_data that password is stored, which is necessary for Digest Auth.

The logic of `uc_convert` looks like this (taken from `Tapo_C200v1_en_1.0.10_Build_200520_Rel.45325n_1594713621606.bin firmware`):

    - `/bin/uc_convert` reads encrypted user config from flash address 0x40000 - 0x50000, which is the same as partition "config".

    - Decryption key is read from flash address 0x600c0, with length 0xc (12 bytes). The content is "C200 1.0" with some trailing null bytes.

    - "C200 1.0" then goes through a hash function, generating hash value : "5982a0a3".

    - Decryption function calls "des_min_do()", which indicates user config is encrypted using DES. DES has key length of 64 bit (8 bytes), so we will have to convert "5982a0a3" into hex value - "3539383261306133".

The logic of the `gen_keys_for_usr_conf_data` is to try to find the `usr_conf_data` file in the signatures. 
If the program manages to find this file, it proceeds to the DES-key generation stage, using a substring in the name of the directory that contains the signatures (for example, for the directory `_Tapo_C200v4_en_1.3.7_Build_230627_Rel.41997n_up_boot-signed_1691143640985.bin.dec.extracted`, the substring `C200v4` is taken and translated into the form `C200 4.0`) and the results are written to a text file.
If no substring in the directory name is found, the program will ask you to enter the string for DES manually. 
Next, the script takes the data from the file, decrypts the file and extracts the found signature using binwalk. 
After that, you can view the data it contains.

*It was tested on firmware for the C200 model with hardware versions 1-4. More tests are needed*
