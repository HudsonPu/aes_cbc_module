# aes_cbc_moduleIntro

## Intro
This is the repository for the AES CBC kernel module based on tiny-AES-c lib.
In contains the implementation of off-tree kernel module, AES lib as a submodule, and some test cases.
Currently only AES128 mode are supported, and the init vector default set to all zero.
The AES working with 16 byte block, if the data send to encryption cannot meet the 16 byte alignment, 0 will be added in the tail.

## Get the source code
You can fetch the source code from github via the following 2 ways.

1. ```git clone https://github.com/HudsonPu/aes_cbc_module.git --recursive```

2.
   ```
   git clone https://github.com/HudsonPu/aes_cbc_module.git

   cd aes_cbc_module/tiny-AES-c
   
   git submodule init

   git submodule update
   ```

## Compile the driver module
 ```  
   cd aes_cbc_module
   
   make
```

## Compile the test cases
```
   cd aes_cbc_module/function_test
   mkdir build
   cd build
   cmake ..
   make
```
## How to use the aes_cbc_module

Supported parameters when loading the kernel modue

encrypt:

    encrypt = 1  # working in encrypt mode

    encrypt = 0  # working in decrypt mode

    default set to 1, if no encrypt parameter when loading the module
    
key:    

    key = "..."   # Hex string of the key
    
    default to be 32 byte hex string, indicate as the 128bit AES key
    
    if the input is shorter than 32 byte, 0 will be added in the end,
    
    if the input is longer than 32 byte, only the first 32 byte will be accept.
    
    Default set to "000102030405060708090a0b0c0d0e0f" if no key parameter when loading the module
    
Examples: 
    
Loading the module and set it work in the encrypt mode
   
```    sudo insmod aes_cbc_module.ko encrypt=1 key="001122334466778899aabbccddeeff" ```
    
Loading the module and set it work in the decrypt mode
    
```    sudo insmod aes_cbc_module.ko encrypt=0 key="001122334466778899aabbccddeeff" ```


After loading the driver modules, the following 2 file node should be created

| Node | Description |
| --- | --- |
| /dev/vencrypt_pt  |  #plaintext node/ # working as input node in encrypt mode/ # working as output node in decrypt mode |
| /dev/vencrypt_ct  |  #ciphertext node/ # working as output node in encrypt mode/ # working as input node in decrypt mode |


Change file node priviledge
    The owner of the to file node is root, you can use it with root user diectly or change the ower to current use with the following commands.
    ```sudo chown "$USER" /dev/vencrypt_*```


## Function test cases

| Test Case | Description |
| --- | --- |
| encryption_test | Simple encryption test with the data defined in AES standard. Detailed test case info could be found in the comments of the test source code.|
| decryption_test | Simple decryption test with the data defined in AES standard. Detailed test case info could be found in the comments of the test source code.|
| encrypt_binary [in_filename] [out_filename] | encrypt the in_filename and store the result to out_filename|
| decrypt_binary [in_filename] [out_filename] | decrypt the in_filename and store the result to out_filename|

## Example for binary encryption and decryption
```
  cd aes_cbc_module/function_test

  sudo rmmod aes_cbc_module
  sudo insmod ../aes_cbc_module.ko encrypt=1
  sudo chown "$USER" /dev/vencrypt_*
  ./build/encrypt_binary input.bin crypt.bin

  sudo rmmod aes_cbc_module
  sudo insmod ../aes_cbc_module.ko encrypt=0
  sudo chown "$USER" /dev/vencrypt_*
  ./build/decrypt_binary crypt.bin result.bin

  diff -s result.bin input.bin
```
NOTE: If the input.bin is not aligned in 16 byte, some extra 0 will be observed in the tail of the result.bin.
