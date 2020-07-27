libsnark merkle circuit example

The example shows how to generate proof for one merkle path on one merkle tree with depth 3.

1/ init 
 ```
 git submodule update --init --recursive
 ```
2/ compile
 ```
 mkdir build; cd build; cmake ..; make
 ```
 You can find the "merkle" binary under the merkle folder.

3/ setup
```
./merkle setup
```

4/ prove
```
./merkle prove [data1] [data2] [data3] [data4] [data5] [data6] [data7] [data8] [index]
```
Record down the root information, which is used on verify.

5/ verify
```
./merkle [root]
```
