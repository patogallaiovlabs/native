Validation helpers for the JNI shim. Both compile against an rskj fat jar
(they live in rskj / native packages to reach package-private classes) and
pick up whichever `org/bitcoin/native/<OS>/<arch>/libsecp256k1.*` comes first
on the classpath, so put a directory with the new binaries before the jar:

    javac -cp rskj.jar -d out Bench.java Conform.java
    java  -cp out:rskj.jar org.bitcoin.Conform > old.txt            # library inside the jar
    java  -cp ../../../src/main/resources:out:rskj.jar org.bitcoin.Conform > new.txt
    diff old.txt new.txt                                             # must be empty
    java  -cp ../../../src/main/resources:out:rskj.jar org.ethereum.crypto.signature.Bench
