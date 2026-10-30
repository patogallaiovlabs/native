package org.ethereum.crypto.signature;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.Secp256k1Context;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.ethereum.vm.PrecompiledContracts;
import org.bouncycastle.util.encoders.Hex;
import java.util.function.Supplier;

public class Bench {
    static byte[] h = Hex.decode("456e746572207465787420686572650000000000000000000000000000000000");
    static byte[] r = Hex.decode("51ed1b4efd72bb712e3512bee2b49aefb3320f56a572ce6eae8427c2f8926a14");
    static byte[] sig64 = new byte[64];
    static byte[] input = new byte[128];
    static void bench(String name, Supplier<Object> f) {
        for (int i = 0; i < 20000; i++) f.get();
        int n = 50000; long t0 = System.nanoTime();
        Object sink = null;
        for (int i = 0; i < n; i++) sink = f.get();
        long dt = System.nanoTime() - t0;
        System.out.printf("%-48s %8.2f us/op  (%s)%n", name, dt / 1e3 / n, sink == null ? "null" : "ok");
    }
    public static void main(String[] a) throws Exception {
        System.arraycopy(r, 0, sig64, 0, 32); System.arraycopy(r, 0, sig64, 32, 32);
        System.arraycopy(h, 0, input, 0, 32); input[63] = 27; System.arraycopy(r, 0, input, 64, 32); System.arraycopy(r, 0, input, 96, 32);
        System.out.println("native context enabled: " + Secp256k1Context.isEnabled());
        Secp256k1Service nat = new Secp256k1ServiceNative();
        Secp256k1Service bc = new Secp256k1ServiceBC();
        ECDSASignature sig = ECDSASignature.fromComponents(r, r, (byte) 27);
        bench("JNI NativeSecp256k1.ecdsaRecover (raw C + JNI)", () -> { try { return NativeSecp256k1.ecdsaRecover(sig64, h, 0, false); } catch (Exception e) { throw new RuntimeException(e); } });
        bench("Secp256k1ServiceNative.signatureToKey", () -> { try { return nat.signatureToKey(h, sig); } catch (Exception e) { throw new RuntimeException(e); } });
        bench("  + ECKey.getAddress (decode+encode+keccak)", () -> { try { return nat.signatureToKey(h, sig).getAddress(); } catch (Exception e) { throw new RuntimeException(e); } });
        byte[] pub = NativeSecp256k1.ecdsaRecover(sig64, h, 0, false);
        bench("ECKey.fromPublicOnly(byte[]) alone (BC decodePoint)", () -> ECKey.fromPublicOnly(pub));
        bench("ECKey.fromPublicOnly + getAddress", () -> ECKey.fromPublicOnly(pub).getAddress());
        bench("keccak256 of 64 bytes", () -> HashUtil.keccak256(java.util.Arrays.copyOfRange(pub, 1, 65)));
        // whole precompile with native service as the singleton
        java.lang.reflect.Field f = Secp256k1.class.getDeclaredField("instance"); f.setAccessible(true); f.set(null, nat);
        PrecompiledContracts.ECRecover ec = new PrecompiledContracts.ECRecover();
        bench("PrecompiledContracts.ECRecover.execute (native)", () -> { try { return ec.execute(input); } catch (Exception e) { throw new RuntimeException(e); } });
        f.set(null, bc);
        bench("Secp256k1ServiceBC.signatureToKey (Bouncy Castle)", () -> { try { return bc.signatureToKey(h, sig); } catch (Exception e) { throw new RuntimeException(e); } });
        bench("PrecompiledContracts.ECRecover.execute (BC)", () -> { try { return ec.execute(input); } catch (Exception e) { throw new RuntimeException(e); } });
    }
}
