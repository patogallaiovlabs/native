package org.bitcoin;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import org.ethereum.crypto.ECKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
public class Conform {
  static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
  static byte[] b32(BigInteger v){ byte[] a=v.toByteArray(); byte[] o=new byte[32]; int n=Math.min(32,a.length); System.arraycopy(a,a.length-n,o,32-n,n); return o; }
  static String h(byte[] b){ return b==null?"null":Hex.toHexString(b); }
  static byte[] cat(byte[]... p){ int l=0; for(byte[] x:p) l+=x.length; byte[] o=new byte[l]; int i=0; for(byte[] x:p){System.arraycopy(x,0,o,i,x.length); i+=x.length;} return o; }
  static String rec(byte[] sig, byte[] msg, int recid, boolean comp){ try { return h(NativeSecp256k1.ecdsaRecover(sig,msg,recid,comp)); } catch(Exception e){ return "EXC:"+e.getMessage(); } }
  static String inf(byte[] sig, byte[] msg, int recid){ try { return ""+NativeSecp256k1.isInfinity(sig,msg,recid); } catch(Exception e){ return "EXC:"+e.getMessage(); } }
  public static void main(String[] a) throws Exception {
    System.out.println("enabled="+Secp256k1Context.isEnabled());
    Random rnd = new Random(42);
    // 1. real signatures: sign with native, verify, recover all recids, compare
    for (int i=0;i<200;i++) {
      byte[] priv=new byte[32]; rnd.nextBytes(priv); priv[0]&=0x3f; byte[] msg=new byte[32]; rnd.nextBytes(msg);
      if(!NativeSecp256k1.secKeyVerify(priv)) continue;
      byte[] pub = NativeSecp256k1.computePubkey(priv, false);
      byte[] sigDer = NativeSecp256k1.sign(msg, priv);
      byte[] sigC = NativeSecp256k1.signCompact(msg, priv);
      System.out.println("sign "+i+" "+h(sigDer)+" "+h(sigC)+" v="+NativeSecp256k1.verify(msg,sigDer,pub)+NativeSecp256k1.verify(msg,sigC,pub)+" pub="+h(pub)+" pubc="+h(NativeSecp256k1.computePubkey(priv,true)));
      for(int r=0;r<4;r++) System.out.println("  rec"+r+" "+rec(sigC,msg,r,false)+" "+rec(sigC,msg,r,true)+" inf="+inf(sigC,msg,r));
      byte[] tweak=new byte[32]; rnd.nextBytes(tweak); tweak[0]&=0x3f;
      System.out.println("  tweaks "+h(NativeSecp256k1.privKeyTweakAdd(priv.clone(),tweak))+" "+h(NativeSecp256k1.privKeyTweakMul(priv.clone(),tweak))+" "+h(NativeSecp256k1.privKeyNegate(priv.clone()))+" "+h(NativeSecp256k1.pubKeyTweakAdd(pub,tweak))+" "+h(NativeSecp256k1.pubKeyTweakMul(pub,tweak))+" "+h(NativeSecp256k1.pubKeyNegate(pub)));
      byte[] pub2 = NativeSecp256k1.computePubkey(tweak,false);
      System.out.println("  add "+h(NativeSecp256k1.pubKeyAdd(pub,pub2))+" parse="+h(NativeSecp256k1.parsePubkey(NativeSecp256k1.computePubkey(priv,true)))+" ecdh="+h(NativeSecp256k1.createECDHSecret(priv,pub2)));
    }
    // 2. garbage signatures
    for (int i=0;i<300;i++) { byte[] sig=new byte[64]; rnd.nextBytes(sig); byte[] msg=new byte[32]; rnd.nextBytes(msg); int r=rnd.nextInt(4);
      if(i%7==0) java.util.Arrays.fill(sig,0,32,(byte)0); if(i%11==0) java.util.Arrays.fill(sig,32,64,(byte)0); if(i%13==0) java.util.Arrays.fill(sig,0,32,(byte)0xff);
      System.out.println("junk "+i+" "+rec(sig,msg,r,false)+" inf="+inf(sig,msg,r)); }
    // 3. constructed infinity: R=kG, s random, z = s*k mod n  => Q = r^-1 (sR - zG) = infinity
    for (int i=0;i<50;i++) {
      BigInteger k = new BigInteger(255,rnd).mod(N); BigInteger s = new BigInteger(255,rnd).mod(N); if(k.signum()==0||s.signum()==0) continue;
      ECPoint R = ECKey.CURVE.getG().multiply(k).normalize();
      BigInteger r = R.getAffineXCoord().toBigInteger(); int recid = R.getAffineYCoord().toBigInteger().testBit(0)?1:0; if(r.compareTo(N)>=0) recid|=2;
      BigInteger z = s.multiply(k).mod(N);
      byte[] sig = cat(b32(r.mod(N)), b32(s)); byte[] msg=b32(z);
      System.out.println("infcase "+i+" "+rec(sig,msg,recid,false)+" inf="+inf(sig,msg,recid)+" other="+inf(sig,msg,recid^1));
    }
    // 4. the lab's dummy signature
    byte[] rr = Hex.decode("51ed1b4efd72bb712e3512bee2b49aefb3320f56a572ce6eae8427c2f8926a14"); byte[] hh=Hex.decode("456e746572207465787420686572650000000000000000000000000000000000");
    System.out.println("dummy "+rec(cat(rr,rr),hh,0,false)+" inf="+inf(cat(rr,rr),hh,0));
  }
}
