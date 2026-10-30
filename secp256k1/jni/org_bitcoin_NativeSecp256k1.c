/*
 * JNI bindings for org.bitcoin.NativeSecp256k1 and org.bitcoin.Secp256k1Context
 * on top of an unmodified upstream libsecp256k1 (see ../README.md for the
 * vendored version).
 *
 * This file is compiled as ONE translation unit together with the library:
 * it includes src/secp256k1.c directly, exactly as upstream's own tests and
 * benchmarks do. That gives the shim the same internal (static) functions the
 * library uses, which is what the fork-only "is the recovered point the point
 * at infinity?" query needs: upstream's secp256k1_ecdsa_recover reports
 * infinity and every other failure as the same 0, and rskj distinguishes
 * them (Secp256k1ServiceNative returns the zero key for infinity and null
 * for everything else), so the distinction must be computed here with the
 * library's own scalar/group code.
 *
 * Every other entry point is a port of the previous shim onto the current
 * public API; the Java-visible contract (buffer layouts, return arrays and
 * status codes) is unchanged. Renames since the old fork:
 *   secp256k1_ec_privkey_{negate,tweak_add,tweak_mul}
 *     -> secp256k1_ec_seckey_{negate,tweak_add,tweak_mul}   (same semantics)
 *   secp256k1_context_create(SIGN | VERIFY)
 *     -> secp256k1_context_create(SECP256K1_CONTEXT_NONE)   (flags are no-ops now)
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../src/secp256k1.c"

#include "org_bitcoin_NativeSecp256k1.h"
#include "org_bitcoin_Secp256k1Context.h"

/* ---- context ---------------------------------------------------------- */

JNIEXPORT jlong JNICALL Java_org_bitcoin_Secp256k1Context_secp256k1_1init_1context
  (JNIEnv* env, jclass classObject)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  (void)classObject;(void)env;
  return (jlong)(uintptr_t)ctx;
}

JNIEXPORT jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ctx_1clone
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  const secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  jlong ctx_clone_l = (jlong)(uintptr_t) secp256k1_context_clone(ctx);
  (void)classObject;(void)env;
  return ctx_clone_l;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1context_1randomize
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* seed = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  (void)classObject;
  return secp256k1_context_randomize(ctx, seed);
}

JNIEXPORT void JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1destroy_1context
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  secp256k1_context_destroy(ctx);
  (void)classObject;(void)env;
}

/* ---- helpers ---------------------------------------------------------- */

/* Build the byte[][] {payload, status} every non-trivial method returns. */
static jobjectArray make_result(JNIEnv* env, const unsigned char* payload, size_t payloadLen,
                                const unsigned char* status, size_t statusLen)
{
  jobjectArray retArray;
  jbyteArray payloadArray, statusArray;

  retArray = (*env)->NewObjectArray(env, 2, (*env)->FindClass(env, "[B"), (*env)->NewByteArray(env, 1));

  payloadArray = (*env)->NewByteArray(env, (jsize)payloadLen);
  (*env)->SetByteArrayRegion(env, payloadArray, 0, (jsize)payloadLen, (const jbyte*)payload);
  (*env)->SetObjectArrayElement(env, retArray, 0, payloadArray);

  statusArray = (*env)->NewByteArray(env, (jsize)statusLen);
  (*env)->SetByteArrayRegion(env, statusArray, 0, (jsize)statusLen, (const jbyte*)status);
  (*env)->SetObjectArrayElement(env, retArray, 1, statusArray);

  return retArray;
}

/* ---- ECDSA ------------------------------------------------------------ */

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint siglen, jint publen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* sigdata = data + 32;
  const unsigned char* pubdata = data + siglen + 32;

  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pubkey;
  int ret;

  if (siglen == 64) {
    ret = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sigdata);
  } else {
    ret = secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigdata, (size_t)siglen);
  }
  if (ret) {
    ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pubdata, (size_t)publen);
    if (ret) {
      ret = secp256k1_ecdsa_verify(ctx, &sig, data, &pubkey);
    }
  }
  (void)classObject;
  return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* secKey = data + 32;
  secp256k1_ecdsa_signature sig;
  unsigned char outputSer[72];
  size_t outputLen = 72;
  unsigned char intsarray[2];

  int ret = secp256k1_ecdsa_sign(ctx, &sig, data, secKey, NULL, NULL);
  if (ret) {
    int ret2 = secp256k1_ecdsa_signature_serialize_der(ctx, outputSer, &outputLen, &sig); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign_1compact
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* secKey = data + 32;
  secp256k1_ecdsa_signature sig;
  unsigned char outputSer[64];
  size_t outputLen = 64;
  unsigned char intsarray[2];

  int ret = secp256k1_ecdsa_sign(ctx, &sig, data, secKey, NULL, NULL);
  if (ret) {
    int ret2 = secp256k1_ecdsa_signature_serialize_compact(ctx, outputSer, &sig); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

/* ---- keys ------------------------------------------------------------- */

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  (void)classObject;
  return secp256k1_ec_seckey_verify(ctx, secKey);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint compressed)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  secp256k1_pubkey pubkey;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, secKey);
  if (ret) {
    int ret2 = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pubkey,
                 compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1parse
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint inputlen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* pubkeydata = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  secp256k1_pubkey pubkey;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeydata, (size_t)inputlen);
  if (ret) {
    int ret2 = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1negate
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  unsigned char intsarray[2];

  int ret = secp256k1_ec_seckey_negate(ctx, privkey);
  intsarray[0] = 32;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, privkey, 32, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1add
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = privkey + 32;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_seckey_tweak_add(ctx, privkey, tweak);
  intsarray[0] = 32;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, privkey, 32, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1mul
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = privkey + 32;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_seckey_tweak_mul(ctx, privkey, tweak);
  intsarray[0] = 32;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, privkey, 32, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1negate
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* pkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  unsigned char outputSer[65];
  size_t outputLen = (size_t)publen;
  unsigned char intsarray[2];
  secp256k1_pubkey pubkey;

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pkey, (size_t)publen);
  if (ret) {
    ret = secp256k1_ec_pubkey_negate(ctx, &pubkey);
  }
  if (ret) {
    int ret2 = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pubkey,
                 publen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1add
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* pkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = pkey + publen;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[2];
  secp256k1_pubkey pubkey;

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pkey, (size_t)publen);
  if (ret) {
    ret = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak);
  }
  if (ret) {
    int ret2 = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1mul
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  unsigned char* pkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = pkey + publen;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[2];
  secp256k1_pubkey pubkey;

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pkey, (size_t)publen);
  if (ret) {
    ret = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, tweak);
  }
  if (ret) {
    int ret2 = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED); (void)ret2;
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1add
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen1, jint publen2)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* pubdata1 = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* pubdata2 = pubdata1 + publen1;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[2];
  secp256k1_pubkey pubkey1, pubkey2, result;
  const secp256k1_pubkey *pubkeys[2];

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey1, pubdata1, (size_t)publen1);
  if (ret) {
    ret = secp256k1_ec_pubkey_parse(ctx, &pubkey2, pubdata2, (size_t)publen2);
  }
  if (ret) {
    pubkeys[0] = &pubkey1;
    pubkeys[1] = &pubkey2;
    ret = secp256k1_ec_pubkey_combine(ctx, &result, pubkeys, 2);
  }
  if (ret) {
    ret = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &result, SECP256K1_EC_UNCOMPRESSED);
  }
  intsarray[0] = (unsigned char)outputLen;
  intsarray[1] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 2);
}

/* ---- ECDH ------------------------------------------------------------- */

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdh
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* secdata = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* pubdata = secdata + 32;
  unsigned char intsarray[1];
  secp256k1_pubkey pubkey;
  unsigned char nonce_res[32];

  int ret = secp256k1_ec_pubkey_parse(ctx, &pubkey, pubdata, (size_t)publen);
  if (ret) {
    ret = secp256k1_ecdh(ctx, nonce_res, &pubkey, secdata, NULL, NULL);
  }
  intsarray[0] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, nonce_res, 32, intsarray, 1);
}

/* ---- recovery --------------------------------------------------------- */

/* Buffer layout: 64 bytes compact signature (r || s), then the 32-byte message. */
JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1recover
  (JNIEnv *env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint recid, jint compressed)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* sigdata = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* msgdata = sigdata + 64;
  secp256k1_ecdsa_recoverable_signature sig;
  secp256k1_pubkey pub;
  unsigned char outputSer[65];
  size_t outputLen = 65;
  unsigned char intsarray[1];

  int ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sigdata, recid);
  if (ret) {
    ret = secp256k1_ecdsa_recover(ctx, &pub, &sig, msgdata);
    if (ret) {
      ret = secp256k1_ec_pubkey_serialize(ctx, outputSer, &outputLen, &pub,
              compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    }
  }
  intsarray[0] = (unsigned char)ret;
  (void)classObject;
  return make_result(env, outputSer, outputLen, intsarray, 1);
}

/*
 * Fork-only query, kept byte-for-byte compatible with the status codes the
 * Java side maps to exceptions:
 *   -1  signature could not be parsed (r or s overflow, bad recid)
 *   -2  r == 0
 *   -3  s == 0
 *   -4  recid has bit 2 set but r + n does not fit in the field
 *   -5  r is not the x coordinate of a curve point
 *    1  the recovered point is the point at infinity
 *    0  a regular point was recovered
 *
 * The body mirrors upstream's static secp256k1_ecdsa_sig_recover (which this
 * translation unit has just compiled) step by step, differing only in what it
 * returns at each exit.
 */
JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1is_1infinity
  (JNIEnv *env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint recid_in)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;
  const unsigned char* sigdata = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* msgdata = sigdata + 64;
  secp256k1_ecdsa_recoverable_signature sig;
  secp256k1_scalar sigr, sigs, m, rn, u1, u2;
  unsigned char brx[32];
  secp256k1_fe fx;
  secp256k1_ge x;
  secp256k1_gej xj, qj;
  int recid;
  int ok;

  (void)classObject;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sigdata, recid_in)) {
    return -1;
  }
  secp256k1_ecdsa_recoverable_signature_load(ctx, &sigr, &sigs, &recid, &sig);
  secp256k1_scalar_set_b32(&m, msgdata, NULL);

  if (secp256k1_scalar_is_zero(&sigr)) {
    return -2;
  }
  if (secp256k1_scalar_is_zero(&sigs)) {
    return -3;
  }
  secp256k1_scalar_get_b32(brx, &sigr);
  ok = secp256k1_fe_set_b32_limit(&fx, brx);
  (void)ok; /* brx comes from a scalar, so it is below the order and certainly below p */
  if (recid & 2) {
    if (secp256k1_fe_cmp_var(&fx, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
      return -4;
    }
    secp256k1_fe_add(&fx, &secp256k1_ecdsa_const_order_as_fe);
  }
  if (!secp256k1_ge_set_xo_var(&x, &fx, recid & 1)) {
    return -5;
  }
  secp256k1_gej_set_ge(&xj, &x);
  secp256k1_scalar_inverse_var(&rn, &sigr);
  secp256k1_scalar_mul(&u1, &rn, &m);
  secp256k1_scalar_negate(&u1, &u1);
  secp256k1_scalar_mul(&u2, &rn, &sigs);
  secp256k1_ecmult(&qj, &xj, &u2, &u1);
  return secp256k1_gej_is_infinity(&qj) ? 1 : 0;
}
