/* Copyright 2019 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * pick random k
 * if B:
 *   compute X = k*B
 * else:
 *   compute X = k*G
 * compute Y = k*A
 * sig.c = Hs(Msg || D || X || Y)
 * sig.r = k - sig.c*r
 */
int monero_apdu_get_tx_proof() {
    unsigned char *msg;
    unsigned char *R;
    unsigned char *A;
    unsigned char *B;
    unsigned char *D;
    unsigned char r[32];
    unsigned char XY[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    #define k (G_monero_vstate.tmp+256)

    msg = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    R = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    A = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    B = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    D = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    monero_io_fetch_decrypt_key(r);

    monero_io_discard(0);

    monero_rng(k,32);
    monero_reduce(k,k);
    os_memmove(G_monero_vstate.tmp+32*0, msg, 32);
    os_memmove(G_monero_vstate.tmp+32*1, D, 32);

    if(G_monero_vstate.options&1) {
        monero_ecmul_k(XY,B,k);
    } else {
        monero_ecmul_G(XY,k);
    }
    os_memmove(G_monero_vstate.tmp+32*2,  XY, 32);

    monero_ecmul_k(XY,A,k);
    os_memmove(G_monero_vstate.tmp+32*3, XY, 32);

    monero_hash_to_scalar(sig_c, &G_monero_vstate.tmp[0],32*4);

    monero_multm(XY, sig_c, r);
    monero_subm(sig_r, k, XY);

    monero_io_insert(sig_c, 32);
    monero_io_insert(sig_r, 32);

    return SW_OK;
}
#if 0
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * pick random k
 * t3 = kG
 * c = hash_to_scalar(h|pubkey|tmp3)
 * r = k -c*sec
 */
int monero_apdu_signature() {

    unsigned char *h;
    unsigned char *pub;
    unsigned char sec[32];
    unsigned char XY[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    #define k sig_r

    h = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    pub = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
    monero_io_fetch_decrypt_key(r);

    monero_rng(k,32);
    monero_reduce(k,k);

    monero_keccak_init_F();
    monero_keccak_update_F(msg,32);
    monero_keccak_update_F(pub,32);

    monero_ecmul_G(XY,k);
    monero_keccak_update_F(XY,32);

    monero_keccak_final_F(sig_c);

    monero_multm(XY, sig_c, sec);
    monero_subm(sig_r, k, XY);

    monero_io_insert(sig_c, 32);
    monero_io_insert(sig_r, 32);

    return SW_OK;
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * sum = 0
 * hash_update(prefix)
 */
int monero_apdu_ring_signature_init() {
   unsigned char *prefix_hash;

   prefix_hash = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);

   monero_io_discard(0);

   monero_keccak_init_F();
   monero_keccak_update_F(prefix_hash,32);
   os_memset(G_monero_vstate.sum, 0, 32);

   return SW_OK;
}

/*
 * if secindex
 *
 * else
 *     c = rand32()
 *     r = rand32()
 *     buf_a = c.pubS[i]+r.G        => &buf->ab[i].a
 *     tmp3  = hash_to_ec(pub[i])
 *     buf_b = r.tmp3+c.image      => &buf->ab[i].b, &buf->ab[i].b
 *     sum = sum + c
 *     hash_update(buf_a)
 *     hash_update(buf_b)
 */
int monero_apdu_ring_signature_process() {
    unsigned char *pub;
    unsigned char *image;
    unsigned char X[32];
    unsigned char Y[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    #define k G_monero_vstate.k

    if (G_monero_vstate.options&1) {
        pub = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);

        monero_io_discard(0);

        monero_rng(k,32);
        monero_reduce(k,k);
        monero_ecmul_G(X,k);
        monero_keccak_update_F(X,32);

        monero_hash_to_ec(X, pub);
        monero_ecmul_k(X,X,k);
        monero_keccak_update_F(X,32);

        return SW_OK;
    } else {

        pub = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);
        imagee = G_monero_vstate.io_buffer+G_monero_vstate.io_offset; monero_io_fetch(NULL,32);

        monero_io_discard(0);

        monero_rng(sig_c,32);
        monero_reduce(sig_c,sig_c);
        monero_rng(sig_r,32);
        monero_reduce(sig_r,sig_r);

        monero_ecmul_k(X,pub,sig_c);
        monero_ecmul_G(Y,sig_r);
        monero_ecadd(X, X, Y);
        monero_keccak_update_F(X,32);

        monero_hash_to_ec(X, pub);
        monero_ecmul_k(X,X,sig_r);
        monero_ecmul_k(Y,image,sig_c);
        monero_ecadd(X, X, Y);
        monero_keccak_update_F(X,32);

        monero_addm(G_monero_vstate.sum,  G_monero_vstate.sum, sig_c);

        monero_io_insert(sig_c, 32);
        monero_io_insert(sig_r, 32);

    }
    return SW_OK;
}

/*
*
*      //c = h-sum
*      //r = k- c*sec
*/
int monero_apdu_ring_signature_final() {
    unsigned char sec[32];
    unsigned char X[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    #define k G_monero_vstate.k

    monero_io_fetch_decrypt_key(sec);

    monero_io_discard(0);

    monero_keccak_final_F(X);
    monero_reduce(X, X);

    monero_subm(sig_c, X, G_monero_vstate.sum);
    monero_multm(X, sig_c, sec);
    monero_subm(sig_r, k, X);

    monero_io_insert(sig_c, 32);
    monero_io_insert(sig_r, 32);

    return SW_OK;
}
#endif
