/**
 * Copyright (c) 2013-2016 Tomas Dzetkulic
 * Copyright (c) 2013-2016 Pavol Rusnak
 * Copyright (c) 2015-2016 Jochen Hoenicke
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdbool.h>
#include <string.h>

#include "bignum.h"
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "hmac.h"
#include "secp256k1.h"
#include "sha2.h"
#include "memzero.h"


int  hdnode_from_seed(const uint8_t *seed, int seed_len, const char *curve,
                     HDNode *out) {
  static CONFIDENTIAL uint8_t I[32 + 32];
  memzero(out, sizeof(HDNode));
  out->depth = 0;
  out->child_num = 0;
  out->curve = get_curve_by_name(curve);
  if (out->curve == 0) {
    return 0;
  }
  static CONFIDENTIAL HMAC_SHA512_CTX ctx;
  hmac_sha512_Init(&ctx, (const uint8_t *)out->curve->bip32_name,
                   strlen(out->curve->bip32_name));
  hmac_sha512_Update(&ctx, seed, seed_len);
  hmac_sha512_Final(&ctx, I);

  if (out->curve->params) {
    bignum256 a;
    while (true) {
      bn_read_be(I, &a);
      if (!bn_is_zero(&a)                                   // != 0
          && bn_is_less(&a, &out->curve->params->order)) {  // < order
        break;
      }
      hmac_sha512_Init(&ctx, (const uint8_t *)out->curve->bip32_name,
                       strlen(out->curve->bip32_name));
      hmac_sha512_Update(&ctx, I, sizeof(I));
      hmac_sha512_Final(&ctx, I);
    }
    memzero(&a, sizeof(a));
  }
  memcpy(out->private_key, I, 32);
  memcpy(out->chain_code, I + 32, 32);
  memzero(I, sizeof(I));
  return 1;
}

int  hdnode_private_ckd(HDNode *inout, uint32_t i) {
  static CONFIDENTIAL uint8_t data[1 + 32 + 4];
  static CONFIDENTIAL uint8_t I[32 + 32];
  static CONFIDENTIAL bignum256 a, b;

  if (i & 0x80000000) {  // private derivation
    data[0] = 0;
    memcpy(data + 1, inout->private_key, 32);
  } else {  // public derivation
    if (!inout->curve->params) {
      return 0;
    }
    //hdnode_fill_public_key(inout);
    //memcpy(data, inout->public_key, 33);
    //non-private derivation disabled
    //saves 10kB ROM and not used in IOTA
    return 0;
  }
  write_be(data + 33, i);

  bn_read_be(inout->private_key, &a);

  static CONFIDENTIAL HMAC_SHA512_CTX ctx;
  hmac_sha512_Init(&ctx, inout->chain_code, 32);
  hmac_sha512_Update(&ctx, data, sizeof(data));
  hmac_sha512_Final(&ctx, I);

  if (inout->curve->params) {
    while (true) {
      bool failed = false;
      bn_read_be(I, &b);
      if (!bn_is_less(&b, &inout->curve->params->order)) {  // >= order
        failed = true;
      } else {
        bn_add(&b, &a);
        bn_mod(&b, &inout->curve->params->order);
        if (bn_is_zero(&b)) {
          failed = true;
        }
      }

      if (!failed) {
        bn_write_be(&b, inout->private_key);
        break;
      }

      data[0] = 1;
      memcpy(data + 1, I + 32, 32);
      hmac_sha512_Init(&ctx, inout->chain_code, 32);
      hmac_sha512_Update(&ctx, data, sizeof(data));
      hmac_sha512_Final(&ctx, I);
    }
  } else {
    memcpy(inout->private_key, I, 32);
  }

  memcpy(inout->chain_code, I + 32, 32);
  inout->depth++;
  inout->child_num = i;

  // making sure to wipe our memory
  memzero(&a, sizeof(a));
  memzero(&b, sizeof(b));
  memzero(I, sizeof(I));
  memzero(data, sizeof(data));
  return 1;
}
#if 0
void  hdnode_fill_public_key(HDNode *node) {
  if (node->public_key[0] != 0) return;

  ecdsa_get_public_key33(node->curve->params, node->private_key,
                         node->public_key);
}
#endif

const curve_info  *get_curve_by_name(const char *curve_name) {
  if (curve_name == 0) {
    return 0;
  }
  if (strcmp(curve_name, SECP256K1_NAME) == 0) {
    return &secp256k1_info;
  }
  return 0;
}

