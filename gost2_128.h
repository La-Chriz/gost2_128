/*
 * GOST2-128
 * Copyright (c) 2026 Lasse Christens
 */

#ifndef GOST2_128_H
#define GOST2_128_H

#include <stdint.h>
#include <stddef.h>

#define GOST2_128_BLOCK_SIZE 16
typedef uint8_t gost2_128_block_t[GOST2_128_BLOCK_SIZE];

typedef enum {
  GOST2_128_NO_ERROR,
  GOST2_128_PARAMETER_ERROR,
  GOST2_128_KEY_SIZE_ERROR,
} gost2_128_error_t;

typedef struct {
  int rounds;
  uint64_t k[8];
} gost2_128_context_t;

gost2_128_error_t gost2_128_init(gost2_128_context_t *ctx, const uint8_t *key, size_t len, int rounds);

gost2_128_error_t gost2_128_encrypt(gost2_128_context_t *ctx, const uint8_t in[16], uint8_t out[16]);

gost2_128_error_t gost2_128_decrypt(gost2_128_context_t *ctx, const uint8_t in[16], uint8_t out[16]);

#endif /* GOST2_128_H */

#ifdef GOST2_128_IMPLEMENTATION
#ifndef GOST2_128_IMPLEMENTED
#define GOST2_128_IMPLEMENTED

static inline uint64_t gost2_128_load64(const uint8_t p[8])
{
  return ((uint64_t)p[7] << 56) |
         ((uint64_t)p[6] << 48) |
         ((uint64_t)p[5] << 40) |
         ((uint64_t)p[4] << 32) |
         ((uint64_t)p[3] << 24) |
         ((uint64_t)p[2] << 16) |
         ((uint64_t)p[1] <<  8) |
         ((uint64_t)p[0]);
}

static inline void gost2_128_store64(uint8_t p[8], uint64_t x)
{
  p[7] = (uint8_t)((x >> 56) & 0xFF);
  p[6] = (uint8_t)((x >> 48) & 0xFF);
  p[5] = (uint8_t)((x >> 40) & 0xFF);
  p[4] = (uint8_t)((x >> 32) & 0xFF);
  p[3] = (uint8_t)((x >> 24) & 0xFF);
  p[2] = (uint8_t)((x >> 16) & 0xFF);
  p[1] = (uint8_t)((x >>  8) & 0xFF);
  p[0] = (uint8_t)(x & 0xFF);
}

static const uint8_t gost2_128_Pi[16][16] = {
  {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3,
   0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2},
  {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC,
   0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
  {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA,
   0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
  {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD,
   0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
  {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6,
   0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
  {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD,
   0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
  {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC,
   0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
  {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9,
   0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
  {0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4,
   0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC},			
  {0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9,
   0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC},
  {0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD,
   0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE},
  {0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8,
   0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2},
  {0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF,
   0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3},
  {0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2,
   0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB},
  {0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA,
   0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9},
  {0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE,
   0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3}
};

static uint8_t gost2_128_s01[256];
static uint8_t gost2_128_s23[256];
static uint8_t gost2_128_s45[256];
static uint8_t gost2_128_s67[256];
static uint8_t gost2_128_s89[256];
static uint8_t gost2_128_sab[256];
static uint8_t gost2_128_scd[256];
static uint8_t gost2_128_sef[256];

static void gost2_128_init_sboxes(void)
{
  for(int i = 0; i < 256; i++)
  {
    gost2_128_s01[i] = (gost2_128_Pi[0][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[1][i & 0xF];
    gost2_128_s23[i] = (gost2_128_Pi[2][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[3][i & 0xF];
    gost2_128_s45[i] = (gost2_128_Pi[4][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[5][i & 0xF];
    gost2_128_s67[i] = (gost2_128_Pi[6][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[7][i & 0xF];
    gost2_128_s89[i] = (gost2_128_Pi[8][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[9][i & 0xF];
    gost2_128_sab[i] = (gost2_128_Pi[10][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[11][i & 0xF];
    gost2_128_scd[i] = (gost2_128_Pi[12][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[13][i & 0xF];
    gost2_128_sef[i] = (gost2_128_Pi[14][(i >> 4) & 0xF] << 4) |
                        gost2_128_Pi[15][i & 0xF];
    
  }
}

static inline uint64_t gost2_128_f(uint64_t x)
{
  x = ((uint64_t)gost2_128_s01[(x >> 56) & 0xFF] << 56) |
      ((uint64_t)gost2_128_s23[(x >> 48) & 0xFF] << 48) |
      ((uint64_t)gost2_128_s45[(x >> 40) & 0xFF] << 40) |
      ((uint64_t)gost2_128_s67[(x >> 32) & 0xFF] << 32) |
      ((uint64_t)gost2_128_s89[(x >> 24) & 0xFF] << 24) |
      ((uint64_t)gost2_128_sab[(x >> 16) & 0xFF] << 16) |
      ((uint64_t)gost2_128_scd[(x >>  8) & 0xFF] <<  8) |
      ((uint64_t)gost2_128_sef[ x & 0xFF]) ;

  x = (x << 11) | (x >> 53);

  return x;
}

static const uint8_t GOST2_128_ENC_KEYS[32] = {
  0, 1, 2, 3, 4, 5, 6, 7,
  0, 1, 2, 3, 4, 5, 6, 7,
  0, 1, 2, 3, 4, 5, 6, 7,
  7, 6, 5, 4, 3, 2, 1, 0
};

static const uint8_t GOST2_128_DEC_KEYS[32] = {
  0, 1, 2, 3, 4, 5, 6, 7,
  7, 6, 5, 4, 3, 2, 1, 0,
  7, 6, 5, 4, 3, 2, 1, 0,
  7, 6, 5, 4, 3, 2, 1, 0
};

gost2_128_error_t gost2_128_init(gost2_128_context_t *ctx, const uint8_t *key, size_t len, int rounds)
{
  if(!ctx || !key)
    return GOST2_128_PARAMETER_ERROR;

  if(len != 64)
    return GOST2_128_KEY_SIZE_ERROR;

  gost2_128_init_sboxes();

  (void) rounds;
  ctx->rounds = 32;

  for(int i = 0; i < 8; i++)
    ctx->k[i] = gost2_128_load64(&key[i*8]);

  return GOST2_128_NO_ERROR;
}

gost2_128_error_t gost2_128_encrypt(gost2_128_context_t *ctx, const uint8_t in[16], uint8_t out[16])
{
  if(!ctx || !in || !out)
    return GOST2_128_PARAMETER_ERROR;

  uint64_t n1 = gost2_128_load64(&in[0]);
  uint64_t n2 = gost2_128_load64(&in[8]);

  for(int i = 0; i < 32; i++)
  {
    uint64_t temp = n1;
    n1 = n2 ^ gost2_128_f(n1 + ctx->k[GOST2_128_ENC_KEYS[i]]);
    n2 = temp;
  }

  gost2_128_store64(&out[0], n2);
  gost2_128_store64(&out[8], n1);
  
  return GOST2_128_NO_ERROR;
}

gost2_128_error_t gost2_128_decrypt(gost2_128_context_t *ctx, const uint8_t in[16], uint8_t out[16])
{
  if(!ctx || !in || !out)
    return GOST2_128_PARAMETER_ERROR;

  uint64_t n1 = gost2_128_load64(&in[0]);
  uint64_t n2 = gost2_128_load64(&in[8]);

  for(int i = 0; i < 32; i++)
  {
    uint64_t temp = n1;
    n1 = n2 ^ gost2_128_f(n1 + ctx->k[GOST2_128_DEC_KEYS[i]]);
    n2 = temp;
  }

  gost2_128_store64(&out[0], n2);
  gost2_128_store64(&out[8], n1);
  
  return GOST2_128_NO_ERROR;
}

#endif /* GOST2_128_IMPLEMENTED */
#endif /* GOST2_128_IMPLEMENTATION */

