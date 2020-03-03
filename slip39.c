/**
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
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

#include "slip39.h"
#include <stdio.h>
#include <string.h>
#include "slip39_wordlist.h"

/**
 * Returns word on position `index`.
 */
const char* get_word(uint16_t index) { return wordlist[index]; }

/**
 * Finds index of given word, if found.
 * Returns true on success and stores result in `index`.
 */
bool word_index(uint16_t* index, const char* word, uint8_t word_length) {
  uint16_t lo = 0;
  uint16_t hi = WORDS_COUNT;
  uint16_t mid = 0;

  while ((hi - lo) > 1) {
    mid = (hi + lo) / 2;
    if (strncmp(wordlist[mid], word, word_length) > 0) {
      hi = mid;
    } else {
      lo = mid;
    }
  }
  if (strncmp(wordlist[lo], word, word_length) != 0) {
    return false;
  }
  *index = lo;
  return true;
}

/**
 * Calculates which buttons still can be pressed after some already were.
 * Returns a 9-bit bitmask, where each bit specifies which buttons
 * can be further pressed (there are still words in this combination).
 * LSB denotes first button.
 *
 * Example: 110000110 - second, third, eighth and ninth button still can be
 * pressed.
 */
uint16_t compute_mask(uint16_t prefix) { return find(prefix, false); }

