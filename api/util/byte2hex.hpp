// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2018 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef UTIL_BYTE2HEX_HPP
#define UTIL_BYTE2HEX_HPP

#include <cstdint>

// This module converts an 8-bit quantity to hex format

/**
 * Function that converts an 8-bit quantity to hex format
 *
 * @param byte
 *   The 8-bit quantity to convert to hex format
 *
 * @tparam buffer
 *   A buffer to store the coverted 8-bit quantity
 */
template <typename T>
static inline void byte_to_hex(const uint8_t byte, T& buffer) {
  char str[2];
  str[0] = (byte >> 4) & 0x0f;
  str[1] = byte & 0x0f;

  for (int i = 0; i < 2; ++i) {
    if (str[i] > 9) str[i] += 39;
    str[i] += 48;
    buffer.push_back(str[i]);
  }
}

#endif //< UTIL_BYTE2HEX_HPP
