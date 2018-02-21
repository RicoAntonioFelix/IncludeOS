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

#pragma once
#ifndef NET_IP6_ADDR_HPP
#define NET_IP6_ADDR_HPP

#include <string>
#include <util/byte2hex.hpp>

namespace net {
namespace ip6 {

/**
 * This type is thrown when creating an instance of Addr
 * with a std::string that doesn't represent a valid IPv6
 * address
 */
struct Invalid_address : std::runtime_error {
  using runtime_error::runtime_error;
}; //< struct Invalid_address

/**
 * IPv6 address representation
 */
struct Addr {
  /**
   * Constructor
   *
   * Create an IPv6 address object to represent the address {::}
   */
  constexpr Addr() noexcept
    : i16{}
  {}

  /**
   * Constructor
   *
   * Create an IPv6 address by specifying each part of the address as a 16-bit value
   *
   * @param p1
   *  The first part of the IPv6 address
   *
   * @param p2
   *  The second part of the IPv6 address
   *
   * @param p3
   *  The third part of the IPv6 address
   *
   * @param p4
   *  The fourth part of the IPv6 address
   *
   * @param p5
   *  The fifth part of the IPv6 address
   *
   * @param p6
   *  The sixth part of the IPv6 address
   *
   * @param p7
   *  The seventh part of the IPv6 address
   *
   * @param p8
   *  The eighth part of the IPv6 address
   */
  constexpr Addr(const uint16_t p1, const uint16_t p2, const uint16_t p3, const uint16_t p4,
                 const uint16_t p5, const uint16_t p6, const uint16_t p7, const uint16_t p8) noexcept
    : i16{}
  {
    i16[0] = __builtin_bswap16(p1);
    i16[1] = __builtin_bswap16(p2);
    i16[2] = __builtin_bswap16(p3);
    i16[3] = __builtin_bswap16(p4);
    i16[4] = __builtin_bswap16(p5);
    i16[5] = __builtin_bswap16(p6);
    i16[6] = __builtin_bswap16(p7);
    i16[7] = __builtin_bswap16(p8);
  }

  /**
   * Constructor
   *
   * Construct an IPv6 address from a {std::string} object
   * representing an IPv6 address
   *
   * @param ipv6_addr
   *  A {std::string} object representing an IPv6 address
   *
   * @throws Invalid_address
   *  IIf the {std::string} object doesn't representing a valid IPv6
   *  address
   */
  Addr(const std::string& ipv6_addr)
    : i16{}
  {
    uint16_t word_register = 0;
    uint8_t  colon_count_register = 0;

    static auto _ = [](char c) -> uint8_t {
      c |= 0x20;
      if ((c >= '0') and (c <= '9')) {
        return c - '0';
      } else if ((c >= 'a') and (c <= 'f')) {
        return (c - 'a') + 10;
      } else {
        throw c;
      }
    };

    for(int i = 1; i <= 39; ++i) {
      if (ipv6_addr[i] == ':') {
        if (ipv6_addr[i - 1] == ':') colon_count_register = 14;
        else if (colon_count_register) colon_count_register -= 2;
        else if (ipv6_addr[i] == '\0') break;
      }
    }

    for(int i = 0, cursor = 0; (i <= 39) and (cursor < 16); ++i) {
      if ((ipv6_addr[i] == ':') or (ipv6_addr[i] == '\0')) {
        i8[cursor] = word_register >> 8;
        i8[cursor + 1] = word_register;
        word_register = 0;

        if ((colon_count_register and i) and (ipv6_addr[ i - 1] == ':')) {
          cursor = colon_count_register;
        } else {
          cursor += 2;
        }
      } else {
        try {
          word_register <<= 4;
          word_register |= _(ipv6_addr[i]);
        } catch (const char c) {
          throw Invalid_address{ipv6_addr + " contain an invalid character: " + c};
        }
      }

      if (ipv6_addr[i] == '\0') break;
    }
  }

  /**
   * Copy constructor
   */
  constexpr Addr(const Addr& addr) noexcept
    : i16{}
  {
    for (int i = 0; i < 8; ++i) {
      i16[i] = addr.i16[i];
    }
  }

  /**
   * Move constructor
   */
  constexpr Addr(Addr&& addr) noexcept
    : i16{}
  {
    for (int i = 0; i < 8; ++i) {
      i16[i] = addr.i16[i];
    }
  }

  /**
   * Copy assignment operator
   */
  constexpr Addr& operator=(const Addr& addr) noexcept {
    for (int i = 0; i < 8; ++i) {
      i16[i] = addr.i16[i];
    }

    return *this;
  }

  /**
   * Move assignment operator
   */
  constexpr Addr& operator=(Addr&& addr) noexcept {
    for (int i = 0; i < 8; ++i) {
      i16[i] = addr.i16[i];
    }

    return *this;
  }

  /**
   * Operator to check for equality
   *
   * @param other
   *  The IPv6 address object to check for equality
   *
   * @return true if this object is equal to other, false otherwise
   */
  constexpr bool operator==(const Addr& other) const noexcept {
    for (int i = 0; i < 8; ++i) {
      if (i16[i] not_eq other.i16[i]) return false;
    }

    return true;
  }

  /**
   * Operator to check for inequality
   *
   * @param other
   *  The IPv6 address object to check for inequality
   *
   * @return true if this object is not equal to other, false otherwise
   */
  constexpr bool operator!=(const Addr& other) const noexcept {
    return not (*this == other);
  }

  /**
   * Operator to perform a bitwise-and operation on the given
   * IPv6 addresses
   *
   * @param other
   *  The IPv6 address object to perform the bitwise-and operation
   *
   * @return An IPv6 address object containing the result of the
   * operation
   */
  constexpr Addr operator&(const Addr& other) const noexcept {
    return Addr {
      static_cast<uint16_t>(i16[0] & other.i16[0]),
      static_cast<uint16_t>(i16[1] & other.i16[1]),
      static_cast<uint16_t>(i16[2] & other.i16[2]),
      static_cast<uint16_t>(i16[3] & other.i16[3]),
      static_cast<uint16_t>(i16[4] & other.i16[4]),
      static_cast<uint16_t>(i16[5] & other.i16[5]),
      static_cast<uint16_t>(i16[6] & other.i16[6]),
      static_cast<uint16_t>(i16[7] & other.i16[7])
    };
  }

  /**
   * Operator to perform a bitwise-or operation on the given
   * IPv6 addresses
   *
   * @param other
   *  The IPv6 address object to perform the bitwise-or operation
   *
   * @return An IPv6 address object containing the result of the
   * operation
   */
  constexpr Addr operator|(const Addr& other) const noexcept {
    return Addr {
      static_cast<uint16_t>(i16[0] | other.i16[0]),
      static_cast<uint16_t>(i16[1] | other.i16[1]),
      static_cast<uint16_t>(i16[2] | other.i16[2]),
      static_cast<uint16_t>(i16[3] | other.i16[3]),
      static_cast<uint16_t>(i16[4] | other.i16[4]),
      static_cast<uint16_t>(i16[5] | other.i16[5]),
      static_cast<uint16_t>(i16[6] | other.i16[6]),
      static_cast<uint16_t>(i16[7] | other.i16[7])
    };
  }

  /**
   * Operator to perform a bitwise-not operation on the IPv6
   * address
   *
   * @return An IPv6 address object containing the result of the
   * operation
   */
  constexpr Addr operator~() const noexcept {
    return Addr{
      static_cast<uint16_t>(~i16[0]),
      static_cast<uint16_t>(~i16[1]),
      static_cast<uint16_t>(~i16[2]),
      static_cast<uint16_t>(~i16[3]),
      static_cast<uint16_t>(~i16[4]),
      static_cast<uint16_t>(~i16[5]),
      static_cast<uint16_t>(~i16[6]),
      static_cast<uint16_t>(~i16[7])
    };
  }

  /**
   * Get a string representation of the IPv6 address
   *
   * @return A string representation of the IPv6 address
   */
  std::string str() const {
    std::string ipv6_addr_str;
    ipv6_addr_str.reserve(39);

    const uint8_t* ipv6_addr_bytes = i8;

    for (int i = 0; i < 16; ++i) {
      byte_to_hex(ipv6_addr_bytes[i], ipv6_addr_str);
      if ((i % 2 == 1) and (i < 15)) ipv6_addr_str.push_back(':');
    }

    return ipv6_addr_str;
  }

  /**
   * Get a string representation of this type
   *
   * @return A string representation of this type
   */
  std::string to_string() const
  { return str(); }

  /**
   * Method to check if the address represents an IPv6 multicast address
   *
   * @return true if multicast, false otherwise
   */
  constexpr bool is_multicast() const noexcept {
    /**
       RFC 4291 2.7 Multicast Addresses

       An IPv6 multicast address is an identifier for a group of interfaces
       (typically on different nodes). An interface may belong to any
       number of multicast groups. Multicast addresses have the following format:
       |   8    |  4 |  4 |                  112 bits                   |
       +------ -+----+----+---------------------------------------------+
       |11111111|flgs|scop|                  group ID                   |
       +--------+----+----+---------------------------------------------+
    **/
    return i8[0] == 0xFF;
  }

  /**
   * Method to check if the address represents an IPv6 loopback address
   *
   * @return true if loopback, false otherwise
   */
  constexpr bool is_loopback() const noexcept {
    return (i16[0] == 0x0000) and (i16[1] == 0x0000) and (i16[2] == 0x0000) and
           (i16[3] == 0x0000) and (i16[4] == 0x0000) and (i16[5] == 0x0000) and
           (i16[6] == 0x0000) and (i16[7] == 0x0100);
  }

  /**
   * Method to check if the address represents an IPv4 mapped address
   *
   * @return true if IPv4 mapped, false otherwise
   */
  constexpr bool is_ip4_mapped() const noexcept {
    return (i16[0] == 0x0000) and (i16[1] == 0x0000) and (i16[2] == 0x0000) and
           (i16[3] == 0x0000) and (i16[4] == 0x0000) and (i16[5] == 0xFFFF);
  }

  /* Data member */
  union {
    uint16_t  i16[ 8];
    uint8_t    i8[16];
  };
}__attribute__((__packed__)); //< struct Addr

// Loopback address
constexpr const Addr loopback {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1};

// Unspecified link-local address
constexpr const Addr link_unspecified {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

// Multicast IPv6 addresses
constexpr const Addr node_all_nodes   {0xFF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1};  //< RFC 4921
constexpr const Addr node_all_routers {0xFF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2};  //< RFC 4921
constexpr const Addr node_mDNSv6      {0xFF01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xFB}; //< RFC 6762 (multicast DNSv6)

// RFC 4291 2.4.6:
// Link-Local addresses are designed to be used for addressing on a
// single link for purposes such as automatic address configuration,
// neighbor discovery, or when no routers are present.
constexpr const Addr link_all_nodes   {0xFF02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1};  //< RFC 4921
constexpr const Addr link_all_routers {0xFF02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2};  //< RFC 4921
constexpr const Addr link_mDNSv6      {0xFF02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xFB}; //< RFC 6762

constexpr const Addr link_dhcp_servers {0xFF02, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x2}; //< RFC 3315
constexpr const Addr site_dhcp_servers {0xFF05, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x3}; //< RFC 3315

} //< namespace ip6
} //< namespace net

// Quick and dirty hash function to allow an IPv6 address to be used as key
// in e.g. std::unordered_map
// NOTE: Need to be looked over by hash experts...
namespace std {
  template<>
  struct hash<net::ip6::Addr> {
    size_t operator()(const net::ip6::Addr& addr) const {
      return std::hash<uint16_t>{}(addr.i16[0])
        + std::hash<uint16_t>{}(addr.i16[1])
        + std::hash<uint16_t>{}(addr.i16[2])
        + std::hash<uint16_t>{}(addr.i16[3])
        + std::hash<uint16_t>{}(addr.i16[4])
        + std::hash<uint16_t>{}(addr.i16[5])
        + std::hash<uint16_t>{}(addr.i16[6])
        + std::hash<uint16_t>{}(addr.i16[7]);
    }
  };
} //< namespace std

#endif //< NET_IP6_ADDR_HPP
