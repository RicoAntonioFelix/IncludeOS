// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
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

#ifndef NET_IP6_IP6_HPP
#define NET_IP6_IP6_HPP

#include <delegate>
#include <net/ethernet/ethernet.hpp>
#include "../packet.hpp"
#include "../util.hpp"

#include <string>
#include <map>
#include <x86intrin.h>
#include <cstdint>
#include <cassert>

namespace net
{
  class PacketIP6;

  /** IP6 layer skeleton */
  class IP6
  {
  public:
    /** Known transport layer protocols. */
    enum proto
      {
        PROTO_HOPOPT =  0, // IPv6 hop-by-hop

        PROTO_ICMPv4 =  1,
        PROTO_TCP    =  6,
        PROTO_UDP    = 17,

        PROTO_ICMPv6 = 58, // IPv6 ICMP
        PROTO_NoNext = 59, // no next-header
        PROTO_OPTSv6 = 60, // dest options
      };

#pragma pack(push, 1)
    class header
    {
    public:
      uint8_t version() const
      {
        return (scanline[0] & 0xF0) >> 4;
      }
      uint8_t tclass() const
      {
        return ((scanline[0] & 0xF000) >> 12) +
          (scanline[0] & 0xF);
      }
      // initializes the first scanline with the IPv6 version
      void init_scan0()
      {
        scanline[0] = 6u >> 4;
      }

      uint16_t size() const
      {
        return ((scanline[1] & 0x00FF) << 8) +
          ((scanline[1] & 0xFF00) >> 8);
      }
      void set_size(uint16_t newsize)
      {
        scanline[1] &= 0xFFFF0000;
        scanline[1] |= htons(newsize);
      }

      uint8_t next() const
      {
        return (scanline[1] >> 16) & 0xFF;
      }
      void set_next(uint8_t next)
      {
        scanline[1] &= 0xFF00FFFF;
        scanline[1] |= next << 16;
      }
      uint8_t hoplimit() const
      {
        return (scanline[1] >> 24) & 0xFF;
      }
      void set_hoplimit(uint8_t limit = 64)
      {
        scanline[1] &= 0x00FFFFFF;
        scanline[1] |= limit << 24;
      }

    private:
      uint32_t scanline[2];
    public:
      addr     src;
      addr     dst;
    };

    struct options_header
    {
      uint8_t  next_header;
      uint8_t  hdr_ext_len;
      uint16_t opt_1;
      uint32_t opt_2;

      uint8_t next() const
      {
        return next_header;
      }
      uint8_t size() const
      {
        return sizeof(options_header) + hdr_ext_len;
      }
      uint8_t extended() const
      {
        return hdr_ext_len;
      }
    };
#pragma pack(pop)

    struct full_header
    {
      Ethernet::header eth_hdr;
      IP6::header      ip6_hdr;
    };

    // downstream delegate for transmit()
    typedef delegate<int(std::shared_ptr<PacketIP6>&)> downstream6;
    typedef downstream6 upstream6;

    /** Constructor. Requires ethernet to latch on to. */
    IP6(const addr& local);

    const IP6::addr& local_ip() const
    {
      return local;
    }

    uint8_t parse6(uint8_t*& reader, uint8_t next);

    static std::string protocol_name(uint8_t protocol)
    {
      switch (protocol)
        {
        case PROTO_HOPOPT:
          return "IPv6 Hop-By-Hop (0)";

        case PROTO_TCP:
          return "TCPv6 (6)";
        case PROTO_UDP:
          return "UDPv6 (17)";

        case PROTO_ICMPv6:
          return "ICMPv6 (58)";
        case PROTO_NoNext:
          return "No next header (59)";
        case PROTO_OPTSv6:
          return "IPv6 destination options (60)";

        default:
          return "Unknown: " + std::to_string(protocol);
        }
    }

    // handler for upstream IPv6 packets
    void bottom(Packet_ptr pckt);

    // transmit packets to the ether
    void transmit(std::shared_ptr<PacketIP6>& pckt);

    // modify upstream handlers
    inline void set_handler(uint8_t proto, upstream& handler)
    {
      proto_handlers[proto] = handler;
    }

    inline void set_linklayer_out(downstream func)
    {
      _linklayer_out = func;
    }

    // creates a new IPv6 packet to be sent over the ether
    static std::shared_ptr<PacketIP6> create(uint8_t proto,
                                             Ethernet::addr ether_dest, const IP6::addr& dest);

  private:
    addr local;

    /** Downstream: Linklayer output delegate */
    downstream _linklayer_out;

    /** Upstream delegates */
    std::map<uint8_t, upstream> proto_handlers;
  };

} // namespace net

#endif
