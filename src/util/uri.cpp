// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2017 Oslo and Akershus University College of Applied Sciences
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

#include <algorithm>
#include <cctype>
#include <uri>
#include <utility>
#include <vector>

#include "../../mod/http-parser/http_parser.h"

namespace uri {

///////////////////////////////////////////////////////////////////////////////
static inline bool icase_equal(const std::string_view lhs, const std::string_view rhs) noexcept {
  return (lhs.size() == rhs.size())
         and
         std::equal(lhs.cbegin(), lhs.cend(), rhs.cbegin(), [](const char a, const char b) {
          return std::tolower(a) == std::tolower(b);
         });
}

///////////////////////////////////////////////////////////////////////////////
static inline uint16_t bind_port(const std::string_view scheme, const uint16_t port_from_uri) noexcept {
  static const std::vector<std::pair<const std::string_view, uint16_t>> port_table
  {
    {"ftp",    21U},
    {"http",   80U},
    {"https",  443U},
    {"irc",    6667U},
    {"ldap",   389U},
    {"nntp",   119U},
    {"rtsp",   554U},
    {"sip",    5060U},
    {"sips",   5061U},
    {"smtp",   25U},
    {"ssh",    22U},
    {"telnet", 23U},
    {"ws",     80U},
    {"xmpp",   5222U},
  };

  if (port_from_uri not_eq 0) return port_from_uri;

  const auto it = std::find_if(port_table.cbegin(), port_table.cend(), [scheme](const auto& _) {
      return icase_equal(_.first, scheme);
  });

  return (it not_eq port_table.cend()) ? it->second : 0xFFFFU;
}

///////////////////////////////////////////////////////////////////////////////
// copy helper
///////////////////////////////////////////////////////////////////////////////
static inline std::string_view updated_copy(const std::string& to_copy,
                                            const std::string_view view,
                                            const std::string& from_copy)
{
  return {to_copy.data() + (view.data() - from_copy.data()), view.size()};
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(const char* uri, const bool parse)
  : uri_str_{decode(uri)}
{
  if (parse) this->parse();
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(const char* uri, const size_t count, const bool parse)
  : uri_str_{decode(std::string_view{uri, count})}
{
  if (parse) this->parse();
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(const std::string& uri, const bool parse)
  : uri_str_{decode(std::string_view{uri.data(), uri.length()})}
{
  if (parse) this->parse();
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(const std::string_view uri, const bool parse)
  : uri_str_{decode(uri)}
{
  if (parse) this->parse();
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(const URI& u)
  : uri_str_  {u.uri_str_}
  , port_     {u.port_}
  , scheme_   {updated_copy(uri_str_, u.scheme_,   u.uri_str_)}
  , userinfo_ {updated_copy(uri_str_, u.userinfo_, u.uri_str_)}
  , host_     {updated_copy(uri_str_, u.host_,     u.uri_str_)}
  , port_str_ {updated_copy(uri_str_, u.port_str_, u.uri_str_)}
  , path_     {updated_copy(uri_str_, u.path_,     u.uri_str_)}
  , query_    {updated_copy(uri_str_, u.query_,    u.uri_str_)}
  , fragment_ {updated_copy(uri_str_, u.fragment_, u.uri_str_)}
  , query_map_{}
{
  for(const auto& ent : u.query_map_)
  {
    query_map_.emplace(updated_copy(uri_str_, ent.first,  u.uri_str_),
                       updated_copy(uri_str_, ent.second, u.uri_str_));
  }
}

///////////////////////////////////////////////////////////////////////////////
URI::URI(URI&& u) noexcept
  : uri_str_{std::move(u.uri_str_)}
  , port_     {u.port_}
  , scheme_   {u.scheme_}
  , userinfo_ {u.userinfo_}
  , host_     {u.host_}
  , port_str_ {u.port_str_}
  , path_     {u.path_}
  , query_    {u.query_}
  , fragment_ {u.fragment_}
  , query_map_{std::move(u.query_map_)}
{}

///////////////////////////////////////////////////////////////////////////////
URI& URI::operator=(const URI& u) {
  uri_str_  = u.uri_str_;
  port_     = u.port_;
  scheme_   = updated_copy(uri_str_, u.scheme_,   u.uri_str_);
  userinfo_ = updated_copy(uri_str_, u.userinfo_, u.uri_str_);
  host_     = updated_copy(uri_str_, u.host_,     u.uri_str_);
  port_str_ = updated_copy(uri_str_, u.port_str_, u.uri_str_);
  path_     = updated_copy(uri_str_, u.path_,     u.uri_str_);
  query_    = updated_copy(uri_str_, u.query_,    u.uri_str_);
  fragment_ = updated_copy(uri_str_, u.fragment_, u.uri_str_);

  query_map_.clear();

  for(const auto& ent : u.query_map_) {
    query_map_.emplace(updated_copy(uri_str_, ent.first,  u.uri_str_),
                       updated_copy(uri_str_, ent.second, u.uri_str_));
  }

  return *this;
}

///////////////////////////////////////////////////////////////////////////////
URI& URI::operator=(URI&& u) noexcept {
  uri_str_   = std::move(u.uri_str_);
  port_      = u.port_;
  scheme_    = u.scheme_;
  userinfo_  = u.userinfo_;
  host_      = u.host_;
  port_str_  = u.port_str_;
  path_      = u.path_;
  query_     = u.query_;
  fragment_  = u.fragment_;
  query_map_ = std::move(u.query_map_);

  return *this;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::scheme() const noexcept {
  return scheme_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::userinfo() const noexcept {
  return userinfo_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::host() const noexcept {
  return host_;
}

///////////////////////////////////////////////////////////////////////////////
bool URI::host_is_ip4() const noexcept {
  return host_.empty() ? false : std::isdigit(host_.back());
}

///////////////////////////////////////////////////////////////////////////////
bool URI::host_is_ip6() const noexcept {
  return host_.empty() ? false : (*(host_.data() + host_.length()) == ']');
}

///////////////////////////////////////////////////////////////////////////////
std::string URI::host_and_port() const {
  return std::string{host_.data(), host_.length()} + ':' + std::to_string(port_);
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::port_str() const noexcept {
  return port_str_;
}

///////////////////////////////////////////////////////////////////////////////
uint16_t URI::port() const noexcept {
  return port_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::path() const noexcept {
  return path_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::query() const noexcept {
  return query_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::fragment() const noexcept {
  return fragment_;
}

///////////////////////////////////////////////////////////////////////////////
std::string_view URI::query(const std::string_view key) {
  if (query_map_.empty() and (not query_.empty())) {
    load_queries();
  }

  const auto target = query_map_.find(key);

  return (target not_eq query_map_.cend()) ? target->second : std::string_view{};
}

///////////////////////////////////////////////////////////////////////////////
bool URI::is_valid() const noexcept {
  return (not host_.empty()) or (not path_.empty()) ;
}

///////////////////////////////////////////////////////////////////////////////
URI::operator bool() const noexcept {
  return is_valid();
}

///////////////////////////////////////////////////////////////////////////////
const std::string& URI::to_string() const noexcept {
  return uri_str_;
}

///////////////////////////////////////////////////////////////////////////////
URI::operator std::string () const {
  return uri_str_;
}

///////////////////////////////////////////////////////////////////////////////
URI& URI::operator << (const std::string& chunk) {
  uri_str_.append(chunk);
  return *this;
}

///////////////////////////////////////////////////////////////////////////////
URI& URI::parse() {
  http_parser_url u;
  http_parser_url_init(&u);

  const auto p = uri_str_.data();
  const auto result = http_parser_parse_url(p, uri_str_.length(), 0, &u);

#ifdef URI_THROW_ON_ERROR
  if (result not_eq 0) {
    throw URI_error{"Invalid uri: " + uri_str_};
  }
#endif //< URI_THROW_ON_ERROR

  (void)result;

  scheme_   = (u.field_set & (1 << UF_SCHEMA))   ? std::string_view{p + u.field_data[UF_SCHEMA].off,   u.field_data[UF_SCHEMA].len}   : std::string_view{};
  userinfo_ = (u.field_set & (1 << UF_USERINFO)) ? std::string_view{p + u.field_data[UF_USERINFO].off, u.field_data[UF_USERINFO].len} : std::string_view{};
  host_     = (u.field_set & (1 << UF_HOST))     ? std::string_view{p + u.field_data[UF_HOST].off,     u.field_data[UF_HOST].len}     : std::string_view{};
  port_str_ = (u.field_set & (1 << UF_PORT))     ? std::string_view{p + u.field_data[UF_PORT].off,     u.field_data[UF_PORT].len}     : std::string_view{};
  path_     = (u.field_set & (1 << UF_PATH))     ? std::string_view{p + u.field_data[UF_PATH].off,     u.field_data[UF_PATH].len}     : std::string_view{};
  query_    = (u.field_set & (1 << UF_QUERY))    ? std::string_view{p + u.field_data[UF_QUERY].off,    u.field_data[UF_QUERY].len}    : std::string_view{};
  fragment_ = (u.field_set & (1 << UF_FRAGMENT)) ? std::string_view{p + u.field_data[UF_FRAGMENT].off, u.field_data[UF_FRAGMENT].len} : std::string_view{};

  port_ = bind_port(scheme_, u.port);

  return *this;
}

///////////////////////////////////////////////////////////////////////////////
URI& URI::reset() {
  new (this) URI{};
  return *this;
}

///////////////////////////////////////////////////////////////////////////////
void URI::load_queries() {
  auto _ = query_;

  std::string_view name  {};
  std::string_view value {};
  std::string_view::size_type base {0U};
  std::string_view::size_type break_point {};

  while (true) {
    if ((break_point = _.find('=')) not_eq std::string_view::npos) {
      name = _.substr(base, break_point);
      //-----------------------------------
      _.remove_prefix(name.length() + 1U);
    }
    else {
      break;
    }

    if ((break_point = _.find('&')) not_eq std::string_view::npos) {
      value = _.substr(base, break_point);
      query_map_.emplace(name, value);
      _.remove_prefix(value.length() + 1U);
    }
    else {
      query_map_.emplace(name, _);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
bool operator < (const URI& lhs, const URI& rhs) noexcept {
  return lhs.to_string() < rhs.to_string();
}

///////////////////////////////////////////////////////////////////////////////
bool operator == (const URI& lhs, const URI& rhs) noexcept {
  return icase_equal(lhs.scheme(), rhs.scheme())
         and (lhs.userinfo() == rhs.userinfo())
         and icase_equal(lhs.host(), rhs.host())
         and lhs.port() == rhs.port()
         and lhs.path() == rhs.path()
         and lhs.query() == rhs.query()
         and lhs.fragment() == rhs.fragment();
}

} //< namespace uri
