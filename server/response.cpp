// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2016 Oslo and Akershus University College of Applied Sciences
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

#include "response.hpp"

using namespace server;

Response::OnSent Response::on_sent_ = [](size_t){};

Response::Response(Connection_ptr conn)
  : http::Response(), conn_(conn)
{
  add_header(http::header_fields::Response::Server, "IncludeOS/Acorn");
  // screw keep alive
  add_header(http::header_fields::Response::Connection, "keep-alive");
}

void Response::send(bool close) const {
  write_to_conn(close);
  end();
}

void Response::write_to_conn(bool close_on_written) const {
  auto res = to_string();
  auto conn = conn_;
  conn_->write(res.data(), res.size(),
    [conn, close_on_written](size_t n) {
      on_sent_(n);
      if(close_on_written)
        conn->close();
    });
}

void Response::send_code(const Code code) {
  set_status_code(code);
  send(!keep_alive);
}

void Response::send_file(const File& file) {
  auto& entry = file.entry;

  /* Content Length */
  add_header(http::header_fields::Entity::Content_Length, std::to_string(entry.size()));

  /* Send header */
  auto res = to_string();
  conn_->write(res.data(), res.size());

  /* Send file over connection */
  auto conn = conn_;
  #ifdef VERBOSE_WEBSERVER
  printf("<Response> Sending file: %s (%llu B).\n",
    entry.name().c_str(), entry.size());
  #endif

  //auto buffer = file.disk->fs().read(entry, 0, entry.size());
  //printf("<Respone> Content:%.*s\n", buffer.size(), buffer.data());

  Async::upload_file(file.disk, file.entry, conn,
    [conn, entry](fs::error_t err, bool good)
  {
      if(good) {
        #ifdef VERBOSE_WEBSERVER
        printf("<Response> Success sending %s => %s\n",
          entry.name().c_str(), conn->remote().to_string().c_str());
        #endif

        on_sent_(entry.size());
      }
      else {
        printf("<Response> Error sending %s => %s [%s]\n",
          entry.name().c_str(), conn->remote().to_string().c_str(), err.to_string().c_str());
      }
  });

  end();
}

void Response::send_json(const std::string& json) {
  add_body(json);
  add_header(http::header_fields::Entity::Content_Type, "application/json");
  send(!keep_alive);
}

void Response::error(Error&& err) {
  // NOTE: only cares about JSON (for now)
  set_status_code(err.code);
  send_json(err.json());
}

void Response::end() const {
  // Response ended, signal server?
}

Response::~Response() {
  //printf("<Response> Deleted\n");
}
