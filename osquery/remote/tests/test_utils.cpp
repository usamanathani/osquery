/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <csignal>
#include <ctime>

#include <thread>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/process/process.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/sql.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_string(enroll_tls_endpoint);
DECLARE_string(tls_server_certs);
DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_caching);

void TLSServerRunner::start() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    return;
  }

  // Pick a port in an ephemeral range at random.
  self.port_ = std::to_string(getUnixTime() % 10000 + 20000);

  // Fork then exec a shell.
  auto python_server = (getTestConfigDirectory() / "test_http_server.py")
                           .make_preferred()
                           .string() +
                       " --tls " + self.port_;
  self.server_ = PlatformProcess::launchTestPythonScript(python_server);
  if (self.server_ == nullptr) {
    return;
  }

  size_t delay = 0;
  std::string query =
      "select pid from listening_ports where port = '" + self.port_ + "'";
  while (delay < 2 * 1000) {
    auto caching = FLAGS_disable_caching;
    FLAGS_disable_caching = true;
    auto results = SQL(query);
    FLAGS_disable_caching = caching;
    if (!results.rows().empty()) {
      self.server_.reset(
          new PlatformProcess(std::atoi(results.rows()[0].at("pid").c_str())));
      break;
    }

    sleepFor(100);
    delay += 100;
  }
}

void TLSServerRunner::setClientConfig() {
  auto& self = instance();

  self.tls_hostname_ = Flag::getValue("tls_hostname");
  Flag::updateValue("tls_hostname", "localhost:" + port());

  self.enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
  Flag::updateValue("enroll_tls_endpoint", "/enroll");

  self.tls_server_certs_ = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs",
                    (getTestConfigDirectory() / "test_server_ca.pem")
                        .make_preferred()
                        .string());

  self.enroll_secret_path_ = Flag::getValue("enroll_secret_path");
  Flag::updateValue("enroll_secret_path",
                    (getTestConfigDirectory() / "test_enroll_secret.txt")
                        .make_preferred()
                        .string());
}

void TLSServerRunner::unsetClientConfig() {
  auto& self = instance();
  Flag::updateValue("tls_hostname", self.tls_hostname_);
  Flag::updateValue("enroll_tls_endpoint", self.enroll_tls_endpoint_);
  Flag::updateValue("tls_server_certs", self.tls_server_certs_);
  Flag::updateValue("enroll_secret_path", self.enroll_secret_path_);
}

void TLSServerRunner::stop() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    self.server_->kill();
    self.server_.reset();
  }
}
} // namespace osquery
