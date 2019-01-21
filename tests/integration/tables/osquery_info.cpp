
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

// Sanity check integration test for osquery_info
// Spec file: specs/utility/osquery_info.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class osqueryInfo : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(osqueryInfo, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from osquery_info");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See helper.h for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"pid", IntType}
  //      {"uuid", NormalType}
  //      {"instance_id", NormalType}
  //      {"version", NormalType}
  //      {"config_hash", NormalType}
  //      {"config_valid", IntType}
  //      {"extensions", NormalType}
  //      {"build_platform", NormalType}
  //      {"build_distro", NormalType}
  //      {"start_time", IntType}
  //      {"watcher", IntType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
