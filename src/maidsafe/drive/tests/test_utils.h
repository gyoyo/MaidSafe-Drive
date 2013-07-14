/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_DRIVE_TESTS_TEST_UTILS_H_
#define MAIDSAFE_DRIVE_TESTS_TEST_UTILS_H_

#include <string>

#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/asio_service.h"

#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/self_encryptor.h"

#ifdef WIN32
#  ifdef HAVE_CBFS
#    include "maidsafe/drive/win_drive.h"
#  else
#    include "maidsafe/drive/dummy_win_drive.h"
#  endif
#else
#  include "maidsafe/drive/unix_drive.h"
#endif

namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace drive {

#ifdef WIN32
#  ifdef HAVE_CBFS
typedef CbfsDriveInUserSpace TestDrive;
#  else
typedef DummyWinDriveInUserSpace TestDrive;
#  endif
#else
typedef FuseDriveInUserSpace TestDrive;
#endif

namespace test {

enum TestOperationCode {
  kCopy = 0,
  kRead = 1,
  kCompare = 2
};

class DerivedDrive : public TestDrive {
 public:
  typedef maidsafe::drive_store::DriveStore DataStore;

  DerivedDrive(DataStore& data_store,
               const boost::filesystem::path &mount_dir,
               const Keyword& keyword,
               const Pin& pin,
               const Password& password)
      : TestDrive(data_store, mount_dir, keyword, pin, password) {}

  std::shared_ptr<DirectoryListingHandler> directory_listing_handler() const {
    return directory_listing_handler_;
  }
};

std::shared_ptr<DerivedDrive> MakeAndMountDrive(
    const maidsafe::test::TestPath& main_test_dir,
    std::shared_ptr<DataStore>& data_store,
    fs::path& mount_directory);

void UnmountDrive(std::shared_ptr<DerivedDrive> drive, AsioService& asio_service);

void PrintResult(const bptime::ptime &start_time,
                 const bptime::ptime &stop_time,
                 size_t size,
                 TestOperationCode operation_code);
fs::path CreateTestFile(fs::path const& path, int64_t &file_size);
fs::path CreateTestFileWithSize(fs::path const& path, size_t size);
fs::path CreateTestFileWithContent(fs::path const& path, const std::string &content);
fs::path CreateTestDirectory(fs::path const& path);
fs::path CreateTestDirectoriesAndFiles(fs::path const& path);
fs::path CreateNamedFile(fs::path const& path, const std::string &name, int64_t &file_size);
fs::path CreateNamedDirectory(fs::path const& path, const std::string &name);
bool ModifyFile(fs::path const& path, int64_t &file_size);
bool SameFileContents(fs::path const& path1, fs::path const& path2);
int64_t CalculateUsedSpace(fs::path const& path);

uint64_t TotalSize(encrypt::DataMapPtr data_map);

}  // namespace test

}  // namespace drive

}  // namespace maidsafe

#endif  // MAIDSAFE_DRIVE_TESTS_TEST_UTILS_H_
