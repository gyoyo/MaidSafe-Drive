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

#ifndef MAIDSAFE_DRIVE_DIRECTORY_LISTING_HANDLER_H_
#define MAIDSAFE_DRIVE_DIRECTORY_LISTING_HANDLER_H_

#include <memory>
#include <string>
#include <utility>

#include "boost/filesystem/path.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/drive_store.h"

#include "maidsafe/drive/config.h"
#include "maidsafe/drive/drive_api.h"
#include "maidsafe/drive/directory_listing.h"
#include "maidsafe/drive/utils.h"


namespace fs = boost::filesystem;
namespace bptime = boost::posix_time;

namespace maidsafe {
namespace drive {

namespace test { class DirectoryListingHandlerTest; }

typedef maidsafe::drive_store::DriveStore DataStore;
const size_t kMaxAttempts = 3;

struct DirectoryData {
  DirectoryData(const DirectoryId& parent_id_in, DirectoryListingPtr dir_listing)
      : parent_id(parent_id_in),
        listing(dir_listing),
        last_save(boost::posix_time::microsec_clock::universal_time()),
        last_change(kMaidSafeEpoch),
        content_changed(false) {}
  DirectoryData()
      : parent_id(),
        listing(),
        last_save(boost::posix_time::microsec_clock::universal_time()),
        last_change(kMaidSafeEpoch),
        content_changed(false) {}
  DirectoryId parent_id;
  DirectoryListingPtr listing;
  bptime::ptime last_save, last_change;
  bool content_changed;
};

class DirectoryListingHandler {
 public:
  typedef passport::Maid Maid;
  typedef passport::detail::Keyword Keyword;
  typedef passport::detail::Pin Pin;
  typedef passport::detail::Password Password;

  enum { kOwnerValue, kGroupValue, kWorldValue, kInvalidValue };

  DirectoryListingHandler(DataStore& data_store,
                          const Keyword& keyword,
                          const Pin& pin,
                          const Password& password);
  // Virtual destructor to allow inheritance in testing.
  virtual ~DirectoryListingHandler();

  Identity unique_user_id() const { return unique_user_id_; }
  Identity root_parent_id() const { return root_parent_id_; }
  DirectoryData GetFromPath(const fs::path& relative_path);
  // Adds a directory or file represented by meta_data and relative_path to the appropriate parent
  // directory listing.  If the element is a directory, a new directory listing is created and
  // stored.  The parent directory's ID is returned in parent_id and its parent directory's ID is
  // returned in grandparent_id.
  void AddElement(const fs::path& relative_path,
                  const MetaData& meta_data,
                  DirectoryId* grandparent_id,
                  DirectoryId* parent_id);
  // Deletes the directory or file represented by relative_path from the appropriate parent
  // directory listing.  If the element is a directory, its directory listing is deleted.
  // meta_data is filled with the element's details if found.  If the element is a file, this
  // allows the caller to delete any corresponding chunks.  If save_changes is true, the parent
  // directory listing is stored after the deletion.
  void DeleteElement(const fs::path& relative_path, MetaData& meta_data);
  void RenameElement(const fs::path& old_relative_path,
                     const fs::path& new_relative_path,
                     MetaData& meta_data,
                     int64_t& reclaimed_space);
  void UpdateParentDirectoryListing(const fs::path& parent_path, MetaData meta_data);

  DataStore& data_store() const { return data_store_; }

  friend class test::DirectoryListingHandlerTest;

 protected:
  DirectoryListingHandler(const DirectoryListingHandler&);
  DirectoryListingHandler& operator=(const DirectoryListingHandler&);
  DirectoryData RetrieveFromStorage(const DirectoryId& parent_id,
                                    const DirectoryId& directory_id) const;
  void PutToStorage(const DirectoryData& directory);
  void DeleteStored(const DirectoryId& parent_id, const DirectoryId& directory_id);
  void RetrieveDataMap(const DirectoryId& parent_id,
                       const DirectoryId& directory_id,
                       DataMapPtr data_map) const;
  bool IsDirectory(const MetaData& meta_data) const;
  void GetParentAndGrandparent(const fs::path& relative_path,
                               DirectoryData* grandparent,
                               DirectoryData* parent,
                               MetaData* parent_meta_data);
  bool RenameTargetCanBeRemoved(const fs::path& new_relative_path,
                                const MetaData& target_meta_data);
  void RenameSameParent(const fs::path& old_relative_path,
                        const fs::path& new_relative_path,
                        MetaData& meta_data,
                        int64_t& reclaimed_space);
  void RenameDifferentParent(const fs::path& old_relative_path,
                             const fs::path& new_relative_path,
                             MetaData& meta_data,
                             int64_t& reclaimed_space);
 private:
  DataStore& data_store_;
  std::shared_ptr<Maid> maid_;
  Identity unique_user_id_, root_parent_id_;
  fs::path relative_root_;
};

}  // namespace drive
}  // namespace maidsafe

#endif  // MAIDSAFE_DRIVE_DIRECTORY_LISTING_HANDLER_H_
