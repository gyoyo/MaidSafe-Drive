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

#ifndef MAIDSAFE_DRIVE_DRIVE_API_H_
#define MAIDSAFE_DRIVE_DRIVE_API_H_

#include <tuple>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>

#include "boost/filesystem/path.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/signals2/signal.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/encrypt/drive_store.h"

#include "maidsafe/drive/config.h"

namespace fs = boost::filesystem;
namespace bs2 = boost::signals2;

namespace maidsafe {
namespace drive {

fs::path RelativePath(const fs::path& mount_dir, const fs::path& absolute_path);

struct FileContext;
struct MetaData;
class DirectoryListingHandler;

// For use in all cases of Create, Delete and Rename.  Signature is absolute
// path, new absolute path for Rename only, and operation type.
typedef bs2::signal<void(fs::path, fs::path, OpType)> DriveChangedSignal;
typedef std::shared_ptr<std::function<DriveChangedSignal::signature_type> > DriveChangedSlotPtr;
typedef maidsafe::drive_store::DriveStore DataStore;

class DriveInUserSpace {
  typedef bs2::signal<void(const fs::path&, OpType op)> NotifyDirectoryChangeSignal;

 public:
  typedef passport::Maid Maid;
  typedef passport::detail::Keyword Keyword;
  typedef passport::detail::Pin Pin;
  typedef passport::detail::Password Password;

  // data_store: An alternative to client_nfs for local testing.
  // maid: Client identity to validate network operations.
  // mount_dir: Identifies the root path at which the drive is mounted.
  DriveInUserSpace(DataStore& data_store,
                   const fs::path& mount_dir,
                   const Keyword& keyword,
                   const Pin& pin,
                   const Password& password);
  virtual ~DriveInUserSpace();
  virtual bool Unmount() = 0;
#ifdef MAIDSAFE_APPLE
  fs::path GetMountDir() { return mount_dir_; }
#endif
  // Returns user's unique id.
  std::string unique_user_id() const;
  // Returns root parent id.
  std::string root_parent_id() const;
  // Returns max available space.
  int64_t MaxSpace() const;
  // Returns used space.
  int64_t UsedSpace() const;
  // Sets the mount state of drive.
  void SetMountState(bool mounted);
  // Blocks until drive is in the mounted state. Times out if state does not change in expected
  // period
  bool WaitUntilMounted();
  // Blocks until drive is in the unmounted state.
  void WaitUntilUnMounted();

  // ********************* File / Folder Transfers *****************************

  // Retrieve the serialised DataMap of the file at 'relative_path' (e.g. to send
  // to another client).
  void GetDataMap(const fs::path& relative_path, std::string* serialised_data_map);
  // Retrieve the serialised DataMap of hidden file at 'relative_path'.
  void GetDataMapHidden(const fs::path& relative_path, std::string* serialised_data_map);
  // Insert a file at 'relative_path' derived from the serialised DataMap (e.g. if
  // receiving from another client).
  void InsertDataMap(const fs::path& relative_path, const std::string& serialised_data_map);

  // Populates the 'meta_data' with information saved for 'relative_path', and sets the id's of the
  // parent and grandparent listings for that path.
  void GetMetaData(const fs::path& relative_path,
                   MetaData& meta_data,
                   DirectoryId* grandparent_directory_id,
                   DirectoryId* parent_directory_id);
  // Updates parent directory at 'parent_path' with the values contained in the 'file_context'.
  void UpdateParent(FileContext* file_context, const fs::path& parent_path);
  // Adds a directory or file represented by 'meta_data' and 'relative_path' to the appropriate
  // parent directory listing. If the element is a directory, a new directory listing is created
  // and stored. The parent directory's ID is returned in 'parent_id' and its parent directory's ID
  // is returned in 'grandparent_id'.
  void AddFile(const fs::path& relative_path,
               const MetaData& meta_data,
               DirectoryId* grandparent_directory_id,
               DirectoryId* parent_directory_id);
  // Deletes the file at 'relative_path' from the appropriate parent directory listing as well as
  // the listing associated with that path if it represents a directory.
  void RemoveFile(const fs::path& relative_path);
  // Renames/moves the file located at 'old_relative_path' to that at 'new_relative_path', setting
  // 'reclaimed_space' to a non-zero value if the paths are identical and the file sizes differ.
  void RenameFile(const fs::path& old_relative_path,
                  const fs::path& new_relative_path,
                  MetaData& meta_data,
                  int64_t& reclaimed_space);
  // Resizes the file.
  bool TruncateFile(FileContext* file_context, const uint64_t& size);

  // *************************** Hidden Files **********************************

  // All hidden files in this sense have extension ".ms_hidden" and are not
  // accessible through the normal filesystem methods.

  // Reads the hidden file at 'relative_path' setting 'content' to it's contents.
  void ReadHiddenFile(const fs::path& relative_path, std::string* content);
  // Writes 'content' to the hidden file at relative_path, overwriting current content if required.
  void WriteHiddenFile(const fs::path& relative_path,
                      const std::string& content,
                      bool overwrite_existing);
  // Deletes the hidden file at 'relative_path'.
  void DeleteHiddenFile(const fs::path& relative_path);
  // Returns the hidden files at 'relative_path' in 'results'.
  void SearchHiddenFiles(const fs::path& relative_path, std::vector<std::string>* results);

  // **************************** File Notes ***********************************

  // Retrieve the collection of notes (serialised to strings) associated with
  // the given file/directory.
  void GetNotes(const fs::path& relative_path, std::vector<std::string>* notes);
  // Append a single serialised note to the collection of notes associated with
  // the given file/directory.
  void AddNote(const fs::path& relative_path, const std::string& note);

  // ************************* Signals Handling ********************************

  bs2::connection ConnectToDriveChanged(DriveChangedSlotPtr slot);

 protected:
  virtual void NotifyRename(const fs::path& from_relative_path,
                            const fs::path& to_relative_path) const = 0;

  enum DriveStage { kUnInitialised, kInitialised, kMounted, kUnMounted, kCleaned } drive_stage_;
  DataStore& data_store_;
  std::shared_ptr<DirectoryListingHandler> directory_listing_handler_;
  fs::path mount_dir_;
  DriveChangedSignal drive_changed_signal_;
  boost::mutex unmount_mutex_;
#ifdef MAIDSAFE_WIN32
  NotifyDirectoryChangeSignal notify_directory_change_;
#endif
  mutable std::mutex api_mutex_;

 private:
  virtual void SetNewAttributes(FileContext* file_context,
                                bool is_directory,
                                bool read_only) = 0;
  void ReadDataMap(const fs::path& relative_path, std::string* serialised_data_map);

  boost::condition_variable unmount_condition_variable_;
  boost::mutex mount_mutex_;
  boost::condition_variable mount_condition_variable_;
};

}  // namespace drive
}  // namespace maidsafe

#endif  // MAIDSAFE_DRIVE_DRIVE_API_H_
