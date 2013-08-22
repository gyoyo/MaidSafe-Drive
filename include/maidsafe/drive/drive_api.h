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

#include <condition_variable>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/drive/config.h"
#include "maidsafe/drive/directory_listing_handler.h"
#include "maidsafe/drive/meta_data.h"
#include "maidsafe/drive/utils.h"


namespace maidsafe {

  namespace drive {

boost::filesystem::path RelativePath(const boost::filesystem::path& mount_dir,
                                     const boost::filesystem::path& absolute_path);

struct MetaData;
template<typename Storage> struct FileContext;
template<typename Storage> class DirectoryListingHandler;

template<typename Storage>
class DriveInUserSpace {
 public:
  // client_nfs: Enables network file operations.
  // data_store: An alternative to client_nfs for local testing.
  // maid: Client identity to validate network operations.
  // unique_user_id: A random id created during user creation in client.
  // root_parent_id: A random id representing non-existing root parent directory.
  // mount_dir: Identifies the root path at which the drive is mounted.
  // max_space: Space available for data storage.
  // used_space: Space taken on network storing data.
  DriveInUserSpace(Storage& data_store,
                   const Identity& unique_user_id,
                   const std::string& root_parent_id,
                   const boost::filesystem::path& mount_dir,
                   const int64_t& max_space,
                   const int64_t& used_space);
  virtual ~DriveInUserSpace();
  virtual bool Unmount(int64_t &max_space, int64_t &used_space) = 0;
#ifdef MAIDSAFE_APPLE
  boost::filesystem::path GetMountDir() { return mount_dir_; }
#endif
  std::string unique_user_id() const;
  std::string root_parent_id() const;
  void SetMountState(bool mounted);
  // Times out after 10 seconds.
  bool WaitUntilMounted();
  // Doesn't time out.
  void WaitUntilUnMounted();

  // ********************* File / Folder Transfers *****************************

  // Retrieve the serialised DataMap of the file at 'relative_path' (e.g. to send to another client)
  void GetDataMap(const boost::filesystem::path& relative_path, std::string* serialised_data_map);
  void GetDataMapHidden(const boost::filesystem::path& relative_path,
                        std::string* serialised_data_map);
  // Insert a file at 'relative_path' derived from the serialised DataMap (e.g. if
  // receiving from another client).
  void InsertDataMap(const boost::filesystem::path& relative_path,
                     const std::string& serialised_data_map);
  void GetMetaData(const boost::filesystem::path& relative_path,
                   MetaData& meta_data,
                   DirectoryId* grandparent_directory_id,
                   DirectoryId* parent_directory_id);
  // Updates parent directory at 'parent_path' with the values contained in the 'file_context'.
  void UpdateParent(FileContext<Storage>* file_context, const boost::filesystem::path& parent_path);
  // Adds a directory or file represented by 'meta_data' and 'relative_path' to the appropriate
  // parent directory listing. If the element is a directory, a new directory listing is created
  // and stored. The parent directory's ID is returned in 'parent_id' and its parent directory's ID
  // is returned in 'grandparent_id'.
  void AddFile(const boost::filesystem::path& relative_path,
               const MetaData& meta_data,
               DirectoryId* grandparent_directory_id,
               DirectoryId* parent_directory_id);
  bool CanRemove(const boost::filesystem::path& relative_path);
  // Deletes the file at 'relative_path' from the appropriate parent directory listing as well as
  // the listing associated with that path if it represents a directory.
  void RemoveFile(const boost::filesystem::path& relative_path);
  // Renames/moves the file located at 'old_relative_path' to that at 'new_relative_path', setting
  // 'reclaimed_space' to a non-zero value if the paths are identical and the file sizes differ.
  void RenameFile(const boost::filesystem::path& old_relative_path,
                  const boost::filesystem::path& new_relative_path,
                  MetaData& meta_data,
                  int64_t& reclaimed_space);
  // Resizes the file.
  bool TruncateFile(FileContext<Storage>* file_context, const uint64_t& size);

  // *************************** Hidden Files **********************************

  // All hidden files in this sense have extension ".ms_hidden" and are not accessible through the
  // normal filesystem methods.

  void ReadHiddenFile(const boost::filesystem::path& relative_path, std::string* content);
  void WriteHiddenFile(const boost::filesystem::path& relative_path,
                      const std::string& content,
                      bool overwrite_existing);
  void DeleteHiddenFile(const boost::filesystem::path& relative_path);
  // Returns the hidden files at 'relative_path' in 'results'.
  void SearchHiddenFiles(const boost::filesystem::path& relative_path,
                         std::vector<std::string>* results);

  // **************************** File Notes ***********************************

  // Retrieve the collection of notes (serialised to strings) associated with given file/directory.
  void GetNotes(const boost::filesystem::path& relative_path, std::vector<std::string>* notes);
  // Append a single serialised note to the collection of notes associated with given file/directory
  void AddNote(const boost::filesystem::path& relative_path, const std::string& note);

 protected:
  virtual void NotifyRename(const boost::filesystem::path& from_relative_path,
                            const boost::filesystem::path& to_relative_path) const = 0;

  enum DriveStage { kUnInitialised, kInitialised, kMounted, kUnMounted, kCleaned } drive_stage_;
  Storage& storage_;
  std::shared_ptr<DirectoryListingHandler<Storage>> directory_listing_handler_;
  boost::filesystem::path mount_dir_;
//  int64_t max_space_, used_space_;
  std::mutex unmount_mutex_;
  mutable std::mutex api_mutex_;

 private:
  virtual void SetNewAttributes(FileContext<Storage>* file_context,
                                bool is_directory,
                                bool read_only) = 0;
  void ReadDataMap(const boost::filesystem::path& relative_path, std::string* serialised_data_map);

  std::condition_variable unmount_condition_variable_;
  std::mutex mount_mutex_;
  std::condition_variable mount_condition_variable_;
};


template<typename Storage>
DriveInUserSpace<Storage>::DriveInUserSpace(Storage& storage,
                                            const Identity& unique_user_id,
                                            const std::string& root_parent_id,
                                            const boost::filesystem::path& mount_dir,
                                            const int64_t& /*max_space*/,
                                            const int64_t& /*used_space*/)
    : drive_stage_(kUnInitialised),
      storage_(storage),
      directory_listing_handler_(new DirectoryListingHandler<Storage>(storage,
                                                                      unique_user_id,
                                                                      root_parent_id)),
      mount_dir_(mount_dir),
//      max_space_(max_space),
//      used_space_(used_space),
      unmount_mutex_(),
      api_mutex_(),
      unmount_condition_variable_(),
      mount_mutex_(),
      mount_condition_variable_() {}

template<typename Storage>
DriveInUserSpace<Storage>::~DriveInUserSpace() {}

template<typename Storage>
std::string DriveInUserSpace<Storage>::unique_user_id() const {
  std::lock_guard<std::mutex> guard(api_mutex_);
  return directory_listing_handler_->unique_user_id().string();
}

template<typename Storage>
std::string DriveInUserSpace<Storage>::root_parent_id() const {
  std::lock_guard<std::mutex> guard(api_mutex_);
  return directory_listing_handler_->root_parent_id().string();
}

template<typename Storage>
void DriveInUserSpace<Storage>::SetMountState(bool mounted) {
  {
    std::lock_guard<std::mutex> lock(mount_mutex_);
    drive_stage_ = (mounted ? kMounted : kUnMounted);
  }
  mount_condition_variable_.notify_one();
}

template<typename Storage>
bool DriveInUserSpace<Storage>::WaitUntilMounted() {
  std::lock_guard<std::mutex> lock(mount_mutex_);
  bool result(mount_condition_variable_.wait_for(lock, std::chrono::seconds(10),
                                                 [this] { return drive_stage_ == kMounted; }));
#ifdef MAIDSAFE_APPLE
//  Sleep(boost::posix_time::seconds(1));
#endif
  return result;
}

template<typename Storage>
void DriveInUserSpace<Storage>::WaitUntilUnMounted() {
  std::unique_lock<std::mutex> lock(mount_mutex_);
  mount_condition_variable_.wait(lock, [this] { return drive_stage_ == kUnMounted; });
}

template<typename Storage>
void DriveInUserSpace<Storage>::GetMetaData(const boost::filesystem::path& relative_path,
                                            MetaData& meta_data,
                                            DirectoryId* grandparent_directory_id,
                                            DirectoryId* parent_directory_id) {
  typedef typename DirectoryListingHandler<Storage>::DirectoryType DirectoryType;
  DirectoryType parent(directory_listing_handler_->GetFromPath(relative_path.parent_path()));
  parent.first.listing->GetChild(relative_path.filename(), meta_data);

  if (grandparent_directory_id)
    *grandparent_directory_id = parent.first.parent_id;
  if (parent_directory_id)
    *parent_directory_id = parent.first.listing->directory_id();
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::UpdateParent(FileContext<Storage>* file_context,
                                             const boost::filesystem::path& parent_path) {
  directory_listing_handler_->UpdateParentDirectoryListing(parent_path, *file_context->meta_data);
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::AddFile(const boost::filesystem::path& relative_path,
                                        const MetaData& meta_data,
                                        DirectoryId* grandparent_directory_id,
                                        DirectoryId* parent_directory_id) {
  directory_listing_handler_->AddElement(relative_path,
                                         meta_data,
                                         grandparent_directory_id,
                                         parent_directory_id);
}

template<typename Storage>
bool DriveInUserSpace<Storage>::CanRemove(const boost::filesystem::path& relative_path) {
  return directory_listing_handler_->CanDelete(relative_path);
}

template<typename Storage>
void DriveInUserSpace<Storage>::RemoveFile(const boost::filesystem::path& relative_path) {
  MetaData meta_data;
  directory_listing_handler_->DeleteElement(relative_path, meta_data);

  if (meta_data.data_map && !meta_data.directory_id) {
    encrypt::SelfEncryptor<Storage> delete_this(meta_data.data_map, storage_);
    delete_this.DeleteAllChunks();
  }
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::RenameFile(const boost::filesystem::path& old_relative_path,
                                           const boost::filesystem::path& new_relative_path,
                                           MetaData& meta_data,
                                           int64_t& reclaimed_space) {
  directory_listing_handler_->RenameElement(old_relative_path,
                                            new_relative_path,
                                            meta_data,
                                            reclaimed_space);
  return;
}

template<typename Storage>
bool DriveInUserSpace<Storage>::TruncateFile(FileContext<Storage>* file_context,
                                             const uint64_t& size) {
  if (!file_context->self_encryptor) {
    file_context->self_encryptor.reset(
        new encrypt::SelfEncryptor<Storage>(file_context->meta_data->data_map, storage_));
  }
  bool result = file_context->self_encryptor->Truncate(size);
  if (result) {
    file_context->content_changed = true;
  }
  return result;
}

// ********************** File / Folder Transfers ******************************

template<typename Storage>
void DriveInUserSpace<Storage>::GetDataMap(const boost::filesystem::path& relative_path,
                                           std::string* serialised_data_map) {
  std::lock_guard<std::mutex> guard(api_mutex_);
  ReadDataMap(relative_path, serialised_data_map);
}

template<typename Storage>
void DriveInUserSpace<Storage>::GetDataMapHidden(const boost::filesystem::path& relative_path,
                                                 std::string* serialised_data_map) {
  std::lock_guard<std::mutex> guard(api_mutex_);
  ReadDataMap(relative_path, serialised_data_map);
}

template<typename Storage>
void DriveInUserSpace<Storage>::ReadDataMap(const boost::filesystem::path& relative_path,
                                            std::string* serialised_data_map) {
  if (relative_path.empty() || !serialised_data_map)
    ThrowError(CommonErrors::invalid_parameter);

  serialised_data_map->clear();
  FileContext<Storage> file_context;
  file_context.meta_data->name = relative_path.filename();
  GetMetaData(relative_path, *file_context.meta_data.get(), nullptr, nullptr);

  if (!file_context.meta_data->data_map)
    ThrowError(CommonErrors::invalid_parameter);

  try {
    encrypt::SerialiseDataMap(*file_context.meta_data->data_map, *serialised_data_map);
  }
  catch(const std::exception& exception) {
    serialised_data_map->clear();
    boost::throw_exception(exception);
  }
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::InsertDataMap(const boost::filesystem::path& relative_path,
                                              const std::string& serialised_data_map) {
  std::lock_guard<std::mutex> guard(api_mutex_);
  LOG(kInfo) << "InsertDataMap - " << relative_path;

  if (relative_path.empty())
    ThrowError(CommonErrors::invalid_parameter);

  FileContext<Storage> file_context(relative_path.filename(), false);
  encrypt::ParseDataMap(serialised_data_map, *file_context.meta_data->data_map);

  SetNewAttributes(&file_context, false, false);

  AddFile(relative_path,
          *file_context.meta_data.get(),
          &file_context.grandparent_directory_id,
          &file_context.parent_directory_id);
  return;
}

// **************************** Hidden Files ***********************************

template<typename Storage>
void DriveInUserSpace<Storage>::ReadHiddenFile(const boost::filesystem::path& relative_path,
                                               std::string* content) {
  if (relative_path.empty() || (relative_path.extension() != kMsHidden) || !content)
    ThrowError(CommonErrors::invalid_parameter);

  FileContext<Storage> file_context;
  file_context.meta_data->name = relative_path.filename();
  GetMetaData(relative_path,
              *file_context.meta_data.get(),
              &file_context.grandparent_directory_id,
              &file_context.parent_directory_id);
  BOOST_ASSERT(!file_context.meta_data->directory_id);

  file_context.self_encryptor.reset(new encrypt::SelfEncryptor<Storage>(
      file_context.meta_data->data_map, storage_));
  if (file_context.self_encryptor->size() > std::numeric_limits<uint32_t>::max())
    ThrowError(CommonErrors::invalid_parameter);

  uint32_t bytes_to_read(static_cast<uint32_t>(file_context.self_encryptor->size()));
  content->resize(bytes_to_read);
  if (!file_context.self_encryptor->Read(const_cast<char*>(content->data()), bytes_to_read, 0))
    ThrowError(CommonErrors::invalid_parameter);

  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::WriteHiddenFile(const boost::filesystem::path &relative_path,
                                                const std::string &content,
                                                bool overwrite_existing) {
  if (relative_path.empty() || (relative_path.extension() != kMsHidden))
    ThrowError(CommonErrors::invalid_parameter);

  boost::filesystem::path hidden_file_path(relative_path);
  // Try getting FileContext to existing
  FileContext<Storage> file_context;
  file_context.meta_data->name = relative_path.filename();
  try {
    GetMetaData(relative_path,
                *file_context.meta_data.get(),
                &file_context.grandparent_directory_id,
                &file_context.parent_directory_id);
    if (!overwrite_existing)
      ThrowError(CommonErrors::invalid_parameter);
  }
  catch(...) {
    // Try adding a new entry if the hidden file doesn't already exist
    file_context = FileContext<Storage>(hidden_file_path.filename(), false);
    AddFile(hidden_file_path,
            *file_context.meta_data.get(),
            &file_context.grandparent_directory_id,
            &file_context.parent_directory_id);
  }

  if (content.size() > std::numeric_limits<uint32_t>::max())
    ThrowError(CommonErrors::invalid_parameter);

  // Write the data
  file_context.self_encryptor.reset(new encrypt::SelfEncryptor<Storage>(
      file_context.meta_data->data_map, storage_));

  if (file_context.self_encryptor->size() > content.size())
    file_context.self_encryptor->Truncate(content.size());
  if (!file_context.self_encryptor->Write(content.c_str(),
                                          static_cast<uint32_t>(content.size()),
                                          0U))
    ThrowError(CommonErrors::invalid_parameter);

  file_context.self_encryptor.reset();
  SetNewAttributes(&file_context, false, false);

  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::DeleteHiddenFile(const boost::filesystem::path &relative_path) {
  if (relative_path.empty() || (relative_path.extension() != kMsHidden))
    ThrowError(CommonErrors::invalid_parameter);
  RemoveFile(relative_path);
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::SearchHiddenFiles(const boost::filesystem::path &relative_path,
                                                  std::vector<std::string> *results) {
  typedef typename DirectoryListingHandler<Storage>::DirectoryType DirectoryType;
  DirectoryType directory(directory_listing_handler_->GetFromPath(relative_path));
  directory.first.listing->GetHiddenChildNames(results);
  return;
}

// ***************************** File Notes ************************************

template<typename Storage>
void DriveInUserSpace<Storage>::GetNotes(const boost::filesystem::path& relative_path,
                                         std::vector<std::string>* notes) {
  LOG(kInfo) << "GetNotes - " << relative_path;
  std::lock_guard<std::mutex> guard(api_mutex_);
  if (relative_path.empty() || !notes)
    ThrowError(CommonErrors::invalid_parameter);

  notes->clear();
  FileContext<Storage> file_context;
  file_context.meta_data->name = relative_path.filename();
  GetMetaData(relative_path, *file_context.meta_data.get(), nullptr, nullptr);
  *notes = file_context.meta_data->notes;
  return;
}

template<typename Storage>
void DriveInUserSpace<Storage>::AddNote(const boost::filesystem::path& relative_path,
                                        const std::string& note) {
  LOG(kInfo) << "AddNote - " << relative_path;
  std::lock_guard<std::mutex> guard(api_mutex_);
  if (relative_path.empty())
    ThrowError(CommonErrors::invalid_parameter);

  FileContext<Storage> file_context;
  file_context.meta_data->name = relative_path.filename();
  GetMetaData(relative_path,
              *file_context.meta_data.get(),
              &file_context.grandparent_directory_id,
              &file_context.parent_directory_id);
  file_context.meta_data->notes.push_back(note);
  UpdateParent(&file_context, relative_path.parent_path());
  return;
}

}  // namespace drive
}  // namespace maidsafe

#endif  // MAIDSAFE_DRIVE_DRIVE_API_H_
