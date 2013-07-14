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

#include "maidsafe/drive/directory_listing_handler.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <vector>

#include "boost/algorithm/string/find.hpp"
#include "boost/assert.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/fstream.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/drive/meta_data.h"
#include "maidsafe/drive/directory_listing.h"
#include "maidsafe/drive/return_codes.h"
#include "maidsafe/drive/utils.h"


namespace maidsafe {
namespace drive {

DirectoryListingHandler::DirectoryListingHandler(DataStore& data_store,
                                                 const Keyword& keyword,
                                                 const Pin& pin,
                                                 const Password& password)
    : data_store_(data_store),
      maid_(),
      unique_user_id_(),
      root_parent_id_(),
      relative_root_(fs::path("/").make_preferred()) {
  bool first_run(false);
  passport::Mid::name_type mid_name(passport::Mid::GenerateName(keyword, pin));
  NonEmptyString serialised_mid;
  try {
    serialised_mid = data_store_.Get(mid_name);
  }
  catch(...) {
    first_run = true;
  }

  if (first_run) {
    unique_user_id_ = Identity(RandomString(64));
    root_parent_id_ = Identity(RandomString(64));
    Maid::signer_type maid_signer;
    maid_.reset(new Maid(maid_signer));

    Session session(unique_user_id_, root_parent_id_, maid_);

    NonEmptyString serialised_session(session.Serialise());
    passport::EncryptedSession encrypted_session(passport::detail::EncryptSession(
                                                    keyword, pin, password, serialised_session));
    passport::Tmid tmid(encrypted_session, passport::Antmid());
    passport::EncryptedTmidName encrypted_tmid_name(passport::detail::EncryptTmidName(
                                                      keyword, pin, tmid.name()));
    passport::Mid::name_type mid_name(passport::Mid::GenerateName(keyword, pin));
    passport::Mid mid(mid_name, encrypted_tmid_name, passport::Anmid());
    data_store_.Put(tmid.name(), tmid.Serialise());
    data_store_.Put(mid_name, mid.Serialise());

    MetaData root_meta_data(relative_root_, true);
    DirectoryListingPtr root_parent_directory(new DirectoryListing(root_parent_id_)),
                        root_directory(new DirectoryListing(*root_meta_data.directory_id));
    DirectoryData root_parent(unique_user_id_, root_parent_directory),
                  root(root_parent_id_, root_directory);
    root_parent.listing->AddChild(root_meta_data);
    PutToStorage(root_parent);
    PutToStorage(root);
  } else {
    passport::Mid mid(mid_name, passport::Mid::serialised_type(serialised_mid));
    passport::EncryptedTmidName encrypted_tmid_name(mid.encrypted_tmid_name());
    passport::Tmid::name_type tmid_name(passport::detail::DecryptTmidName(
                                          keyword, pin, encrypted_tmid_name));
    NonEmptyString serialised_tmid(data_store_.Get(tmid_name));
    passport::Tmid tmid(tmid_name, passport::Tmid::serialised_type(serialised_tmid));
    passport::EncryptedSession encrypted_session(tmid.encrypted_session());
    NonEmptyString serialised_session(passport::detail::DecryptSession(
                                        keyword, pin, password, encrypted_session));
    Session session(serialised_session);
    maid_ = session.maid();
    unique_user_id_ = session.unique_user_id();
    root_parent_id_ = session.root_parent_id();
  }
}

DirectoryListingHandler::~DirectoryListingHandler() {}

DirectoryData DirectoryListingHandler::GetFromPath(const fs::path& relative_path) {
  // Get root directory listing.
  DirectoryData directory(RetrieveFromStorage(unique_user_id_, root_parent_id_));
  // Get successive directory listings until found.
  MetaData meta_data;
  bool found_root = false;
  for (auto itr(relative_path.begin()); itr != relative_path.end(); ++itr) {
    // for itr == begin, path is "/" which is wrong for Windows.
    if (itr == relative_path.begin()) {
      directory.listing->GetChild(relative_root_, meta_data);
      found_root = true;
    } else {
      directory.listing->GetChild((*itr), meta_data);
    }

    if (!meta_data.directory_id)
      ThrowError(CommonErrors::invalid_parameter);
    directory = RetrieveFromStorage(directory.listing->directory_id(),
                                    *meta_data.directory_id);
    if (found_root)
      found_root = false;
  }
  return  directory;
}

void DirectoryListingHandler::AddElement(const fs::path& relative_path,
                                         const MetaData& meta_data,
                                         DirectoryId* grandparent_id,
                                         DirectoryId* parent_id) {
  DirectoryData grandparent, parent;
  MetaData parent_meta_data;

  GetParentAndGrandparent(relative_path, &grandparent, &parent, &parent_meta_data);
  parent.listing->AddChild(meta_data);

  if (IsDirectory(meta_data)) {
    DirectoryData directory(parent.listing->directory_id(),
                              DirectoryListingPtr(
                                  new DirectoryListing(*meta_data.directory_id)));
    try {
      PutToStorage(directory);
    }
    catch(const std::exception& exception) {
      parent.listing->RemoveChild(meta_data);
      boost::throw_exception(exception);
    }
  }

  parent_meta_data.UpdateLastModifiedTime();

#ifndef MAIDSAFE_WIN32
  parent_meta_data.attributes.st_ctime = parent_meta_data.attributes.st_mtime;
  if (IsDirectory(meta_data))
    ++parent_meta_data.attributes.st_nlink;
#endif
  grandparent.listing->UpdateChild(parent_meta_data, true);

  try {
    PutToStorage(parent);
  }
  catch(const std::exception& exception) {
    parent.listing->RemoveChild(meta_data);
    boost::throw_exception(exception);
  }

  PutToStorage(grandparent);

  if (grandparent_id)
    *grandparent_id = grandparent.listing->directory_id();
  if (parent_id)
    *parent_id = parent.listing->directory_id();
}

void DirectoryListingHandler::DeleteElement(const fs::path& relative_path, MetaData& meta_data) {
  DirectoryData grandparent, parent;
  MetaData parent_meta_data;
  GetParentAndGrandparent(relative_path, &grandparent, &parent, &parent_meta_data);
  parent.listing->GetChild(relative_path.filename(), meta_data);

  if (IsDirectory(meta_data)) {
    DirectoryData directory(GetFromPath(relative_path));
    DeleteStored(parent.listing->directory_id(), *meta_data.directory_id);
  }

  parent.listing->RemoveChild(meta_data);
  parent_meta_data.UpdateLastModifiedTime();

#ifndef MAIDSAFE_WIN32
  parent_meta_data.attributes.st_ctime = parent_meta_data.attributes.st_mtime;
  if (IsDirectory(meta_data))
    --parent_meta_data.attributes.st_nlink;
#endif

  try {
    grandparent.listing->UpdateChild(parent_meta_data, true);
  }
  catch(...) { /*Non-critical*/ }

#ifndef MAIDSAFE_WIN32
  PutToStorage(grandparent);
#endif
  PutToStorage(parent);

  return;
}

void DirectoryListingHandler::RenameElement(const fs::path& old_relative_path,
                                            const fs::path& new_relative_path,
                                            MetaData& meta_data,
                                            int64_t& reclaimed_space) {
  if (old_relative_path == new_relative_path)
    return;

  if (old_relative_path.parent_path() == new_relative_path.parent_path())
    RenameSameParent(old_relative_path, new_relative_path, meta_data, reclaimed_space);
  else
    RenameDifferentParent(old_relative_path, new_relative_path, meta_data, reclaimed_space);
  return;
}

void DirectoryListingHandler::RenameSameParent(const fs::path& old_relative_path,
                                               const fs::path& new_relative_path,
                                               MetaData& meta_data,
                                               int64_t& reclaimed_space) {
  DirectoryData grandparent, parent;
  MetaData parent_meta_data;
  GetParentAndGrandparent(old_relative_path, &grandparent, &parent, &parent_meta_data);

#ifndef MAIDSAFE_WIN32
  struct stat old;
  old.st_ctime = meta_data.attributes.st_ctime;
  old.st_mtime = meta_data.attributes.st_mtime;
  time(&meta_data.attributes.st_mtime);
  meta_data.attributes.st_ctime = meta_data.attributes.st_mtime;
#endif

  if (!parent.listing->HasChild(new_relative_path.filename())) {
    parent.listing->RemoveChild(meta_data);
    meta_data.name = new_relative_path.filename();
    parent.listing->AddChild(meta_data);
  } else {
    MetaData old_meta_data;
    try {
      parent.listing->GetChild(new_relative_path.filename(), old_meta_data);
    }
    catch(const std::exception& exception) {
#ifndef MAIDSAFE_WIN32
      meta_data.attributes.st_ctime = old.st_ctime;
      meta_data.attributes.st_mtime = old.st_mtime;
#endif
      boost::throw_exception(exception);
    }
    parent.listing->RemoveChild(old_meta_data);
    reclaimed_space = old_meta_data.GetAllocatedSize();
    parent.listing->RemoveChild(meta_data);
    meta_data.name = new_relative_path.filename();
    parent.listing->AddChild(meta_data);
  }

#ifdef MAIDSAFE_WIN32
  GetSystemTimeAsFileTime(&parent_meta_data.last_write_time);
#else
  parent_meta_data.attributes.st_ctime =
      parent_meta_data.attributes.st_mtime =
      meta_data.attributes.st_mtime;
//   if (!same_parent && IsDirectory(meta_data)) {
//     --parent_meta_data.attributes.st_nlink;
//     ++new_parent_meta_data.attributes.st_nlink;
//     new_parent_meta_data.attributes.st_ctime =
//         new_parent_meta_data.attributes.st_mtime =
//         parent_meta_data.attributes.st_mtime;
//   }
#endif
  PutToStorage(parent);

#ifndef MAIDSAFE_WIN32
  try {
    grandparent.first.listing->UpdateChild(parent_meta_data, true);
  }
  catch(...) { /*Non-critical*/ }
  PutToStorage(grandparent);
#endif
  return;
}

void DirectoryListingHandler::RenameDifferentParent(const fs::path& old_relative_path,
                                                    const fs::path& new_relative_path,
                                                    MetaData& meta_data,
                                                    int64_t& reclaimed_space) {
  DirectoryData old_grandparent, old_parent, new_grandparent, new_parent;
  MetaData old_parent_meta_data, new_parent_meta_data;
  GetParentAndGrandparent(old_relative_path,
                          &old_grandparent,
                          &old_parent,
                          &old_parent_meta_data);
  GetParentAndGrandparent(new_relative_path,
                          &new_grandparent,
                          &new_parent,
                          &new_parent_meta_data);
#ifndef MAIDSAFE_WIN32
  struct stat old;
  old.st_ctime = meta_data.attributes.st_ctime;
  old.st_mtime = meta_data.attributes.st_mtime;
  time(&meta_data.attributes.st_mtime);
  meta_data.attributes.st_ctime = meta_data.attributes.st_mtime;
#endif

  if (IsDirectory(meta_data)) {
    DirectoryData directory(GetFromPath(old_relative_path));
    DeleteStored(directory.parent_id, directory.listing->directory_id());
    directory.parent_id = new_parent.listing->directory_id();
    PutToStorage(directory);
  }

  old_parent.listing->RemoveChild(meta_data);

  if (!new_parent.listing->HasChild(new_relative_path.filename())) {
    meta_data.name = new_relative_path.filename();
    new_parent.listing->AddChild(meta_data);
  } else {
    MetaData old_meta_data;
    try {
      new_parent.listing->GetChild(new_relative_path.filename(), old_meta_data);
    }
    catch(const std::exception& exception) {
#ifndef MAIDSAFE_WIN32
      meta_data.attributes.st_ctime = old.st_ctime;
      meta_data.attributes.st_mtime = old.st_mtime;
#endif
      boost::throw_exception(exception);
    }
    new_parent.listing->RemoveChild(old_meta_data);
    reclaimed_space = old_meta_data.GetAllocatedSize();
    meta_data.name = new_relative_path.filename();
    new_parent.listing->AddChild(meta_data);
  }

#ifdef MAIDSAFE_WIN32
  GetSystemTimeAsFileTime(&old_parent_meta_data.last_write_time);
#else
  old_parent_meta_data.attributes.st_ctime =
      old_parent_meta_data.attributes.st_mtime =
      meta_data.attributes.st_mtime;
  if (IsDirectory(meta_data)) {
    --old_parent_meta_data.attributes.st_nlink;
    ++new_parent_meta_data.attributes.st_nlink;
    new_parent_meta_data.attributes.st_ctime =
        new_parent_meta_data.attributes.st_mtime =
        old_parent_meta_data.attributes.st_mtime;
  }
#endif
  PutToStorage(old_parent);
  PutToStorage(new_parent);

#ifndef MAIDSAFE_WIN32
  try {
    old_grandparent.first.listing->UpdateChild(old_parent_meta_data, true);
  }
  catch(...) { /*Non-critical*/ }
  PutToStorage(old_grandparent);
#endif
  return;
}

void DirectoryListingHandler::UpdateParentDirectoryListing(const fs::path& parent_path,
                                                           MetaData meta_data) {
  DirectoryData parent = GetFromPath(parent_path);
  parent.listing->UpdateChild(meta_data, true);
  PutToStorage(parent);
  return;
}

bool DirectoryListingHandler::IsDirectory(const MetaData& meta_data) const {
  return static_cast<bool>(meta_data.directory_id);
}

void DirectoryListingHandler::GetParentAndGrandparent(const fs::path& relative_path,
                                                      DirectoryData* grandparent,
                                                      DirectoryData* parent,
                                                      MetaData* parent_meta_data) {
  *grandparent = GetFromPath(relative_path.parent_path().parent_path());
  grandparent->listing->GetChild(relative_path.parent_path().filename(), *parent_meta_data);
  if (!(parent_meta_data->directory_id)) {
    ThrowError(CommonErrors::invalid_parameter);
  }
  *parent = GetFromPath(relative_path.parent_path());
  return;
}

DirectoryData DirectoryListingHandler::RetrieveFromStorage(const DirectoryId& parent_id,
                                                           const DirectoryId& directory_id) const {
  DataMapPtr data_map(new encrypt::DataMap);
  // Retrieve encrypted datamap.
  RetrieveDataMap(parent_id, directory_id, data_map);
  // Decrypt serialised directory listing.
  encrypt::SelfEncryptor self_encryptor(data_map, data_store_);
  uint32_t data_map_chunks_size(static_cast<uint32_t>(data_map->chunks.size()));
  uint32_t data_map_size;
  if (data_map_chunks_size != 0) {
    data_map_size = (data_map_chunks_size - 1) * data_map->chunks[0].size +
                    data_map->chunks.rbegin()->size;
  } else {
    data_map_size = static_cast<uint32_t>(data_map->content.size());
  }
  std::string serialised_directory_listing(data_map_size, 0);
  if (!self_encryptor.Read(const_cast<char*>(serialised_directory_listing.c_str()),
                           data_map_size,
                           0)) {
    ThrowError(CommonErrors::invalid_parameter);
  }
  // Parse serialised directory listing.
  Identity id(std::string("", 64));
  DirectoryData directory(parent_id, std::make_shared<DirectoryListing>(id));
  directory.listing->Parse(serialised_directory_listing);
  assert(directory.listing->directory_id() == directory_id);
  return directory;
}

void DirectoryListingHandler::PutToStorage(const DirectoryData& directory) {
  // Serialise directory listing.
  std::string serialised_directory_listing;
  directory.listing->Serialise(serialised_directory_listing);

  // Self-encrypt serialised directory listing.
  DataMapPtr data_map(new encrypt::DataMap);
  {
    encrypt::SelfEncryptor self_encryptor(data_map, data_store_);
    assert(serialised_directory_listing.size() <= std::numeric_limits<uint32_t>::max());
    if (!self_encryptor.Write(serialised_directory_listing.c_str(),
                              static_cast<uint32_t>(serialised_directory_listing.size()),
                              0)) {
      ThrowError(CommonErrors::invalid_parameter);
    }
  }
  // Encrypt directory listing's datamap.
  asymm::CipherText encrypted_data_map =
                      encrypt::EncryptDataMap(directory.parent_id,
                                              directory.listing->directory_id(),
                                              data_map);
  // Store the encrypted datamap.
  OwnerDirectory owner_directory(OwnerDirectory::name_type(directory.listing->directory_id()),
                                 encrypted_data_map,
                                 maid_->private_key());
  data_store_.Put(owner_directory.name(), owner_directory.Serialise());
  return;
}

void DirectoryListingHandler::DeleteStored(const DirectoryId& parent_id,
                                           const DirectoryId& directory_id) {
  DataMapPtr data_map(new encrypt::DataMap);
  RetrieveDataMap(parent_id, directory_id, data_map);
  encrypt::SelfEncryptor self_encryptor(data_map, data_store_);
  self_encryptor.DeleteAllChunks();
  data_store_.Delete(OwnerDirectory::name_type(directory_id));
  return;
}

void DirectoryListingHandler::RetrieveDataMap(const DirectoryId& parent_id,
                                              const DirectoryId& directory_id,
                                              DataMapPtr data_map) const {
  assert(data_map);
  OwnerDirectory::name_type name(directory_id);
  OwnerDirectory::serialised_type serialised_data;
  serialised_data.data = data_store_.Get(name);
  // Parse.
  OwnerDirectory owner_directory(name, serialised_data);
  // Generate data map.
  encrypt::DecryptDataMap(parent_id,
                          directory_id,
                          owner_directory.data().string(),
                          data_map);
  return;
}

// If the target is a file it can be deleted.  On POSIX, if it's a non-empty
// directory, it can be deleted.
#ifndef MAIDSAFE_WIN32
bool DirectoryListingHandler::RenameTargetCanBeRemoved(const fs::path& new_relative_path,
                                                       const MetaData& target_meta_data) {
  bool can_be_removed = !IsDirectory(target_meta_data);
  if (!can_be_removed) {
    DirectoryListingPtr target_directory_listing = GetFromPath(new_relative_path).listing;
    if (target_directory_listing)
      can_be_removed = target_directory_listing->empty();
  }
  return can_be_removed;
}
#endif

}  // namespace drive
}  // namespace maidsafe
