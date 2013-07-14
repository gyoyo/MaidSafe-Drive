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

#include "maidsafe/drive/utils.h"

#include <regex>
#include <algorithm>

#include "maidsafe/common/log.h"
#include "maidsafe/encrypt/self_encryptor.h"

#include "maidsafe/passport/detail/passport.pb.h"

#include "maidsafe/drive/directory_listing_handler.h"
#include "maidsafe/drive/directory_listing.h"
#include "maidsafe/drive/meta_data.h"
#include "maidsafe/drive/proto_structs.pb.h"

namespace maidsafe {

namespace drive {

FileContext::FileContext()
    : meta_data(new MetaData),
      self_encryptor(),
      content_changed(false),
      grandparent_directory_id(),
      parent_directory_id() {}

FileContext::FileContext(const fs::path& name, bool is_directory)
      : meta_data(new MetaData(name, is_directory)),
        self_encryptor(),
        content_changed(!is_directory),
        grandparent_directory_id(),
        parent_directory_id() {}

FileContext::FileContext(std::shared_ptr<MetaData> meta_data_in)
    : meta_data(meta_data_in),
      self_encryptor(),
      content_changed(false),
      grandparent_directory_id(),
      parent_directory_id() {}


Session::Session(const Identity& unique_user_id,
                 const Identity& root_parent_id,
                 const std::shared_ptr<passport::Maid>& maid)
  : unique_user_id_(unique_user_id),
    root_parent_id_(root_parent_id),
    maid_(maid) {}

Session::Session(const NonEmptyString& serialised_session)
  : unique_user_id_(),
    root_parent_id_(),
    maid_() {
  Parse(serialised_session);
}

NonEmptyString Session::Serialise() {
  protobuf::Session proto_session;

  proto_session.set_unique_user_id(unique_user_id_.string());
  proto_session.set_root_parent_id(root_parent_id_.string());

  passport::detail::protobuf::Passport proto_passport;
  auto proto_fob(proto_passport.add_fob());
  maid_->ToProtobuf(proto_fob);
  proto_session.set_serialised_maid(proto_passport.SerializeAsString());
  return NonEmptyString(proto_session.SerializeAsString());
}

Identity Session::unique_user_id() {
  return unique_user_id_;
}

Identity Session::root_parent_id() {
  return root_parent_id_;
}

std::shared_ptr<passport::Maid> Session::maid() {
  return maid_;
}

void Session::Parse(const NonEmptyString& serialised_session) {
  protobuf::Session proto_session;
  if (!proto_session.ParseFromString(serialised_session.string()) ||
      !proto_session.IsInitialized()) {
    LOG(kError) << "Failed to parse session.";
    ThrowError(CommonErrors::parsing_error);
  }

  unique_user_id_ = Identity(proto_session.unique_user_id());
  root_parent_id_ = Identity(proto_session.root_parent_id());

  passport::detail::protobuf::Passport proto_passport;
  if (!proto_passport.ParseFromString(proto_session.serialised_maid()) ||
      !proto_passport.IsInitialized()) {
    LOG(kError) << "Failed to parse maid.";
    ThrowError(CommonErrors::parsing_error);
  }

  maid_.reset(new passport::Maid(proto_passport.fob(0)));
}

#ifndef MAIDSAFE_WIN32
// Not called by Windows...
int ForceFlush(DirectoryListingHandlerPtr directory_listing_handler, FileContext* file_context) {
  BOOST_ASSERT(file_context);
  file_context->self_encryptor->Flush();

  try {
    directory_listing_handler->UpdateParentDirectoryListing(
        file_context->meta_data->name.parent_path(), *file_context->meta_data.get());
  } catch(...) {
      return kFailedToSaveParentDirectoryListing;
  }
  return kSuccess;
}
#endif

bool ExcludedFilename(const fs::path& path) {
  std::string file_name(path.filename().stem().string());
  if (file_name.size() == 4 && isdigit(file_name[3])) {
    if (file_name[3] != '0') {
      std::string name(file_name.substr(0, 3));
      std::transform(name.begin(), name.end(), name.begin(), tolower);
      if (name.compare(0, 3, "com", 0, 3) == 0) {
        return true;
      }
      if (name.compare(0, 3, "lpt", 0, 3) == 0) {
        return true;
      }
    }
  } else if (file_name.size() == 3) {
    std::string name(file_name);
    std::transform(name.begin(), name.end(), name.begin(), tolower);
    if (name.compare(0, 3, "con", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "prn", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "aux", 0, 3) == 0) {
      return true;
    }
    if (name.compare(0, 3, "nul", 0, 3) == 0) {
      return true;
    }
  } else if (file_name.size() == 6) {
    if (file_name[5] == '$') {
      std::string name(file_name);
      std::transform(name.begin(), name.end(), name.begin(), tolower);
      if (name.compare(0, 5, "clock", 0, 5) == 0) {
        return true;
      }
    }
  }
  static const std::string excluded = "\"\\/<>?:*|";
  std::string::const_iterator first(file_name.begin()), last(file_name.end());
  for (; first != last; ++first) {
    if (find(excluded.begin(), excluded.end(), *first) != excluded.end())
      return true;
  }
  return false;
}

bool MatchesMask(std::wstring mask, const fs::path& file_name) {
#ifdef MAIDSAFE_WIN32
  static const std::wstring kNeedEscaped(L".[]{}()+|^$");
#else
  #ifdef MAIDSAFE_APPLE
  static const std::wstring kNeedEscaped(L".]{}()+|^$");
  #else
  static const std::wstring kNeedEscaped(L".{}()+|^$");
  #endif
#endif
  static const std::wstring kEscape(L"\\");
  try {
    // Apply escapes
    std::for_each(kNeedEscaped.begin(), kNeedEscaped.end(), [&mask](wchar_t i) {
      boost::replace_all(mask, std::wstring(1, i), kEscape + std::wstring(1, i));
    });

    // Apply wildcards
    boost::replace_all(mask, L"*", L".*");
    boost::replace_all(mask, L"?", L".");

    // Check for match
    std::wregex reg_ex(mask, std::regex_constants::icase);
    return std::regex_match(file_name.wstring(), reg_ex);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what() << " - file_name: " << file_name << ", mask: "
                << std::string(mask.begin(), mask.end());
    return false;
  }
}

bool SearchesMask(std::wstring mask, const fs::path& file_name) {
  static const std::wstring kNeedEscaped(L".[]{}()+|^$");
  static const std::wstring kEscape(L"\\");
  try {
    // Apply escapes
    std::for_each(kNeedEscaped.begin(), kNeedEscaped.end(), [&mask](wchar_t i) {
      boost::replace_all(mask, std::wstring(1, i), kEscape + std::wstring(1, i));
    });

    // Apply wildcards
    boost::replace_all(mask, L"*", L".*");
    boost::replace_all(mask, L"?", L".");

    // Check for match
    std::wregex reg_ex(mask, std::regex_constants::icase);
    return std::regex_search(file_name.wstring(), reg_ex);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what() << " - file_name: " << file_name << ", mask: "
                << std::string(mask.begin(), mask.end());
    return false;
  }
}

}  // namespace drive

}  // namespace maidsafe
