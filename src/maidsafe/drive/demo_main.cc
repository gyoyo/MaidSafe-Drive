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

#include <functional>
#include <iostream>  // NOLINT
#include <memory>
#include <string>
#include <fstream>  // NOLINT
#include <iterator>

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"
#include "boost/preprocessor/stringize.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/secure_string.h"
#include "maidsafe/encrypt/drive_store.h"

#ifdef WIN32
#  include "maidsafe/drive/win_drive.h"
#else
#  include "maidsafe/drive/unix_drive.h"
#endif
#include "maidsafe/drive/return_codes.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;
typedef maidsafe::passport::detail::Keyword Keyword;
typedef maidsafe::passport::detail::Pin Pin;
typedef maidsafe::passport::detail::Password Password;

namespace maidsafe {
namespace drive {

#ifdef WIN32
typedef CbfsDriveInUserSpace DemoDrive;
#else
typedef FuseDriveInUserSpace DemoDrive;
#endif

typedef std::unique_ptr<DemoDrive> DemoDrivePtr;

int Mount(const fs::path &mount_dir,
          const fs::path &chunk_dir,
          const Keyword& keyword,
          const Pin& pin,
          const Password& password) {
  fs::path data_store_path(chunk_dir / "store");
  DiskUsage disk_usage(1048576000);
  maidsafe::drive_store::DriveStore data_store(data_store_path, disk_usage);

  boost::system::error_code error_code;
  if (!fs::exists(chunk_dir, error_code))
    return error_code.value();

  DemoDrivePtr drive(new DemoDrive(data_store, mount_dir, keyword, pin, password));

#ifdef WIN32
  drive->WaitUntilUnMounted();
  drive->Unmount();
#endif

  return 0;
}

}  // namespace drive
}  // namespace maidsafe


fs::path GetPathFromProgramOption(const std::string &option_name,
                                  po::variables_map *variables_map,
                                  bool must_exist) {
  if (variables_map->count(option_name)) {
    boost::system::error_code error_code;
    fs::path option_path(variables_map->at(option_name).as<std::string>());
    if (must_exist) {
      if (!fs::exists(option_path, error_code) || error_code) {
        LOG(kError) << "Invalid " << option_name << " option.  " << option_path
                    << " doesn't exist or can't be accessed (error message: "
                    << error_code.message() << ")";
        return fs::path();
      }
      if (!fs::is_directory(option_path, error_code) || error_code) {
        LOG(kError) << "Invalid " << option_name << " option.  " << option_path
                    << " is not a directory (error message: "
                    << error_code.message() << ")";
        return fs::path();
      }
    } else {
      if (fs::exists(option_path, error_code)) {
        LOG(kError) << "Invalid " << option_name << " option.  " << option_path
                    << " already exists (error message: "
                    << error_code.message() << ")";
        return fs::path();
      }
    }
    LOG(kInfo) << option_name << " set to " << option_path;
    return option_path;
  } else {
    LOG(kWarning) << "You must set the " << option_name << " option to a"
                 << (must_exist ? "n " : " non-") << "existing directory.";
    return fs::path();
  }
}

std::string GetUserInputFromProgramOption(const std::string &option_name,
                                          po::variables_map *variables_map,
                                          bool must_exist) {
  if (variables_map->count(option_name)) {
    std::string option(variables_map->at(option_name).as<std::string>());
    if (must_exist) {
      if (option.empty()) {
        LOG(kError) << "Invalid " << option_name << " option.  " << option << " empty.";
        return std::string();
      }
    }
    // LOG(kInfo) << option_name << " set to " << option;
    return option;
  } else {
    LOG(kWarning) << "You must set the " << option_name << " option to a non-empty string.";
    return std::string();
  }
}

int main(int argc, char *argv[]) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  boost::system::error_code error_code;
#ifdef WIN32
  fs::path logging_dir("C:\\ProgramData\\MaidSafeDrive\\logs");
#else
  fs::path logging_dir(fs::temp_directory_path(error_code) / "maidsafe_drive/logs");
  if (error_code) {
    LOG(kError) << error_code.message();
    return 1;
  }
#endif
  if (!fs::exists(logging_dir, error_code))
    fs::create_directories(logging_dir, error_code);
  if (error_code)
    LOG(kError) << error_code.message();
  if (!fs::exists(logging_dir, error_code))
    LOG(kError) << "Couldn't create logging directory at " << logging_dir;
  fs::path log_path(logging_dir / "maidsafe_drive");
  // All command line parameters are only for this run. To allow persistance, update the config
  // file. Command line overrides any config file settings.
  try {
    po::options_description options_description("Allowed options");
    options_description.add_options()
        ("help,H", "print this help message")
        ("chunkdir,C", po::value<std::string>(), "set directory to store chunks")
        ("mountdir,D", po::value<std::string>(), "set virtual drive name")
        ("password,P", po::value<std::string>()->default_value(""), "password")
        ("keyword,K", po::value<std::string>()->default_value(""), "keyword")
        ("pin,I", po::value<std::string>()->default_value(""), "pin")
        ("checkdata", "check all data (metadata and chunks)")
        ("start", "start MaidSafeDrive (mount drive) [default]")
        ("stop", "stop MaidSafeDrive (unmount drive) [not implemented]"); // dunno if we can from here!

    po::variables_map variables_map;
    po::store(po::command_line_parser(argc, argv).options(options_description).allow_unregistered().
                                                  run(), variables_map);
    po::notify(variables_map);

    // set up options for config file
    po::options_description config_file_options;
    config_file_options.add(options_description);

    // try open some config options
    std::ifstream local_config_file("maidsafe_drive.conf");
#ifdef WIN32
    fs::path main_config_path("C:/ProgramData/MaidSafeDrive/maidsafe_drive.conf");
#else
    fs::path main_config_path("/etc/maidsafe_drive.conf");
#endif
    std::ifstream main_config_file(main_config_path.string().c_str());

    // try local first for testing
    if (local_config_file) {
      LOG(kInfo) << "Using local config file \"maidsafe_drive.conf\"";
      store(parse_config_file(local_config_file, config_file_options), variables_map);
      notify(variables_map);
    } else if (main_config_file) {
      LOG(kInfo) << "Using main config file " << main_config_path;
      store(parse_config_file(main_config_file, config_file_options), variables_map);
      notify(variables_map);
    } else {
      LOG(kWarning) << "No configuration file found at " << main_config_path;
    }

    if (variables_map.count("help")) {
      LOG(kInfo) << options_description;
      return 1;
    }

    fs::path chunkstore_path(GetPathFromProgramOption("chunkdir", &variables_map, true));
#ifdef WIN32
    fs::path mount_path(GetPathFromProgramOption("mountdir", &variables_map, false));
#else
    fs::path mount_path(GetPathFromProgramOption("mountdir", &variables_map, true));
#endif


    if (variables_map.count("stop")) {
      LOG(kInfo) << "Trying to stop.";
      return 0;
    }

    if (chunkstore_path == fs::path() || mount_path == fs::path()) {
      LOG(kWarning) << options_description;
      return 1;
    }

    std::string keyword_str(GetUserInputFromProgramOption("keyword", &variables_map, true));
    std::string pin_str(GetUserInputFromProgramOption("pin", &variables_map, true));
    std::string password_str(GetUserInputFromProgramOption("password", &variables_map, true));

    if (keyword_str.empty() || pin_str.empty() || password_str.empty()) {
      std::cout << "Enter keyword" << std::endl;
      getline(std::cin, keyword_str);
      std::cout << "Enter pin" << std::endl;
      getline(std::cin, pin_str);
      std::cout << "Enter password" << std::endl;
      getline(std::cin, password_str);
    }

    if (keyword_str.empty() || pin_str.empty() || password_str.empty()) {
      LOG(kError) << options_description;
      return 1;
    }

    Keyword keyword(keyword_str);
    Pin pin(pin_str);
    Password password(password_str);

    int result(maidsafe::drive::Mount(mount_path, chunkstore_path, keyword, pin, password));
    return result;
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    return 1;
  }
  catch(...) {
    LOG(kError) << "Exception of unknown type!";
  }
  return 0;
}
