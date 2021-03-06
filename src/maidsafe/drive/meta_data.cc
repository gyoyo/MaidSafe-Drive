/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/drive/meta_data.h"

#include <utility>

#include "boost/algorithm/string/predicate.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/drive/proto_structs.pb.h"
#include "maidsafe/drive/utils.h"


namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace drive {

const uint32_t kAttributesDir = 0x4000;

#ifdef MAIDSAFE_WIN32
namespace {

const uint32_t kAttributesFormat = 0x0FFF;
const uint32_t kAttributesRegular = 0x8000;


FILETIME BptimeToFileTime(bptime::ptime const &ptime) {
  SYSTEMTIME system_time;
  boost::gregorian::date::ymd_type year_month_day = ptime.date().year_month_day();

  system_time.wYear = year_month_day.year;
  system_time.wMonth = year_month_day.month;
  system_time.wDay = year_month_day.day;
  system_time.wDayOfWeek = ptime.date().day_of_week();

  // Now extract the hour/min/second field from time_duration
  bptime::time_duration time_duration = ptime.time_of_day();
  system_time.wHour = static_cast<WORD>(time_duration.hours());
  system_time.wMinute = static_cast<WORD>(time_duration.minutes());
  system_time.wSecond = static_cast<WORD>(time_duration.seconds());

  // Although ptime has a fractional second field, SYSTEMTIME millisecond
  // field is 16 bit, and will not store microsecond. We will treat this
  // field separately later.
  system_time.wMilliseconds = 0;

  // Convert SYSTEMTIME to FILETIME structure
  FILETIME file_time;
  SystemTimeToFileTime(&system_time, &file_time);

  // Now we are almost done. The FILETIME has date, and time. It is
  // only missing fractional second.

  // Extract the raw FILETIME into a 64 bit integer.
  boost::uint64_t hundreds_of_nanosecond_since_1601 = file_time.dwHighDateTime;
  hundreds_of_nanosecond_since_1601 <<= 32;
  hundreds_of_nanosecond_since_1601 |= file_time.dwLowDateTime;

  // Add in the fractional second, which is in microsecond * 10 to get
  // 100s of nanosecond
  hundreds_of_nanosecond_since_1601 += time_duration.fractional_seconds() * 10;

  // Now put the time back inside filetime.
  file_time.dwHighDateTime = hundreds_of_nanosecond_since_1601 >> 32;
  file_time.dwLowDateTime = hundreds_of_nanosecond_since_1601 & 0x00000000FFFFFFFF;

  return file_time;
}

bptime::ptime FileTimeToBptime(FILETIME const &ftime) {
  return bptime::from_ftime<bptime::ptime>(ftime);
}

}  // unnamed namespace
#endif



MetaData::MetaData()
    : name(),
#ifdef MAIDSAFE_WIN32
      end_of_file(0),
      allocation_size(0),
      attributes(0xFFFFFFFF),
      creation_time(),
      last_access_time(),
      last_write_time(),
      data_map(),
      directory_id() {}
#else
      attributes(),
      link_to(),
      data_map(),
      directory_id(),
      notes() {
  attributes.st_gid = getgid();
  attributes.st_uid = getuid();
  attributes.st_mode = 0644;
  attributes.st_nlink = 1;
}
#endif

MetaData::MetaData(const fs::path &name, bool is_directory)
    : name(name),
#ifdef MAIDSAFE_WIN32
      end_of_file(0),
      allocation_size(0),
      attributes(is_directory ? FILE_ATTRIBUTE_DIRECTORY : 0xFFFFFFFF),
      creation_time(),
      last_access_time(),
      last_write_time(),
      data_map(is_directory ? nullptr : std::make_shared<encrypt::DataMap>()),
      directory_id(is_directory ? std::make_shared<DirectoryId>(RandomString(64)) : nullptr),
      notes() {
  FILETIME file_time;
  GetSystemTimeAsFileTime(&file_time);
  creation_time = file_time;
  last_access_time = file_time;
  last_write_time = file_time;
}
#else
      attributes(),
      link_to(),
      data_map(is_directory ? nullptr : std::make_shared<encrypt::DataMap>()),
      directory_id(is_directory ? std::make_shared<DirectoryId>(RandomString(64)) : nullptr),
      notes() {
  attributes.st_gid = getgid();
  attributes.st_uid = getuid();
  attributes.st_mode = 0644;
  attributes.st_nlink = 1;
  attributes.st_ctime = attributes.st_mtime = time(&attributes.st_atime);

  if (is_directory) {
    attributes.st_mode = (0755 | S_IFDIR);
    attributes.st_size = detail::kDirectorySize;
  }
}
#endif

MetaData::MetaData(const MetaData& meta_data)
    : name(meta_data.name),
#ifdef MAIDSAFE_WIN32
      end_of_file(meta_data.end_of_file),
      allocation_size(meta_data.allocation_size),
      attributes(meta_data.attributes),
      creation_time(meta_data.creation_time),
      last_access_time(meta_data.last_access_time),
      last_write_time(meta_data.last_write_time),
#else
      attributes(meta_data.attributes),
      link_to(meta_data.link_to),
#endif
      data_map(nullptr),
      directory_id(nullptr),
      notes(meta_data.notes) {
  if (meta_data.data_map)
    data_map.reset(new encrypt::DataMap(*meta_data.data_map));
  if (meta_data.directory_id)
    directory_id.reset(new DirectoryId(*meta_data.directory_id));
}

MetaData::MetaData(MetaData&& meta_data)
    : name(std::move(meta_data.name)),
#ifdef MAIDSAFE_WIN32
      end_of_file(std::move(meta_data.end_of_file)),
      allocation_size(std::move(meta_data.allocation_size)),
      attributes(std::move(meta_data.attributes)),
      creation_time(std::move(meta_data.creation_time)),
      last_access_time(std::move(meta_data.last_access_time)),
      last_write_time(std::move(meta_data.last_write_time)),
#else
      attributes(std::move(meta_data.attributes)),
      link_to(std::move(meta_data.link_to)),
#endif
      data_map(nullptr),
      directory_id(nullptr),
      notes(std::move(meta_data.notes)) {
  if (meta_data.data_map)
    data_map.reset(new encrypt::DataMap(*meta_data.data_map));
  if (meta_data.directory_id)
    directory_id.reset(new DirectoryId(*meta_data.directory_id));
}

MetaData& MetaData::operator=(MetaData other) {
  swap(*this, other);
  return *this;
}

MetaData::MetaData(const std::string& serialised_meta_data) {
  if (!name.empty())
    ThrowError(CommonErrors::invalid_parameter);

  protobuf::MetaData pb_meta_data;
  if (!pb_meta_data.ParseFromString(serialised_meta_data))
    ThrowError(CommonErrors::parsing_error);

  name = pb_meta_data.name();
  if ((name == "\\") || (name == "/"))
    name = fs::path("/").make_preferred();

  const protobuf::AttributesArchive& attributes_archive = pb_meta_data.attributes_archive();

#ifdef MAIDSAFE_WIN32
  creation_time = BptimeToFileTime(bptime::from_iso_string(attributes_archive.creation_time()));
  last_access_time =
      BptimeToFileTime(bptime::from_iso_string(attributes_archive.last_access_time()));
  last_write_time = BptimeToFileTime(bptime::from_iso_string(attributes_archive.last_write_time()));
  end_of_file = attributes_archive.st_size();

  if ((attributes_archive.st_mode() & kAttributesDir) == kAttributesDir) {
    attributes |= FILE_ATTRIBUTE_DIRECTORY;
    end_of_file = 0;
  }
  allocation_size = end_of_file;

  if (attributes_archive.has_win_attributes())
    attributes = static_cast<DWORD>(attributes_archive.win_attributes());
#else
  if (attributes_archive.has_link_to())
    link_to = attributes_archive.link_to();
  attributes.st_size = attributes_archive.st_size();

  static bptime::ptime epoch(boost::gregorian::date(1970, 1, 1));
  bptime::time_duration diff(
      bptime::from_iso_string(attributes_archive.last_access_time()) - epoch);
  attributes.st_atime = diff.ticks() / diff.ticks_per_second();
  diff = bptime::from_iso_string(attributes_archive.last_write_time()) - epoch;
  attributes.st_mtime = diff.ticks() / diff.ticks_per_second();
  diff = bptime::from_iso_string(attributes_archive.creation_time()) - epoch;
  attributes.st_ctime = diff.ticks() / diff.ticks_per_second();

  attributes.st_mode = attributes_archive.st_mode();

  if (attributes_archive.has_st_dev())
    attributes.st_dev = attributes_archive.st_dev();
  if (attributes_archive.has_st_ino())
    attributes.st_ino = attributes_archive.st_ino();
  if (attributes_archive.has_st_nlink())
    attributes.st_nlink = attributes_archive.st_nlink();
  if (attributes_archive.has_st_uid())
    attributes.st_uid = attributes_archive.st_uid();
  if (attributes_archive.has_st_gid())
    attributes.st_gid = attributes_archive.st_gid();
  if (attributes_archive.has_st_rdev())
    attributes.st_rdev = attributes_archive.st_rdev();
  if (attributes_archive.has_st_blksize())
    attributes.st_blksize = attributes_archive.st_blksize();
  if (attributes_archive.has_st_blocks())
    attributes.st_blocks = attributes_archive.st_blocks();

  if ((attributes_archive.st_mode() & kAttributesDir) == kAttributesDir)
    attributes.st_size = 4096;
#endif

  if (pb_meta_data.has_serialised_data_map()) {
    if (pb_meta_data.has_directory_id())
      ThrowError(CommonErrors::parsing_error);
    data_map.reset(new encrypt::DataMap);
    encrypt::ParseDataMap(pb_meta_data.serialised_data_map(), *data_map);
  } else if (pb_meta_data.has_directory_id()) {
    directory_id.reset(new DirectoryId(pb_meta_data.directory_id()));
  } else {
    ThrowError(CommonErrors::invalid_parameter);
  }

  for (int i(0); i != pb_meta_data.notes_size(); ++i)
    notes.push_back(pb_meta_data.notes(i));
}

std::string MetaData::Serialise() const {
  protobuf::MetaData pb_meta_data;
  pb_meta_data.set_name(name.string());
  protobuf::AttributesArchive* attributes_archive = pb_meta_data.mutable_attributes_archive();

#ifdef MAIDSAFE_WIN32
  attributes_archive->set_creation_time(bptime::to_iso_string(FileTimeToBptime(creation_time)));
  attributes_archive->set_last_access_time(
      bptime::to_iso_string(FileTimeToBptime(last_access_time)));
  attributes_archive->set_last_write_time(bptime::to_iso_string(FileTimeToBptime(last_write_time)));
  attributes_archive->set_st_size(end_of_file);

  uint32_t st_mode(0x01FF);
  st_mode &= kAttributesFormat;
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
    st_mode |= kAttributesDir;
  else
    st_mode |= kAttributesRegular;
  attributes_archive->set_st_mode(st_mode);
  attributes_archive->set_win_attributes(attributes);
#else
  attributes_archive->set_link_to(link_to.string());
  attributes_archive->set_st_size(attributes.st_size);

  attributes_archive->set_last_access_time(
      bptime::to_iso_string(bptime::from_time_t(attributes.st_atime)));
  attributes_archive->set_last_write_time(
      bptime::to_iso_string(bptime::from_time_t(attributes.st_mtime)));
  attributes_archive->set_creation_time(
      bptime::to_iso_string(bptime::from_time_t(attributes.st_ctime)));

  attributes_archive->set_st_dev(attributes.st_dev);
  attributes_archive->set_st_ino(attributes.st_ino);
  attributes_archive->set_st_mode(attributes.st_mode);
  attributes_archive->set_st_nlink(attributes.st_nlink);
  attributes_archive->set_st_uid(attributes.st_uid);
  attributes_archive->set_st_gid(attributes.st_gid);
  attributes_archive->set_st_rdev(attributes.st_rdev);
  attributes_archive->set_st_blksize(attributes.st_blksize);
  attributes_archive->set_st_blocks(attributes.st_blocks);
#endif

  if (data_map) {
    std::string serialised_data_map;
    encrypt::SerialiseDataMap(*data_map, serialised_data_map);
    pb_meta_data.set_serialised_data_map(serialised_data_map);
  } else {
    pb_meta_data.set_directory_id(directory_id->string());
  }

  for (auto note : notes)
    pb_meta_data.add_notes(note);

  return pb_meta_data.SerializeAsString();
}

bptime::ptime MetaData::creation_posix_time() const {
#ifdef MAIDSAFE_WIN32
  return FileTimeToBptime(creation_time);
#else
  return bptime::from_time_t(attributes.st_ctime);
#endif
}

bptime::ptime MetaData::last_write_posix_time() const {
#ifdef MAIDSAFE_WIN32
  return FileTimeToBptime(last_write_time);
#else
  return bptime::from_time_t(attributes.st_mtime);
#endif
}

void MetaData::UpdateLastModifiedTime() {
#ifdef MAIDSAFE_WIN32
  GetSystemTimeAsFileTime(&last_write_time);
#else
  time(&attributes.st_mtime);
#endif
}

uint64_t MetaData::GetAllocatedSize() const {
#ifdef MAIDSAFE_WIN32
  return allocation_size;
#else
  return attributes.st_size;
#endif
}

bool operator<(const MetaData& lhs, const MetaData& rhs) {
  return boost::ilexicographical_compare(lhs.name.wstring(), rhs.name.wstring());
}

void swap(MetaData& lhs, MetaData& rhs) {
  using std::swap;
  swap(lhs.name, rhs.name);
#ifdef MAIDSAFE_WIN32
  swap(lhs.end_of_file, rhs.end_of_file);
  swap(lhs.allocation_size, rhs.allocation_size);
  swap(lhs.attributes, rhs.attributes);
  swap(lhs.creation_time, rhs.creation_time);
  swap(lhs.last_access_time, rhs.last_access_time);
  swap(lhs.last_write_time, rhs.last_write_time);
#else
  swap(lhs.attributes, rhs.attributes);
  swap(lhs.link_to, rhs.link_to);
#endif
  swap(lhs.data_map, rhs.data_map);
  swap(lhs.directory_id, rhs.directory_id);
  swap(lhs.notes, rhs.notes);
}

}  // namespace drive

}  // namespace maidsafe
