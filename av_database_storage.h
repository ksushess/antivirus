#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "scan_engine.h"

namespace antivirus {

enum class AvDatabaseLoadFailure {
    None = 0,
    FileMissing,
    OpenFailed,
    InvalidFormat,
    ManifestSignatureInvalid
};

struct AvDatabaseLoadStats {
    AvDatabaseInfo info;
    std::size_t skippedRecordCount = 0;
    AvDatabaseLoadFailure failure = AvDatabaseLoadFailure::None;
    std::wstring message;
};

bool SaveAvDatabaseToFile(
    const std::wstring& path,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database,
    const AvDatabaseInfo& info,
    std::wstring* errorMessage
);

bool LoadAvDatabaseFromFile(
    const std::wstring& path,
    std::map<std::uint64_t, std::vector<AvRecord>>* database,
    AvDatabaseLoadStats* stats,
    std::wstring* errorMessage
);

bool ExportBuiltInDefaultAvDatabase(
    const std::wstring& path,
    std::wstring* errorMessage
);

} // namespace antivirus
