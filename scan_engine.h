#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace antivirus {

enum class ScanObjectType : std::uint32_t {
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2
};

struct AvRecord {
    std::uint64_t objectSignaturePrefix = 0;
    std::uint32_t objectSignatureLength = 0;
    std::vector<std::uint8_t> objectSignature;
    std::uint64_t offsetBegin = 0;
    std::uint64_t offsetEnd = 0;
    ScanObjectType objectType = ScanObjectType::Unknown;
    std::vector<std::uint8_t> avRecordSignature;
    std::wstring threatName;
};

struct AvDatabaseInfo {
    bool isLoaded = false;
    long recordCount = 0;
    std::wstring releaseDate;
};

class IByteStream {
public:
    virtual ~IByteStream() = default;

    virtual std::uint64_t GetSize() const = 0;
    virtual bool ReadAt(std::uint64_t offset, void* buffer, std::size_t size) = 0;
};

class FileByteStream final : public IByteStream {
public:
    explicit FileByteStream(const std::wstring& path);
    ~FileByteStream() override;

    bool IsOpen() const;

    std::uint64_t GetSize() const override;
    bool ReadAt(std::uint64_t offset, void* buffer, std::size_t size) override;

private:
    std::uint64_t size_ = 0;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

struct ScanResult {
    bool success = false;
    bool malicious = false;
    std::wstring path;
    ScanObjectType objectType = ScanObjectType::Unknown;
    std::uint64_t matchedOffset = 0;
    std::wstring threatName;
    std::wstring message;
};

bool BuildDemoAvDatabase(
    std::map<std::uint64_t, std::vector<AvRecord>>* database,
    AvDatabaseInfo* info,
    std::wstring* errorMessage
);

ScanObjectType DetectObjectType(const std::wstring& path, IByteStream* stream = nullptr);
const wchar_t* ObjectTypeToDisplayName(ScanObjectType type);

ScanResult ScanByteStream(
    const std::wstring& displayPath,
    IByteStream* stream,
    ScanObjectType objectType,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database
);

ScanResult ScanFileWithDatabase(
    const std::wstring& path,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database
);

} // namespace antivirus
