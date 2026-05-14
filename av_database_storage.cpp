#include "av_database_storage.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace antivirus {
namespace {

constexpr std::array<char, 8> kDatabaseMagic = { 'A', 'V', 'D', 'B', '0', '0', '0', '1' };
constexpr std::uint32_t kDatabaseVersion = 1;

struct DiskDatabaseHeader {
    char magic[8] = {};
    std::uint32_t version = 0;
    std::uint32_t releaseDateSize = 0;
    std::uint32_t recordCount = 0;
    std::uint32_t manifestSignatureSize = 0;
};

template <typename T>
void AppendLittleEndian(std::vector<std::uint8_t>* target, T value) {
    if (!target) {
        return;
    }

    for (std::size_t index = 0; index < sizeof(T); ++index) {
        target->push_back(static_cast<std::uint8_t>((value >> (index * 8)) & 0xFF));
    }
}

template <typename T>
bool ReadLittleEndian(
    const std::vector<std::uint8_t>& source,
    std::size_t* offset,
    T* value
) {
    if (!offset || !value) {
        return false;
    }

    if (*offset + sizeof(T) > source.size()) {
        return false;
    }

    T result = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        result |= static_cast<T>(source[*offset + index]) << (index * 8);
    }

    *offset += sizeof(T);
    *value = result;
    return true;
}

bool ComputeSha256(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>* hash) {
    if (!hash) {
        return false;
    }

    hash->clear();

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    PUCHAR objectBuffer = nullptr;
    DWORD objectBufferSize = 0;
    DWORD hashSize = 0;
    DWORD bytesWritten = 0;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        goto cleanup;
    }

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectBufferSize),
            sizeof(objectBufferSize),
            &bytesWritten,
            0) != 0) {
        goto cleanup;
    }

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashSize),
            sizeof(hashSize),
            &bytesWritten,
            0) != 0) {
        goto cleanup;
    }

    objectBuffer = static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, objectBufferSize));
    if (!objectBuffer) {
        goto cleanup;
    }

    hash->resize(hashSize);
    if (BCryptCreateHash(algorithm, &hashHandle, objectBuffer, objectBufferSize, nullptr, 0, 0) != 0) {
        goto cleanup;
    }

    if (size > 0 && BCryptHashData(hashHandle, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0) {
        goto cleanup;
    }

    if (BCryptFinishHash(hashHandle, hash->data(), hashSize, 0) != 0) {
        goto cleanup;
    }

    ok = true;

cleanup:
    if (!ok) {
        hash->clear();
    }
    if (hashHandle) {
        BCryptDestroyHash(hashHandle);
    }
    if (objectBuffer) {
        HeapFree(GetProcessHeap(), 0, objectBuffer);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }

    return ok;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string utf8(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, utf8.data(), size, nullptr, nullptr);
    return utf8;
}

std::wstring Utf8ToWide(const std::vector<std::uint8_t>& value) {
    if (value.empty()) {
        return L"";
    }

    const int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(value.data()),
        static_cast<int>(value.size()),
        nullptr,
        0
    );
    if (size <= 0) {
        return L"";
    }

    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(value.data()),
        static_cast<int>(value.size()),
        wide.data(),
        size
    );
    return wide;
}

bool EnsureParentDirectoryExists(const std::wstring& path, std::wstring* errorMessage) {
    std::error_code error;
    const std::filesystem::path parentPath = std::filesystem::path(path).parent_path();
    if (parentPath.empty()) {
        return true;
    }

    std::filesystem::create_directories(parentPath, error);
    if (error) {
        if (errorMessage) {
            *errorMessage = L"Unable to create the antivirus bases directory.";
        }
        return false;
    }
    return true;
}

bool BuildRecordSignaturePayload(const AvRecord& record, std::vector<std::uint8_t>* payload) {
    if (!payload) {
        return false;
    }

    payload->clear();
    AppendLittleEndian(payload, record.objectSignaturePrefix);
    AppendLittleEndian(payload, record.objectSignatureLength);
    payload->insert(payload->end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendLittleEndian(payload, record.offsetBegin);
    AppendLittleEndian(payload, record.offsetEnd);
    AppendLittleEndian(payload, static_cast<std::uint32_t>(record.objectType));
    return true;
}

bool SerializeRecord(const AvRecord& record, std::vector<std::uint8_t>* bytes, std::wstring* errorMessage) {
    if (!bytes) {
        return false;
    }

    const std::string threatNameUtf8 = WideToUtf8(record.threatName);
    if (record.objectSignature.size() > 0xFFFFFFFFu ||
        record.avRecordSignature.size() > 0xFFFFFFFFu ||
        threatNameUtf8.size() > 0xFFFFFFFFu) {
        if (errorMessage) {
            *errorMessage = L"One of the antivirus records is too large to save.";
        }
        return false;
    }

    AppendLittleEndian(bytes, record.objectSignaturePrefix);
    AppendLittleEndian(bytes, record.objectSignatureLength);
    AppendLittleEndian(bytes, static_cast<std::uint32_t>(record.objectSignature.size()));
    AppendLittleEndian(bytes, record.offsetBegin);
    AppendLittleEndian(bytes, record.offsetEnd);
    AppendLittleEndian(bytes, static_cast<std::uint32_t>(record.objectType));
    AppendLittleEndian(bytes, static_cast<std::uint32_t>(threatNameUtf8.size()));
    AppendLittleEndian(bytes, static_cast<std::uint32_t>(record.avRecordSignature.size()));

    bytes->insert(bytes->end(), record.objectSignature.begin(), record.objectSignature.end());
    bytes->insert(bytes->end(), threatNameUtf8.begin(), threatNameUtf8.end());
    bytes->insert(bytes->end(), record.avRecordSignature.begin(), record.avRecordSignature.end());
    return true;
}

bool VerifyRecordSignature(const AvRecord& record) {
    std::vector<std::uint8_t> payload;
    if (!BuildRecordSignaturePayload(record, &payload)) {
        return false;
    }

    std::vector<std::uint8_t> expectedSignature;
    if (!ComputeSha256(payload.data(), payload.size(), &expectedSignature)) {
        return false;
    }

    return expectedSignature == record.avRecordSignature;
}

bool BuildManifestPayload(
    const AvDatabaseInfo& info,
    const std::vector<std::uint8_t>& serializedRecords,
    std::vector<std::uint8_t>* payload,
    std::wstring* errorMessage
) {
    if (!payload) {
        return false;
    }

    payload->clear();
    const std::string releaseDateUtf8 = WideToUtf8(info.releaseDate);
    if (releaseDateUtf8.size() > 0xFFFFFFFFu) {
        if (errorMessage) {
            *errorMessage = L"Database release date is too large to save.";
        }
        return false;
    }

    AppendLittleEndian(payload, static_cast<std::uint32_t>(releaseDateUtf8.size()));
    payload->insert(payload->end(), releaseDateUtf8.begin(), releaseDateUtf8.end());
    AppendLittleEndian(payload, static_cast<std::uint32_t>(info.recordCount));
    payload->insert(payload->end(), serializedRecords.begin(), serializedRecords.end());
    return true;
}

bool ParseSingleRecord(
    const std::vector<std::uint8_t>& bytes,
    std::size_t* offset,
    AvRecord* record
) {
    if (!offset || !record) {
        return false;
    }

    std::uint32_t objectSignatureBytes = 0;
    std::uint32_t threatNameBytes = 0;
    std::uint32_t avRecordSignatureBytes = 0;
    std::uint32_t objectTypeValue = 0;

    if (!ReadLittleEndian(bytes, offset, &record->objectSignaturePrefix) ||
        !ReadLittleEndian(bytes, offset, &record->objectSignatureLength) ||
        !ReadLittleEndian(bytes, offset, &objectSignatureBytes) ||
        !ReadLittleEndian(bytes, offset, &record->offsetBegin) ||
        !ReadLittleEndian(bytes, offset, &record->offsetEnd) ||
        !ReadLittleEndian(bytes, offset, &objectTypeValue) ||
        !ReadLittleEndian(bytes, offset, &threatNameBytes) ||
        !ReadLittleEndian(bytes, offset, &avRecordSignatureBytes)) {
        return false;
    }

    if (*offset + objectSignatureBytes + threatNameBytes + avRecordSignatureBytes > bytes.size()) {
        return false;
    }

    record->objectType = static_cast<ScanObjectType>(objectTypeValue);
    record->objectSignature.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset + objectSignatureBytes)
    );
    *offset += objectSignatureBytes;

    const std::vector<std::uint8_t> threatNameUtf8(
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset + threatNameBytes)
    );
    record->threatName = Utf8ToWide(threatNameUtf8);
    *offset += threatNameBytes;

    record->avRecordSignature.assign(
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(*offset + avRecordSignatureBytes)
    );
    *offset += avRecordSignatureBytes;

    return true;
}

} // namespace

bool SaveAvDatabaseToFile(
    const std::wstring& path,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database,
    const AvDatabaseInfo& info,
    std::wstring* errorMessage
) {
    if (errorMessage) {
        errorMessage->clear();
    }

    if (!EnsureParentDirectoryExists(path, errorMessage)) {
        return false;
    }

    std::vector<std::uint8_t> recordBytes;
    long recordCount = 0;
    for (const auto& [_, records] : database) {
        for (const AvRecord& record : records) {
            if (!SerializeRecord(record, &recordBytes, errorMessage)) {
                return false;
            }
            ++recordCount;
        }
    }

    AvDatabaseInfo normalizedInfo = info;
    normalizedInfo.recordCount = recordCount;

    std::vector<std::uint8_t> manifestPayload;
    if (!BuildManifestPayload(normalizedInfo, recordBytes, &manifestPayload, errorMessage)) {
        return false;
    }

    std::vector<std::uint8_t> manifestSignature;
    if (!ComputeSha256(manifestPayload.data(), manifestPayload.size(), &manifestSignature)) {
        if (errorMessage) {
            *errorMessage = L"Unable to compute the manifest signature.";
        }
        return false;
    }

    const std::string releaseDateUtf8 = WideToUtf8(normalizedInfo.releaseDate);
    DiskDatabaseHeader header = {};
    std::memcpy(header.magic, kDatabaseMagic.data(), kDatabaseMagic.size());
    header.version = kDatabaseVersion;
    header.releaseDateSize = static_cast<std::uint32_t>(releaseDateUtf8.size());
    header.recordCount = static_cast<std::uint32_t>(recordCount);
    header.manifestSignatureSize = static_cast<std::uint32_t>(manifestSignature.size());

    std::ofstream stream(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        if (errorMessage) {
            *errorMessage = L"Unable to open the antivirus database file for writing.";
        }
        return false;
    }

    stream.write(reinterpret_cast<const char*>(&header), sizeof(header));
    stream.write(releaseDateUtf8.data(), static_cast<std::streamsize>(releaseDateUtf8.size()));
    stream.write(
        reinterpret_cast<const char*>(manifestSignature.data()),
        static_cast<std::streamsize>(manifestSignature.size())
    );
    if (!recordBytes.empty()) {
        stream.write(reinterpret_cast<const char*>(recordBytes.data()), static_cast<std::streamsize>(recordBytes.size()));
    }

    if (!stream.good()) {
        if (errorMessage) {
            *errorMessage = L"Unable to write the antivirus database file.";
        }
        return false;
    }

    return true;
}

bool LoadAvDatabaseFromFile(
    const std::wstring& path,
    std::map<std::uint64_t, std::vector<AvRecord>>* database,
    AvDatabaseLoadStats* stats,
    std::wstring* errorMessage
) {
    if (database) {
        database->clear();
    }
    if (stats) {
        *stats = {};
    }
    if (errorMessage) {
        errorMessage->clear();
    }

    std::ifstream stream(std::filesystem::path(path), std::ios::binary);
    if (!stream.is_open()) {
        if (stats) {
            stats->failure = std::filesystem::exists(std::filesystem::path(path))
                ? AvDatabaseLoadFailure::OpenFailed
                : AvDatabaseLoadFailure::FileMissing;
            stats->message = L"Unable to open the antivirus database file.";
        }
        if (errorMessage) {
            *errorMessage = L"Unable to open the antivirus database file.";
        }
        return false;
    }

    DiskDatabaseHeader header = {};
    stream.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!stream.good() ||
        std::memcmp(header.magic, kDatabaseMagic.data(), kDatabaseMagic.size()) != 0 ||
        header.version != kDatabaseVersion) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::InvalidFormat;
            stats->message = L"Antivirus database format is invalid.";
        }
        if (errorMessage) {
            *errorMessage = L"Antivirus database format is invalid.";
        }
        return false;
    }

    std::vector<std::uint8_t> releaseDateUtf8(header.releaseDateSize);
    if (header.releaseDateSize > 0) {
        stream.read(reinterpret_cast<char*>(releaseDateUtf8.data()), static_cast<std::streamsize>(releaseDateUtf8.size()));
    }

    std::vector<std::uint8_t> manifestSignature(header.manifestSignatureSize);
    if (header.manifestSignatureSize > 0) {
        stream.read(
            reinterpret_cast<char*>(manifestSignature.data()),
            static_cast<std::streamsize>(manifestSignature.size())
        );
    }

    std::vector<char> rawRecordBytes(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>()
    );
    const std::vector<std::uint8_t> recordBytes(rawRecordBytes.begin(), rawRecordBytes.end());

    if (!stream.eof() && stream.fail()) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::InvalidFormat;
            stats->message = L"Antivirus database file is truncated.";
        }
        if (errorMessage) {
            *errorMessage = L"Antivirus database file is truncated.";
        }
        return false;
    }

    AvDatabaseInfo info;
    info.isLoaded = true;
    info.recordCount = static_cast<long>(header.recordCount);
    info.releaseDate = Utf8ToWide(releaseDateUtf8);

    std::vector<std::uint8_t> manifestPayload;
    if (!BuildManifestPayload(info, recordBytes, &manifestPayload, errorMessage)) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::InvalidFormat;
            stats->message = errorMessage ? *errorMessage : L"Antivirus database manifest is invalid.";
        }
        return false;
    }

    std::vector<std::uint8_t> expectedManifestSignature;
    if (!ComputeSha256(manifestPayload.data(), manifestPayload.size(), &expectedManifestSignature)) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::InvalidFormat;
            stats->message = L"Unable to verify the manifest signature.";
        }
        if (errorMessage) {
            *errorMessage = L"Unable to verify the manifest signature.";
        }
        return false;
    }

    if (expectedManifestSignature != manifestSignature) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::ManifestSignatureInvalid;
            stats->message = L"Manifest signature verification failed.";
        }
        if (errorMessage) {
            *errorMessage = L"Manifest signature verification failed.";
        }
        return false;
    }

    std::map<std::uint64_t, std::vector<AvRecord>> loadedDatabase;
    std::size_t offset = 0;
    std::size_t skippedRecordCount = 0;
    for (std::uint32_t index = 0; index < header.recordCount; ++index) {
        AvRecord record;
        if (!ParseSingleRecord(recordBytes, &offset, &record)) {
            if (stats) {
                stats->failure = AvDatabaseLoadFailure::InvalidFormat;
                stats->message = L"Unable to parse one of the antivirus database records.";
            }
            if (errorMessage) {
                *errorMessage = L"Unable to parse one of the antivirus database records.";
            }
            return false;
        }

        if (!VerifyRecordSignature(record)) {
            ++skippedRecordCount;
            continue;
        }

        loadedDatabase[record.objectSignaturePrefix].push_back(std::move(record));
    }

    if (offset != recordBytes.size()) {
        if (stats) {
            stats->failure = AvDatabaseLoadFailure::InvalidFormat;
            stats->message = L"Antivirus database file contains trailing or malformed record data.";
        }
        if (errorMessage) {
            *errorMessage = L"Antivirus database file contains trailing or malformed record data.";
        }
        return false;
    }

    long loadedCount = 0;
    for (const auto& [_, records] : loadedDatabase) {
        loadedCount += static_cast<long>(records.size());
    }

    info.recordCount = loadedCount;
    info.isLoaded = true;

    if (database) {
        *database = std::move(loadedDatabase);
    }
    if (stats) {
        stats->info = info;
        stats->skippedRecordCount = skippedRecordCount;
        stats->failure = AvDatabaseLoadFailure::None;
        stats->message = skippedRecordCount == 0
            ? L"Antivirus database loaded successfully."
            : (L"Antivirus database loaded successfully. Skipped records: " + std::to_wstring(skippedRecordCount));
    }

    return true;
}

bool ExportBuiltInDefaultAvDatabase(
    const std::wstring& path,
    std::wstring* errorMessage
) {
    std::map<std::uint64_t, std::vector<AvRecord>> database;
    AvDatabaseInfo info;
    if (!BuildDemoAvDatabase(&database, &info, errorMessage)) {
        return false;
    }

    return SaveAvDatabaseToFile(path, database, info, errorMessage);
}

} // namespace antivirus
