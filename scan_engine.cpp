#include "scan_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <queue>
#include <string>

#pragma comment(lib, "bcrypt.lib")

namespace antivirus {
namespace {

constexpr wchar_t kDemoDatabaseReleaseDate[] = L"2026-05-11";
constexpr std::size_t kPrefixBytes = sizeof(std::uint64_t);
constexpr std::size_t kScanChunkBytes = 64 * 1024;

struct AhoNode {
    std::array<int, 256> next = {};
    int failure = 0;
    std::vector<std::uint64_t> outputs;

    AhoNode() {
        next.fill(-1);
    }
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

std::uint64_t PrefixToKey(const std::uint8_t* bytes) {
    std::uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
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

std::vector<std::uint8_t> AsciiBytes(const std::string& value) {
    return std::vector<std::uint8_t>(value.begin(), value.end());
}

std::wstring ToLowerCopy(const std::wstring& value) {
    std::wstring lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return lowered;
}

bool CreateRecord(
    const std::wstring& threatName,
    const std::vector<std::uint8_t>& signatureBytes,
    ScanObjectType objectType,
    std::uint64_t offsetBegin,
    std::uint64_t offsetEnd,
    AvRecord* record,
    std::wstring* errorMessage
) {
    if (!record) {
        return false;
    }

    if (signatureBytes.size() < sizeof(std::uint64_t)) {
        if (errorMessage) {
            *errorMessage = L"Demo signature is shorter than 8 bytes.";
        }
        return false;
    }

    record->objectSignaturePrefix = PrefixToKey(signatureBytes.data());
    record->objectSignatureLength = static_cast<std::uint32_t>(signatureBytes.size());
    record->offsetBegin = offsetBegin;
    record->offsetEnd = offsetEnd;
    record->objectType = objectType;
    record->threatName = threatName;

    if (!ComputeSha256(signatureBytes.data(), signatureBytes.size(), &record->objectSignature)) {
        if (errorMessage) {
            *errorMessage = L"Unable to compute the demo object signature hash.";
        }
        return false;
    }

    std::vector<std::uint8_t> signaturePayload;
    AppendLittleEndian(&signaturePayload, record->objectSignaturePrefix);
    AppendLittleEndian(&signaturePayload, record->objectSignatureLength);
    signaturePayload.insert(signaturePayload.end(), record->objectSignature.begin(), record->objectSignature.end());
    AppendLittleEndian(&signaturePayload, record->offsetBegin);
    AppendLittleEndian(&signaturePayload, record->offsetEnd);
    AppendLittleEndian(&signaturePayload, static_cast<std::uint32_t>(record->objectType));

    if (!ComputeSha256(signaturePayload.data(), signaturePayload.size(), &record->avRecordSignature)) {
        if (errorMessage) {
            *errorMessage = L"Unable to compute the demo AV record signature.";
        }
        return false;
    }

    return true;
}

bool AddDemoRecord(
    std::map<std::uint64_t, std::vector<AvRecord>>* database,
    const std::wstring& threatName,
    const std::string& signatureText,
    ScanObjectType objectType,
    std::uint64_t offsetBegin,
    std::uint64_t offsetEnd,
    std::wstring* errorMessage
) {
    if (!database) {
        return false;
    }

    AvRecord record;
    if (!CreateRecord(
            threatName,
            AsciiBytes(signatureText),
            objectType,
            offsetBegin,
            offsetEnd,
            &record,
            errorMessage)) {
        return false;
    }

    (*database)[record.objectSignaturePrefix].push_back(std::move(record));
    return true;
}

bool ReadPrefix(IByteStream* stream, std::uint64_t offset, std::uint8_t* buffer) {
    return stream && buffer && stream->ReadAt(offset, buffer, sizeof(std::uint64_t));
}

std::array<std::uint8_t, kPrefixBytes> KeyToBytes(std::uint64_t key) {
    std::array<std::uint8_t, kPrefixBytes> bytes = {};
    std::memcpy(bytes.data(), &key, sizeof(key));
    return bytes;
}

std::vector<AhoNode> BuildPrefixAutomaton(const std::map<std::uint64_t, std::vector<AvRecord>>& database) {
    std::vector<AhoNode> nodes(1);

    for (const auto& [prefixKey, _] : database) {
        const auto pattern = KeyToBytes(prefixKey);
        std::size_t state = 0;
        for (std::uint8_t byte : pattern) {
            if (nodes[state].next[byte] == -1) {
                nodes[state].next[byte] = static_cast<int>(nodes.size());
                nodes.emplace_back();
            }
            state = static_cast<std::size_t>(nodes[state].next[byte]);
        }
        nodes[state].outputs.push_back(prefixKey);
    }

    std::queue<std::size_t> queue;
    for (std::size_t byte = 0; byte < 256; ++byte) {
        const int nextState = nodes[0].next[byte];
        if (nextState != -1) {
            nodes[static_cast<std::size_t>(nextState)].failure = 0;
            queue.push(static_cast<std::size_t>(nextState));
        } else {
            nodes[0].next[byte] = 0;
        }
    }

    while (!queue.empty()) {
        const std::size_t state = queue.front();
        queue.pop();

        for (std::size_t byte = 0; byte < 256; ++byte) {
            const int nextState = nodes[state].next[byte];
            if (nextState == -1) {
                nodes[state].next[byte] = nodes[static_cast<std::size_t>(nodes[state].failure)].next[byte];
                continue;
            }

            queue.push(static_cast<std::size_t>(nextState));
            const std::size_t failureState = static_cast<std::size_t>(nodes[state].failure);
            nodes[static_cast<std::size_t>(nextState)].failure = nodes[failureState].next[byte];
            const auto& failureOutputs = nodes[static_cast<std::size_t>(nodes[static_cast<std::size_t>(nextState)].failure)].outputs;
            nodes[static_cast<std::size_t>(nextState)].outputs.insert(
                nodes[static_cast<std::size_t>(nextState)].outputs.end(),
                failureOutputs.begin(),
                failureOutputs.end()
            );
        }
    }

    return nodes;
}

bool RecordMatchesAtOffset(
    IByteStream* stream,
    std::uint64_t fileSize,
    std::uint64_t offset,
    ScanObjectType objectType,
    const AvRecord& record,
    std::wstring* errorMessage
) {
    if (!stream) {
        if (errorMessage) {
            *errorMessage = L"The scan stream is not available.";
        }
        return false;
    }

    if (record.objectType != objectType) {
        return false;
    }

    if (offset < record.offsetBegin || offset > record.offsetEnd) {
        return false;
    }

    if (record.objectSignatureLength < kPrefixBytes) {
        return false;
    }

    const std::uint64_t signatureLength = record.objectSignatureLength;
    if (offset + signatureLength > fileSize) {
        return false;
    }

    std::vector<std::uint8_t> candidateSignature(static_cast<std::size_t>(signatureLength));
    if (!stream->ReadAt(offset, candidateSignature.data(), candidateSignature.size())) {
        if (errorMessage) {
            *errorMessage = L"Unable to read the complete signature candidate from the scan stream.";
        }
        return false;
    }

    std::vector<std::uint8_t> candidateHash;
    if (!ComputeSha256(candidateSignature.data(), candidateSignature.size(), &candidateHash)) {
        if (errorMessage) {
            *errorMessage = L"Unable to compute the object signature hash during scanning.";
        }
        return false;
    }

    return candidateHash == record.objectSignature;
}

} // namespace

class FileByteStream::Impl {
public:
    explicit Impl(const std::wstring& path)
        : stream(std::filesystem::path(path), std::ios::binary) {
        if (!stream.is_open()) {
            return;
        }

        stream.seekg(0, std::ios::end);
        const std::streamoff endPosition = stream.tellg();
        if (endPosition <= 0) {
            size = 0;
        } else {
            size = static_cast<std::uint64_t>(endPosition);
        }
        stream.seekg(0, std::ios::beg);
    }

    std::ifstream stream;
    std::uint64_t size = 0;
};

FileByteStream::FileByteStream(const std::wstring& path)
    : impl_(std::make_unique<Impl>(path)) {
    if (impl_) {
        size_ = impl_->size;
    }
}

FileByteStream::~FileByteStream() = default;

bool FileByteStream::IsOpen() const {
    return impl_ && impl_->stream.is_open();
}

std::uint64_t FileByteStream::GetSize() const {
    return size_;
}

bool FileByteStream::ReadAt(std::uint64_t offset, void* buffer, std::size_t size) {
    if (!impl_ || !impl_->stream.is_open() || !buffer) {
        return false;
    }

    if (offset > size_ || size > static_cast<std::size_t>(size_ - offset)) {
        return false;
    }

    impl_->stream.clear();
    impl_->stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!impl_->stream.good()) {
        return false;
    }

    impl_->stream.read(static_cast<char*>(buffer), static_cast<std::streamsize>(size));
    return impl_->stream.good() || impl_->stream.gcount() == static_cast<std::streamsize>(size);
}

bool BuildDemoAvDatabase(
    std::map<std::uint64_t, std::vector<AvRecord>>* database,
    AvDatabaseInfo* info,
    std::wstring* errorMessage
) {
    if (!database || !info) {
        if (errorMessage) {
            *errorMessage = L"Invalid antivirus database output pointers.";
        }
        return false;
    }

    database->clear();
    *info = {};

    if (!AddDemoRecord(
            database,
            L"Demo.PowerShell.TestPattern",
            "Demo-Av-Test-Pattern",
            ScanObjectType::PowerShellScript,
            0,
            4096,
            errorMessage)) {
        return false;
    }

    if (!AddDemoRecord(
            database,
            L"Demo.PE.DosStub",
            "This program cannot be run in DOS mode",
            ScanObjectType::PeFile,
            32,
            512,
            errorMessage)) {
        return false;
    }

    long count = 0;
    for (const auto& [_, entries] : *database) {
        count += static_cast<long>(entries.size());
    }

    info->isLoaded = true;
    info->recordCount = count;
    info->releaseDate = kDemoDatabaseReleaseDate;
    return true;
}

ScanObjectType DetectObjectType(const std::wstring& path, IByteStream* stream) {
    const std::wstring extension = ToLowerCopy(std::filesystem::path(path).extension().wstring());
    if (extension == L".ps1") {
        return ScanObjectType::PowerShellScript;
    }

    std::uint8_t header[2] = {};
    std::unique_ptr<FileByteStream> ownedStream;
    IByteStream* activeStream = stream;
    if (!activeStream) {
        ownedStream = std::make_unique<FileByteStream>(path);
        if (!ownedStream->IsOpen()) {
            return ScanObjectType::Unknown;
        }
        activeStream = ownedStream.get();
    }

    if (activeStream->ReadAt(0, header, sizeof(header)) && header[0] == 'M' && header[1] == 'Z') {
        return ScanObjectType::PeFile;
    }

    return ScanObjectType::Unknown;
}

const wchar_t* ObjectTypeToDisplayName(ScanObjectType type) {
    switch (type) {
    case ScanObjectType::PeFile:
        return L"PE File";
    case ScanObjectType::PowerShellScript:
        return L"PowerShell Script";
    case ScanObjectType::Unknown:
    default:
        return L"Unknown";
    }
}

ScanResult ScanByteStream(
    const std::wstring& displayPath,
    IByteStream* stream,
    ScanObjectType objectType,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database
) {
    ScanResult result;
    result.success = true;
    result.path = displayPath;
    result.objectType = objectType;

    if (!stream) {
        result.success = false;
        result.message = L"The scan stream is not available.";
        return result;
    }

    const std::uint64_t fileSize = stream->GetSize();
    if (fileSize < sizeof(std::uint64_t)) {
        result.message = L"No matching signatures found.";
        return result;
    }

    const std::vector<AhoNode> automaton = BuildPrefixAutomaton(database);
    if (automaton.empty()) {
        result.message = L"No matching signatures found.";
        return result;
    }

    std::vector<std::uint8_t> chunk(kScanChunkBytes);
    std::size_t state = 0;

    for (std::uint64_t baseOffset = 0; baseOffset < fileSize; baseOffset += chunk.size()) {
        const std::size_t bytesToRead = static_cast<std::size_t>(std::min<std::uint64_t>(chunk.size(), fileSize - baseOffset));
        if (!stream->ReadAt(baseOffset, chunk.data(), bytesToRead)) {
            result.success = false;
            result.message = L"Unable to read the scan stream.";
            return result;
        }

        for (std::size_t index = 0; index < bytesToRead; ++index) {
            const std::uint8_t byte = chunk[index];
            state = static_cast<std::size_t>(automaton[state].next[byte]);

            if (automaton[state].outputs.empty()) {
                continue;
            }

            const std::uint64_t endOffset = baseOffset + index;
            if (endOffset + 1 < kPrefixBytes) {
                continue;
            }

            const std::uint64_t candidateOffset = endOffset + 1 - kPrefixBytes;
            for (std::uint64_t prefixKey : automaton[state].outputs) {
                const auto entry = database.find(prefixKey);
                if (entry == database.end()) {
                    continue;
                }

                for (const AvRecord& record : entry->second) {
                    std::wstring validationError;
                    if (!RecordMatchesAtOffset(stream, fileSize, candidateOffset, objectType, record, &validationError)) {
                        if (!validationError.empty()) {
                            result.success = false;
                            result.message = validationError;
                            return result;
                        }
                        continue;
                    }

                    result.malicious = true;
                    result.matchedOffset = candidateOffset;
                    result.threatName = record.threatName;
                    result.message = L"Malicious object detected.";
                    return result;
                }
            }
        }
    }

    result.message = L"No matching signatures found.";
    return result;
}

ScanResult ScanFileWithDatabase(
    const std::wstring& path,
    const std::map<std::uint64_t, std::vector<AvRecord>>& database
) {
    ScanResult result;
    result.path = path;

    FileByteStream stream(path);
    if (!stream.IsOpen()) {
        result.success = false;
        result.message = L"Unable to open the selected file.";
        return result;
    }

    const ScanObjectType objectType = DetectObjectType(path, &stream);
    result = ScanByteStream(path, &stream, objectType, database);
    result.objectType = objectType;

    if (objectType == ScanObjectType::Unknown && result.success && !result.malicious) {
        result.message = L"Unsupported file type. No matching signatures found.";
    }

    return result;
}

} // namespace antivirus
