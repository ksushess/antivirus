#include "rpc_client.h"

#include <rpc.h>
#include <cstdlib>
#include <string>

#include "antivirus_rpc.h"
#include "shared.h"

handle_t AntivirusBinding = nullptr;

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return std::malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    std::free(pointer);
}

namespace {

handle_t CreateBinding() {
    RPC_WSTR stringBinding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(antivirus::kRpcEndpoint)),
        nullptr,
        &stringBinding
    );
    if (status != RPC_S_OK) {
        return nullptr;
    }

    handle_t binding = nullptr;
    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    return status == RPC_S_OK ? binding : nullptr;
}

void FreeBinding(handle_t binding) {
    if (binding) {
        RpcBindingFree(&binding);
    }
}

void ResetAuthenticationState(antivirus::RpcAuthenticationState* state) {
    if (!state) {
        return;
    }

    state->isAuthenticated = false;
    state->resultCode = antivirus::kRpcResultUnexpectedResponse;
    state->username.clear();
    state->message.clear();
}

void ResetLicenseState(antivirus::RpcLicenseState* state) {
    if (!state) {
        return;
    }

    state->licenseState = antivirus::kLicenseStateUnknown;
    state->resultCode = antivirus::kRpcResultUnexpectedResponse;
    state->expirationDate.clear();
    state->message.clear();
}

void ResetDatabaseInfo(antivirus::RpcAvDatabaseInfo* info) {
    if (!info) {
        return;
    }

    info->isLoaded = false;
    info->recordCount = 0;
    info->resultCode = antivirus::kRpcResultUnexpectedResponse;
    info->releaseDate.clear();
    info->message.clear();
}

void ResetScanSummary(antivirus::RpcScanSummary* summary) {
    if (!summary) {
        return;
    }

    summary->hasDetections = false;
    summary->scannedCount = 0;
    summary->detectedCount = 0;
    summary->resultCode = antivirus::kRpcResultUnexpectedResponse;
    summary->summary.clear();
}

void ResetScheduledScanState(antivirus::RpcScheduledScanState* state) {
    if (!state) {
        return;
    }

    state->isEnabled = false;
    state->intervalSeconds = 0;
    state->lastResultCode = antivirus::kRpcResultUnexpectedResponse;
    state->resultCode = antivirus::kRpcResultUnexpectedResponse;
    state->targetPath.clear();
    state->nextRunText.clear();
    state->lastRunText.clear();
    state->lastSummary.clear();
}

void ResetMonitoringState(antivirus::RpcMonitoringState* state) {
    if (!state) {
        return;
    }

    state->resultCode = antivirus::kRpcResultUnexpectedResponse;
    state->directories.clear();
    state->events.clear();
}

} // namespace


bool RequestServiceStopViaRpc() {
    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    RpcTryExcept{
        RequestServiceStop();
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);
    return ok;
}

bool GetAuthenticationStateViaRpc(antivirus::RpcAuthenticationState* state) {
    ResetAuthenticationState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t usernameBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long isAuthenticated = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = GetAuthenticationState(
            &isAuthenticated,
            antivirus::kRpcTextBufferChars,
            usernameBuffer,
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->isAuthenticated = isAuthenticated != 0;
    state->resultCode = resultCode;
    state->username = usernameBuffer;
    state->message = messageBuffer;
    return true;
}

bool LoginUserViaRpc(
    const std::wstring& username,
    const std::wstring& password,
    antivirus::RpcAuthenticationState* state
) {
    ResetAuthenticationState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long isAuthenticated = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = LoginUser(
            const_cast<wchar_t*>(username.c_str()),
            const_cast<wchar_t*>(password.c_str()),
            &isAuthenticated,
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->isAuthenticated = isAuthenticated != 0;
    state->resultCode = resultCode;
    state->message = messageBuffer;

    if (state->isAuthenticated) {
        GetAuthenticationStateViaRpc(state);
    }

    return true;
}

bool LogoutUserViaRpc(std::wstring* message, long* resultCode) {
    if (message) {
        message->clear();
    }
    if (resultCode) {
        *resultCode = antivirus::kRpcResultUnexpectedResponse;
    }

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long rpcResult = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        rpcResult = LogoutUser(
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok) {
        return false;
    }

    if (message) {
        *message = messageBuffer;
    }
    if (resultCode) {
        *resultCode = rpcResult;
    }

    return true;
}

bool GetLicenseStateViaRpc(antivirus::RpcLicenseState* state) {
    ResetLicenseState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t expirationBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long licenseState = antivirus::kLicenseStateUnknown;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = GetLicenseState(
            &licenseState,
            antivirus::kRpcTextBufferChars,
            expirationBuffer,
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->licenseState = licenseState;
    state->resultCode = resultCode;
    state->expirationDate = expirationBuffer;
    state->message = messageBuffer;
    return true;
}

bool ActivateProductViaRpc(const std::wstring& activationCode, antivirus::RpcLicenseState* state) {
    ResetLicenseState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t expirationBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long licenseState = antivirus::kLicenseStateUnknown;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = ActivateProduct(
            const_cast<wchar_t*>(activationCode.c_str()),
            &licenseState,
            antivirus::kRpcTextBufferChars,
            expirationBuffer,
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->licenseState = licenseState;
    state->resultCode = resultCode;
    state->expirationDate = expirationBuffer;
    state->message = messageBuffer;
    return true;
}

bool GetAvDatabaseInfoViaRpc(antivirus::RpcAvDatabaseInfo* info) {
    ResetDatabaseInfo(info);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t releaseDateBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long isLoaded = 0;
    long recordCount = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = GetAvDatabaseInfo(
            &isLoaded,
            &recordCount,
            antivirus::kRpcTextBufferChars,
            releaseDateBuffer,
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !info) {
        return ok;
    }

    info->isLoaded = isLoaded != 0;
    info->recordCount = recordCount;
    info->resultCode = resultCode;
    info->releaseDate = releaseDateBuffer;
    info->message = messageBuffer;
    return true;
}

bool ScanFileViaRpc(const std::wstring& path, antivirus::RpcScanSummary* summary) {
    ResetScanSummary(summary);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t summaryBuffer[antivirus::kRpcTextBufferChars] = {};
    long isMalicious = 0;
    long scannedCount = 0;
    long detectedCount = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = ScanFilePath(
            const_cast<wchar_t*>(path.c_str()),
            &isMalicious,
            &scannedCount,
            &detectedCount,
            antivirus::kRpcTextBufferChars,
            summaryBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !summary) {
        return ok;
    }

    summary->hasDetections = isMalicious != 0;
    summary->scannedCount = scannedCount;
    summary->detectedCount = detectedCount;
    summary->resultCode = resultCode;
    summary->summary = summaryBuffer;
    return true;
}

bool ScanDirectoryViaRpc(const std::wstring& path, antivirus::RpcScanSummary* summary) {
    ResetScanSummary(summary);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t summaryBuffer[antivirus::kRpcTextBufferChars] = {};
    long hasDetections = 0;
    long scannedCount = 0;
    long detectedCount = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = ScanDirectoryPath(
            const_cast<wchar_t*>(path.c_str()),
            &hasDetections,
            &scannedCount,
            &detectedCount,
            antivirus::kRpcTextBufferChars,
            summaryBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !summary) {
        return ok;
    }

    summary->hasDetections = hasDetections != 0;
    summary->scannedCount = scannedCount;
    summary->detectedCount = detectedCount;
    summary->resultCode = resultCode;
    summary->summary = summaryBuffer;
    return true;
}

bool ScanFixedDrivesViaRpc(antivirus::RpcScanSummary* summary) {
    ResetScanSummary(summary);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t summaryBuffer[antivirus::kRpcTextBufferChars] = {};
    long hasDetections = 0;
    long scannedCount = 0;
    long detectedCount = 0;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = ScanFixedDrives(
            &hasDetections,
            &scannedCount,
            &detectedCount,
            antivirus::kRpcTextBufferChars,
            summaryBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !summary) {
        return ok;
    }

    summary->hasDetections = hasDetections != 0;
    summary->scannedCount = scannedCount;
    summary->detectedCount = detectedCount;
    summary->resultCode = resultCode;
    summary->summary = summaryBuffer;
    return true;
}

bool ConfigureScheduledScanViaRpc(
    bool isEnabled,
    long intervalSeconds,
    const std::wstring& targetPath,
    std::wstring* message,
    long* resultCode
) {
    if (message) {
        message->clear();
    }
    if (resultCode) {
        *resultCode = antivirus::kRpcResultUnexpectedResponse;
    }

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long rpcResult = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        rpcResult = ConfigureScheduledScan(
            isEnabled ? 1 : 0,
            intervalSeconds,
            const_cast<wchar_t*>(targetPath.c_str()),
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok) {
        return false;
    }

    if (message) {
        *message = messageBuffer;
    }
    if (resultCode) {
        *resultCode = rpcResult;
    }
    return true;
}

bool GetScheduledScanStateViaRpc(antivirus::RpcScheduledScanState* state) {
    ResetScheduledScanState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t targetBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t nextRunBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t lastRunBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t summaryBuffer[antivirus::kRpcTextBufferChars] = {};
    long isEnabled = 0;
    long intervalSeconds = 0;
    long lastResultCode = antivirus::kRpcResultUnexpectedResponse;
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = GetScheduledScanState(
            &isEnabled,
            &intervalSeconds,
            antivirus::kRpcTextBufferChars,
            targetBuffer,
            antivirus::kRpcTextBufferChars,
            nextRunBuffer,
            antivirus::kRpcTextBufferChars,
            lastRunBuffer,
            &lastResultCode,
            antivirus::kRpcTextBufferChars,
            summaryBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->isEnabled = isEnabled != 0;
    state->intervalSeconds = intervalSeconds;
    state->lastResultCode = lastResultCode;
    state->resultCode = resultCode;
    state->targetPath = targetBuffer;
    state->nextRunText = nextRunBuffer;
    state->lastRunText = lastRunBuffer;
    state->lastSummary = summaryBuffer;
    return true;
}

bool AddMonitoredDirectoryViaRpc(const std::wstring& path, std::wstring* message, long* resultCode) {
    if (message) {
        message->clear();
    }
    if (resultCode) {
        *resultCode = antivirus::kRpcResultUnexpectedResponse;
    }

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long rpcResult = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        rpcResult = AddMonitoredDirectory(
            const_cast<wchar_t*>(path.c_str()),
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok) {
        return false;
    }

    if (message) {
        *message = messageBuffer;
    }
    if (resultCode) {
        *resultCode = rpcResult;
    }
    return true;
}

bool RemoveMonitoredDirectoryViaRpc(const std::wstring& path, std::wstring* message, long* resultCode) {
    if (message) {
        message->clear();
    }
    if (resultCode) {
        *resultCode = antivirus::kRpcResultUnexpectedResponse;
    }

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t messageBuffer[antivirus::kRpcTextBufferChars] = {};
    long rpcResult = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        rpcResult = RemoveMonitoredDirectory(
            const_cast<wchar_t*>(path.c_str()),
            antivirus::kRpcTextBufferChars,
            messageBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok) {
        return false;
    }

    if (message) {
        *message = messageBuffer;
    }
    if (resultCode) {
        *resultCode = rpcResult;
    }
    return true;
}

bool GetMonitoringStateViaRpc(antivirus::RpcMonitoringState* state) {
    ResetMonitoringState(state);

    handle_t binding = CreateBinding();
    if (!binding) {
        return false;
    }

    AntivirusBinding = binding;
    bool ok = true;

    wchar_t directoriesBuffer[antivirus::kRpcTextBufferChars] = {};
    wchar_t eventsBuffer[antivirus::kRpcTextBufferChars] = {};
    long resultCode = antivirus::kRpcResultUnexpectedResponse;

    RpcTryExcept{
        resultCode = GetMonitoringState(
            antivirus::kRpcTextBufferChars,
            directoriesBuffer,
            antivirus::kRpcTextBufferChars,
            eventsBuffer
        );
    }
        RpcExcept(1) {
        ok = false;
    }
    RpcEndExcept

    AntivirusBinding = nullptr;
    FreeBinding(binding);

    if (!ok || !state) {
        return ok;
    }

    state->resultCode = resultCode;
    state->directories = directoriesBuffer;
    state->events = eventsBuffer;
    return true;
}
