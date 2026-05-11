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
