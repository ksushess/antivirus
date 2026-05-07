#pragma once

#include <string>

namespace antivirus {

struct RpcAuthenticationState {
    bool isAuthenticated = false;
    long resultCode = 0;
    std::wstring username;
    std::wstring message;
};

struct RpcLicenseState {
    long licenseState = 0;
    long resultCode = 0;
    std::wstring expirationDate;
    std::wstring message;
};

} // namespace antivirus

bool RequestServiceStopViaRpc();
bool GetAuthenticationStateViaRpc(antivirus::RpcAuthenticationState* state);
bool LoginUserViaRpc(
    const std::wstring& username,
    const std::wstring& password,
    antivirus::RpcAuthenticationState* state
);
bool LogoutUserViaRpc(std::wstring* message, long* resultCode);
bool GetLicenseStateViaRpc(antivirus::RpcLicenseState* state);
bool ActivateProductViaRpc(const std::wstring& activationCode, antivirus::RpcLicenseState* state);
