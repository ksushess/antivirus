#pragma once

#include <chrono>
#include <string>

namespace antivirus {

struct BackendCallStatus {
    bool success = false;
    long httpStatus = 0;
    unsigned long transportError = 0;
    std::wstring message;
};

struct TokenBundle {
    std::string accessToken;
    std::string refreshToken;
    std::chrono::system_clock::time_point accessExpiry = {};
    std::chrono::system_clock::time_point refreshExpiry = {};
};

struct UserProfile {
    std::wstring username;
    std::wstring email;
    std::wstring role;
    std::wstring createdAt;
};

struct LicenseTicket {
    std::wstring currentDate;
    std::wstring ticketLifetime;
    std::wstring activationDate;
    std::wstring expirationDate;
    long long userId = 0;
    long long deviceId = 0;
    bool blocked = false;
    std::chrono::system_clock::time_point currentTime = {};
    std::chrono::system_clock::time_point expirationTime = {};
    std::chrono::minutes lifetime = std::chrono::minutes::zero();
};

struct LoginResponse {
    BackendCallStatus status;
    TokenBundle tokens;
};

struct RefreshResponse {
    BackendCallStatus status;
    TokenBundle tokens;
};

struct UserProfileResponse {
    BackendCallStatus status;
    UserProfile profile;
};

struct LicenseTicketResponse {
    BackendCallStatus status;
    LicenseTicket ticket;
    std::wstring signature;
    bool hasTicket = false;
};

LoginResponse BackendLogin(const std::wstring& username, const std::wstring& password);
RefreshResponse BackendRefresh(const std::string& refreshToken);
UserProfileResponse BackendGetCurrentUser(const std::string& accessToken);
LicenseTicketResponse BackendCheckLicense(const std::string& accessToken, const std::wstring& deviceMac);
LicenseTicketResponse BackendActivateLicense(
    const std::string& accessToken,
    const std::wstring& activationCode,
    const std::wstring& deviceName,
    const std::wstring& deviceMac
);

} // namespace antivirus
