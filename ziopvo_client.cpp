#include "ziopvo_client.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <optional>
#include <sstream>
#include <string_view>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace antivirus {
namespace {

constexpr wchar_t kBackendHost[] = L"localhost";
constexpr INTERNET_PORT kBackendPort = 8443;
constexpr wchar_t kBackendUserAgent[] = L"AntivirusService/1.0";
constexpr DWORD kRequestTimeoutMs = 15000;
constexpr DWORD kIgnoredSecurityFlags =
    SECURITY_FLAG_IGNORE_UNKNOWN_CA |
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

struct HttpResponse {
    BackendCallStatus status;
    std::string body;
};

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return L"";
    }

    const int wideSize = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (wideSize <= 0) {
        return L"";
    }

    std::wstring wideValue(static_cast<size_t>(wideSize), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), wideValue.data(), wideSize);
    return wideValue;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return "";
    }

    const int utf8Size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0) {
        return "";
    }

    std::string utf8Value(static_cast<size_t>(utf8Size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), utf8Value.data(), utf8Size, nullptr, nullptr);
    return utf8Value;
}

std::string JsonEscape(const std::wstring& value) {
    const std::string utf8Value = WideToUtf8(value);
    std::string escaped;
    escaped.reserve(utf8Value.size() + 16);

    for (unsigned char ch : utf8Value) {
        switch (ch) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(static_cast<char>(ch));
            break;
        }
    }

    return escaped;
}

void SkipWhitespace(std::string_view json, size_t& position) {
    while (position < json.size()) {
        const char ch = json[position];
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            break;
        }
        ++position;
    }
}

bool FindKeyValueStart(std::string_view json, std::string_view key, size_t& valueStart) {
    const std::string pattern = "\"" + std::string(key) + "\"";
    size_t searchPosition = 0;

    while (true) {
        const size_t keyPosition = json.find(pattern, searchPosition);
        if (keyPosition == std::string_view::npos) {
            return false;
        }

        size_t position = keyPosition + pattern.size();
        SkipWhitespace(json, position);
        if (position >= json.size() || json[position] != ':') {
            searchPosition = keyPosition + pattern.size();
            continue;
        }

        ++position;
        SkipWhitespace(json, position);
        valueStart = position;
        return true;
    }
}

std::optional<std::string> ParseJsonString(std::string_view json, size_t position) {
    if (position >= json.size() || json[position] != '"') {
        return std::nullopt;
    }

    ++position;
    std::string value;

    while (position < json.size()) {
        const char ch = json[position++];
        if (ch == '"') {
            return value;
        }

        if (ch == '\\' && position < json.size()) {
            const char escaped = json[position++];
            switch (escaped) {
            case '"':
            case '\\':
            case '/':
                value.push_back(escaped);
                break;
            case 'b':
                value.push_back('\b');
                break;
            case 'f':
                value.push_back('\f');
                break;
            case 'n':
                value.push_back('\n');
                break;
            case 'r':
                value.push_back('\r');
                break;
            case 't':
                value.push_back('\t');
                break;
            default:
                value.push_back(escaped);
                break;
            }
            continue;
        }

        value.push_back(ch);
    }

    return std::nullopt;
}

std::optional<std::string> ExtractJsonString(std::string_view json, std::string_view key) {
    size_t valueStart = 0;
    if (!FindKeyValueStart(json, key, valueStart)) {
        return std::nullopt;
    }

    return ParseJsonString(json, valueStart);
}

std::optional<long long> ExtractJsonInteger(std::string_view json, std::string_view key) {
    size_t valueStart = 0;
    if (!FindKeyValueStart(json, key, valueStart)) {
        return std::nullopt;
    }

    size_t end = valueStart;
    while (end < json.size() && (json[end] == '-' || (json[end] >= '0' && json[end] <= '9'))) {
        ++end;
    }

    if (end == valueStart) {
        return std::nullopt;
    }

    try {
        return std::stoll(std::string(json.substr(valueStart, end - valueStart)));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<bool> ExtractJsonBoolean(std::string_view json, std::string_view key) {
    size_t valueStart = 0;
    if (!FindKeyValueStart(json, key, valueStart)) {
        return std::nullopt;
    }

    if (json.substr(valueStart, 4) == "true") {
        return true;
    }
    if (json.substr(valueStart, 5) == "false") {
        return false;
    }

    return std::nullopt;
}

std::optional<std::string> ExtractJsonObject(std::string_view json, std::string_view key) {
    size_t valueStart = 0;
    if (!FindKeyValueStart(json, key, valueStart)) {
        return std::nullopt;
    }

    if (valueStart >= json.size() || json[valueStart] != '{') {
        return std::nullopt;
    }

    int depth = 0;
    bool inString = false;
    bool escaped = false;

    for (size_t position = valueStart; position < json.size(); ++position) {
        const char ch = json[position];

        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }

        if (ch == '"') {
            inString = true;
            continue;
        }

        if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                return std::string(json.substr(valueStart, position - valueStart + 1));
            }
        }
    }

    return std::nullopt;
}

std::chrono::system_clock::time_point UnixSecondsToTimePoint(long long secondsSinceEpoch) {
    return std::chrono::system_clock::from_time_t(static_cast<time_t>(secondsSinceEpoch));
}

std::optional<std::chrono::system_clock::time_point> ParseLocalDateTime(const std::string& value) {
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    const int fields = std::sscanf(
        value.c_str(),
        "%d-%d-%dT%d:%d:%d",
        &year,
        &month,
        &day,
        &hour,
        &minute,
        &second
    );
    if (fields < 5) {
        return std::nullopt;
    }

    std::tm localTime = {};
    localTime.tm_year = year - 1900;
    localTime.tm_mon = month - 1;
    localTime.tm_mday = day;
    localTime.tm_hour = hour;
    localTime.tm_min = minute;
    localTime.tm_sec = second;
    localTime.tm_isdst = -1;

    const std::time_t parsedTime = std::mktime(&localTime);
    if (parsedTime == static_cast<std::time_t>(-1)) {
        return std::nullopt;
    }

    return std::chrono::system_clock::from_time_t(parsedTime);
}

std::optional<std::chrono::minutes> ParseTicketLifetime(const std::string& value) {
    if (value.size() < 2) {
        return std::nullopt;
    }

    const char suffix = value.back();
    const std::string digits = value.substr(0, value.size() - 1);

    long long amount = 0;
    try {
        amount = std::stoll(digits);
    } catch (...) {
        return std::nullopt;
    }

    switch (suffix) {
    case 'm':
        return std::chrono::minutes(amount);
    case 'h':
        return std::chrono::minutes(amount * 60);
    case 'd':
        return std::chrono::minutes(amount * 24 * 60);
    default:
        return std::nullopt;
    }
}

std::optional<std::string> Base64UrlDecode(std::string encoded) {
    std::replace(encoded.begin(), encoded.end(), '-', '+');
    std::replace(encoded.begin(), encoded.end(), '_', '/');

    while (encoded.size() % 4 != 0) {
        encoded.push_back('=');
    }

    DWORD decodedSize = 0;
    if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &decodedSize,
            nullptr,
            nullptr)) {
        return std::nullopt;
    }

    std::string decoded(decodedSize, '\0');
    if (!CryptStringToBinaryA(
            encoded.c_str(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            reinterpret_cast<BYTE*>(decoded.data()),
            &decodedSize,
            nullptr,
            nullptr)) {
        return std::nullopt;
    }

    decoded.resize(decodedSize);
    return decoded;
}

std::optional<std::chrono::system_clock::time_point> DecodeJwtExpiration(const std::string& token) {
    const size_t firstDot = token.find('.');
    if (firstDot == std::string::npos) {
        return std::nullopt;
    }

    const size_t secondDot = token.find('.', firstDot + 1);
    if (secondDot == std::string::npos || secondDot <= firstDot + 1) {
        return std::nullopt;
    }

    std::optional<std::string> decodedPayload = Base64UrlDecode(token.substr(firstDot + 1, secondDot - firstDot - 1));
    if (!decodedPayload.has_value()) {
        return std::nullopt;
    }

    const std::optional<long long> expiration = ExtractJsonInteger(decodedPayload.value(), "exp");
    if (!expiration.has_value()) {
        return std::nullopt;
    }

    return UnixSecondsToTimePoint(expiration.value());
}

std::wstring BuildAuthorizationHeader(const std::string& accessToken) {
    return L"Authorization: Bearer " + Utf8ToWide(accessToken) + L"\r\n";
}

std::wstring DefaultErrorMessageForStatus(long httpStatus) {
    switch (httpStatus) {
    case 400:
        return L"Bad request.";
    case 401:
    case 403:
        return L"Invalid credentials or expired session.";
    case 404:
        return L"Backend endpoint not found.";
    default:
        return L"Backend request failed.";
    }
}

HttpResponse SendJsonRequest(
    const wchar_t* method,
    const wchar_t* path,
    const std::string& body,
    const std::string* accessToken
) {
    HttpResponse response;

    HINTERNET session = WinHttpOpen(kBackendUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        response.status.transportError = GetLastError();
        response.status.message = L"Unable to initialize WinHTTP.";
        return response;
    }

    WinHttpSetTimeouts(session, kRequestTimeoutMs, kRequestTimeoutMs, kRequestTimeoutMs, kRequestTimeoutMs);

    HINTERNET connection = WinHttpConnect(session, kBackendHost, kBackendPort, 0);
    if (!connection) {
        response.status.transportError = GetLastError();
        response.status.message = L"Unable to connect to ziopvo backend.";
        WinHttpCloseHandle(session);
        return response;
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        method,
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!request) {
        response.status.transportError = GetLastError();
        response.status.message = L"Unable to create HTTPS request.";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, const_cast<DWORD*>(&kIgnoredSecurityFlags), sizeof(kIgnoredSecurityFlags));

    std::wstring headers = L"Accept: application/json\r\n";
    if (!body.empty()) {
        headers += L"Content-Type: application/json\r\n";
    }
    if (accessToken) {
        headers += BuildAuthorizationHeader(*accessToken);
    }

    const void* requestBody = body.empty() ? nullptr : body.data();
    const DWORD requestBodySize = static_cast<DWORD>(body.size());

    if (!WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.size()),
            const_cast<void*>(requestBody),
            requestBodySize,
            requestBodySize,
            0)) {
        response.status.transportError = GetLastError();
        response.status.message = L"HTTPS request to ziopvo failed.";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        response.status.transportError = GetLastError();
        response.status.message = L"Unable to receive backend response.";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX
    );
    response.status.httpStatus = statusCode;

    std::string responseBody;
    while (true) {
        DWORD availableBytes = 0;
        if (!WinHttpQueryDataAvailable(request, &availableBytes)) {
            response.status.transportError = GetLastError();
            response.status.message = L"Unable to read backend response.";
            break;
        }

        if (availableBytes == 0) {
            break;
        }

        std::vector<char> buffer(availableBytes);
        DWORD downloadedBytes = 0;
        if (!WinHttpReadData(request, buffer.data(), availableBytes, &downloadedBytes)) {
            response.status.transportError = GetLastError();
            response.status.message = L"Unable to download backend response.";
            break;
        }

        responseBody.append(buffer.data(), buffer.data() + downloadedBytes);
    }

    response.body = responseBody;
    if (response.status.transportError == 0) {
        response.status.success = (statusCode >= 200 && statusCode < 300);

        if (response.status.success) {
            response.status.message.clear();
        } else if (const std::optional<std::string> backendMessage = ExtractJsonString(responseBody, "message")) {
            response.status.message = Utf8ToWide(*backendMessage);
        } else if (const std::optional<std::string> backendError = ExtractJsonString(responseBody, "error")) {
            response.status.message = Utf8ToWide(*backendError);
        } else if (const std::optional<std::string> backendSignature = ExtractJsonString(responseBody, "signature")) {
            response.status.message = Utf8ToWide(*backendSignature);
        } else {
            response.status.message = DefaultErrorMessageForStatus(statusCode);
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return response;
}

BackendCallStatus InvalidJsonStatus(const wchar_t* message) {
    BackendCallStatus status;
    status.message = message;
    status.httpStatus = 200;
    return status;
}

std::optional<LicenseTicket> ParseLicenseTicket(std::string_view json) {
    const std::optional<std::string> ticketJson = ExtractJsonObject(json, "ticket");
    if (!ticketJson.has_value()) {
        return std::nullopt;
    }

    LicenseTicket ticket;

    if (const std::optional<std::string> currentDate = ExtractJsonString(*ticketJson, "currentDate")) {
        ticket.currentDate = Utf8ToWide(*currentDate);
        if (const auto parsedTime = ParseLocalDateTime(*currentDate)) {
            ticket.currentTime = *parsedTime;
        }
    }

    if (const std::optional<std::string> lifetime = ExtractJsonString(*ticketJson, "ticketLifetime")) {
        ticket.ticketLifetime = Utf8ToWide(*lifetime);
        if (const auto parsedLifetime = ParseTicketLifetime(*lifetime)) {
            ticket.lifetime = *parsedLifetime;
        }
    }

    if (const std::optional<std::string> activationDate = ExtractJsonString(*ticketJson, "activationDate")) {
        ticket.activationDate = Utf8ToWide(*activationDate);
    }

    if (const std::optional<std::string> expirationDate = ExtractJsonString(*ticketJson, "expirationDate")) {
        ticket.expirationDate = Utf8ToWide(*expirationDate);
        if (const auto parsedTime = ParseLocalDateTime(*expirationDate)) {
            ticket.expirationTime = *parsedTime;
        }
    }

    if (const std::optional<long long> userId = ExtractJsonInteger(*ticketJson, "userId")) {
        ticket.userId = *userId;
    }
    if (const std::optional<long long> deviceId = ExtractJsonInteger(*ticketJson, "deviceId")) {
        ticket.deviceId = *deviceId;
    }
    if (const std::optional<bool> blocked = ExtractJsonBoolean(*ticketJson, "blocked")) {
        ticket.blocked = *blocked;
    }

    return ticket;
}

} // namespace

LoginResponse BackendLogin(const std::wstring& username, const std::wstring& password) {
    const std::string requestBody = "{\"username\":\"" + JsonEscape(username) + "\",\"password\":\"" + JsonEscape(password) + "\"}";
    HttpResponse httpResponse = SendJsonRequest(L"POST", L"/api/auth/login", requestBody, nullptr);

    LoginResponse response;
    response.status = httpResponse.status;
    if (!response.status.success) {
        return response;
    }

    const std::optional<std::string> accessToken = ExtractJsonString(httpResponse.body, "accessToken");
    const std::optional<std::string> refreshToken = ExtractJsonString(httpResponse.body, "refreshToken");
    if (!accessToken.has_value() || !refreshToken.has_value()) {
        response.status = InvalidJsonStatus(L"Login response does not contain JWT tokens.");
        return response;
    }

    const std::optional<std::chrono::system_clock::time_point> accessExpiry = DecodeJwtExpiration(*accessToken);
    const std::optional<std::chrono::system_clock::time_point> refreshExpiry = DecodeJwtExpiration(*refreshToken);
    if (!accessExpiry.has_value() || !refreshExpiry.has_value()) {
        response.status = InvalidJsonStatus(L"Unable to read JWT expiration timestamps.");
        return response;
    }

    response.tokens.accessToken = *accessToken;
    response.tokens.refreshToken = *refreshToken;
    response.tokens.accessExpiry = *accessExpiry;
    response.tokens.refreshExpiry = *refreshExpiry;
    return response;
}

RefreshResponse BackendRefresh(const std::string& refreshToken) {
    const std::string requestBody = "{\"refreshToken\":\"" + refreshToken + "\"}";
    HttpResponse httpResponse = SendJsonRequest(L"POST", L"/api/auth/refresh", requestBody, nullptr);

    RefreshResponse response;
    response.status = httpResponse.status;
    if (!response.status.success) {
        return response;
    }

    const std::optional<std::string> accessToken = ExtractJsonString(httpResponse.body, "accessToken");
    const std::optional<std::string> newRefreshToken = ExtractJsonString(httpResponse.body, "refreshToken");
    if (!accessToken.has_value() || !newRefreshToken.has_value()) {
        response.status = InvalidJsonStatus(L"Refresh response does not contain updated JWT tokens.");
        return response;
    }

    const std::optional<std::chrono::system_clock::time_point> accessExpiry = DecodeJwtExpiration(*accessToken);
    const std::optional<std::chrono::system_clock::time_point> refreshExpiry = DecodeJwtExpiration(*newRefreshToken);
    if (!accessExpiry.has_value() || !refreshExpiry.has_value()) {
        response.status = InvalidJsonStatus(L"Unable to read refreshed JWT expiration timestamps.");
        return response;
    }

    response.tokens.accessToken = *accessToken;
    response.tokens.refreshToken = *newRefreshToken;
    response.tokens.accessExpiry = *accessExpiry;
    response.tokens.refreshExpiry = *refreshExpiry;
    return response;
}

UserProfileResponse BackendGetCurrentUser(const std::string& accessToken) {
    HttpResponse httpResponse = SendJsonRequest(L"GET", L"/api/user/me", "", &accessToken);

    UserProfileResponse response;
    response.status = httpResponse.status;
    if (!response.status.success) {
        return response;
    }

    const std::optional<std::string> username = ExtractJsonString(httpResponse.body, "username");
    if (!username.has_value()) {
        response.status = InvalidJsonStatus(L"User profile response does not contain username.");
        return response;
    }

    response.profile.username = Utf8ToWide(*username);
    if (const std::optional<std::string> email = ExtractJsonString(httpResponse.body, "email")) {
        response.profile.email = Utf8ToWide(*email);
    }
    if (const std::optional<std::string> role = ExtractJsonString(httpResponse.body, "role")) {
        response.profile.role = Utf8ToWide(*role);
    }
    if (const std::optional<std::string> createdAt = ExtractJsonString(httpResponse.body, "createdAt")) {
        response.profile.createdAt = Utf8ToWide(*createdAt);
    }

    return response;
}

LicenseTicketResponse BackendCheckLicense(const std::string& accessToken, const std::wstring& deviceMac) {
    const std::string requestBody = "{\"deviceMac\":\"" + JsonEscape(deviceMac) + "\"}";
    HttpResponse httpResponse = SendJsonRequest(L"POST", L"/api/license/check", requestBody, &accessToken);

    LicenseTicketResponse response;
    response.status = httpResponse.status;
    if (const std::optional<std::string> signature = ExtractJsonString(httpResponse.body, "signature")) {
        response.signature = Utf8ToWide(*signature);
    }

    if (!response.status.success) {
        return response;
    }

    const std::optional<LicenseTicket> ticket = ParseLicenseTicket(httpResponse.body);
    if (!ticket.has_value()) {
        response.status = InvalidJsonStatus(L"License response does not contain a valid ticket.");
        return response;
    }

    response.ticket = *ticket;
    response.hasTicket = true;
    return response;
}

LicenseTicketResponse BackendActivateLicense(
    const std::string& accessToken,
    const std::wstring& activationCode,
    const std::wstring& deviceName,
    const std::wstring& deviceMac
) {
    const std::string requestBody =
        "{\"activationKey\":\"" + JsonEscape(activationCode) +
        "\",\"deviceName\":\"" + JsonEscape(deviceName) +
        "\",\"deviceMac\":\"" + JsonEscape(deviceMac) + "\"}";

    HttpResponse httpResponse = SendJsonRequest(L"POST", L"/api/license/activate", requestBody, &accessToken);

    LicenseTicketResponse response;
    response.status = httpResponse.status;
    if (const std::optional<std::string> signature = ExtractJsonString(httpResponse.body, "signature")) {
        response.signature = Utf8ToWide(*signature);
    }

    if (!response.status.success) {
        return response;
    }

    const std::optional<LicenseTicket> ticket = ParseLicenseTicket(httpResponse.body);
    if (!ticket.has_value()) {
        return response;
    }

    response.ticket = *ticket;
    response.hasTicket = true;
    return response;
}

} // namespace antivirus
