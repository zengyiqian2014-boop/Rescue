// signature.h - Authenticode verification for Rescue.
//
// The whole value of an autostart cleaner is telling a *legitimate* signed
// program from a dropper. Doing that right means checking BOTH kinds of
// Authenticode signature Windows uses:
//   * embedded  - the signature is inside the .exe/.dll itself
//   * catalog   - the file is unsigned on disk but its hash is vouched for by a
//                 signed security catalog (.cat). MOST Windows system binaries
//                 are catalog-signed, so a tool that only checks embedded
//                 signatures screams "unsigned!" at half of System32. We check
//                 catalogs too, so only genuinely unvouched files get flagged.
#pragma once
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <string>

#ifdef _MSC_VER   // MinGW links -lwintrust -lcrypt32 via the Makefile instead
#pragma comment(lib, "wintrust")
#pragma comment(lib, "crypt32")
#endif

namespace sig {

enum class Trust {
    Missing,        // path does not resolve to a file
    Unsigned,       // file exists, no valid signature anywhere
    Untrusted,      // signature present but does not verify / not trusted
    Embedded,       // trusted embedded Authenticode signature
    Catalog         // trusted via a signed system catalog
};

inline const wchar_t* TrustName(Trust t) {
    switch (t) {
        case Trust::Missing:   return L"MISSING";
        case Trust::Unsigned:  return L"UNSIGNED";
        case Trust::Untrusted: return L"UNTRUSTED";
        case Trust::Embedded:  return L"signed";
        case Trust::Catalog:   return L"signed (catalog)";
    }
    return L"?";
}

// Best-effort signer common-name for an embedded signature.
inline std::wstring EmbeddedSigner(const wchar_t* path) {
    HCERTSTORE store = nullptr; HCRYPTMSG msg = nullptr;
    std::wstring name;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
            &store, &msg, nullptr))
        return name;
    DWORD sz = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &sz) && sz) {
        std::string buf(sz, 0);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(), &sz)) {
            auto* info = reinterpret_cast<CERT_INFO*>(buf.data());
            PCCERT_CONTEXT c = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_FIND_SUBJECT_CERT, info, nullptr);
            if (c) {
                wchar_t nm[256];
                if (CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nm, 256))
                    name = nm;
                CertFreeCertificateContext(c);
            }
        }
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return name;
}

// Verify a file's trust. Fills 'signer' for embedded signatures when available.
inline Trust Verify(const std::wstring& path, std::wstring* signer = nullptr) {
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return Trust::Missing;

    // --- 1. embedded signature ---
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    if (r == ERROR_SUCCESS) {
        if (signer) *signer = EmbeddedSigner(path.c_str());
        return Trust::Embedded;
    }
    bool noEmbedded = (r == (LONG)TRUST_E_NOSIGNATURE ||
                       r == (LONG)TRUST_E_PROVIDER_UNKNOWN ||
                       r == (LONG)TRUST_E_SUBJECT_FORM_UNKNOWN);

    // --- 2. catalog signature ---
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    Trust result = noEmbedded ? Trust::Unsigned : Trust::Untrusted;
    if (h != INVALID_HANDLE_VALUE) {
        HCATADMIN cat = nullptr;
        GUID drv = DRIVER_ACTION_VERIFY;
        if (CryptCATAdminAcquireContext(&cat, &drv, 0)) {
            DWORD hashLen = 0;
            CryptCATAdminCalcHashFromFileHandle(h, &hashLen, nullptr, 0);
            if (hashLen) {
                std::string hash(hashLen, 0);
                if (CryptCATAdminCalcHashFromFileHandle(h, &hashLen, (BYTE*)hash.data(), 0)) {
                    HCATINFO ci = CryptCATAdminEnumCatalogFromHash(cat, (BYTE*)hash.data(), hashLen, 0, nullptr);
                    if (ci) {
                        // A catalog vouches for this hash; verify the catalog itself.
                        CATALOG_INFO info{}; info.cbStruct = sizeof(info);
                        if (CryptCATCatalogInfoFromContext(ci, &info, 0)) {
                            WINTRUST_CATALOG_INFO wci{};
                            wci.cbStruct = sizeof(wci);
                            wci.pcwszCatalogFilePath = info.wszCatalogFile;
                            wci.pcwszMemberFilePath = path.c_str();
                            // member tag = hex of the hash
                            std::wstring tag; tag.reserve(hashLen * 2);
                            const wchar_t* hx = L"0123456789ABCDEF";
                            for (DWORD i = 0; i < hashLen; ++i) {
                                tag += hx[(BYTE)hash[i] >> 4];
                                tag += hx[(BYTE)hash[i] & 0xF];
                            }
                            wci.pcwszMemberTag = tag.c_str();
                            wci.hMemberFile = h;
                            WINTRUST_DATA cd{};
                            cd.cbStruct = sizeof(cd);
                            cd.dwUIChoice = WTD_UI_NONE;
                            cd.fdwRevocationChecks = WTD_REVOKE_NONE;
                            cd.dwUnionChoice = WTD_CHOICE_CATALOG;
                            cd.pCatalog = &wci;
                            cd.dwStateAction = WTD_STATEACTION_VERIFY;
                            cd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
                            GUID ca = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                            LONG cr = WinVerifyTrust(nullptr, &ca, &cd);
                            cd.dwStateAction = WTD_STATEACTION_CLOSE;
                            WinVerifyTrust(nullptr, &ca, &cd);
                            if (cr == ERROR_SUCCESS) result = Trust::Catalog;
                        }
                        CryptCATAdminReleaseCatalogContext(cat, ci, 0);
                    }
                }
            }
            CryptCATAdminReleaseContext(cat, 0);
        }
        CloseHandle(h);
    }
    return result;
}

// Convenience: is this file something we should NOT flag?
inline bool IsTrusted(Trust t) { return t == Trust::Embedded || t == Trust::Catalog; }

} // namespace sig
