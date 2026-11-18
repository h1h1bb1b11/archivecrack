// ArchiveCrack - archive password brute-force GUI (Dear ImGui + DirectX 11)
// Targets archives you own. Native ZipCrypto engine plus an optional 7-Zip backend.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <commdlg.h>
#include <d3d11.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cmath>
#include <algorithm>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "inflate.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "comdlg32.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ------------------------------------------------------------------ helpers
static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// Split a UTF-8 string into individual code points (used as the charset).
static std::vector<std::string> splitUtf8(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        size_t len = 1;
        if (c >= 0xF0) len = 4;
        else if (c >= 0xE0) len = 3;
        else if (c >= 0xC0) len = 2;
        if (i + len > s.size()) len = 1;
        out.push_back(s.substr(i, len));
        i += len;
    }
    // de-duplicate while keeping order
    std::vector<std::string> uniq;
    for (auto& ch : out)
        if (std::find(uniq.begin(), uniq.end(), ch) == uniq.end()) uniq.push_back(ch);
    return uniq;
}

// ------------------------------------------------------------------ ZipCrypto
static uint32_t gCrcTable[256];
static void initCrcTable() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        gCrcTable[i] = c;
    }
}

struct ZipKeys {
    uint32_t k0 = 0x12345678u, k1 = 0x23456789u, k2 = 0x34567890u;
    void update(uint8_t c) {
        k0 = gCrcTable[(k0 ^ c) & 0xff] ^ (k0 >> 8);
        k1 = (k1 + (k0 & 0xff)) * 134775813u + 1u;
        k2 = gCrcTable[(k2 ^ (uint8_t)(k1 >> 24)) & 0xff] ^ (k2 >> 8);
    }
    uint8_t decryptByte() const {
        uint16_t t = (uint16_t)((k2 | 2) & 0xffff);
        return (uint8_t)(((t * (t ^ 1)) >> 8) & 0xff);
    }
};

// ------------------------------------------------------------------ archive IO
class FileReader {
public:
    ~FileReader() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    bool open(const std::wstring& path) {
        h_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h_, &sz)) return false;
        size_ = (uint64_t)sz.QuadPart;
        return true;
    }
    uint64_t size() const { return size_; }
    bool readAt(uint64_t off, void* buf, size_t n) {
        if (off >= size_) return false;
        LARGE_INTEGER li{};
        li.QuadPart = (LONGLONG)off;
        if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) return false;
        DWORD got = 0;
        return ReadFile(h_, buf, (DWORD)n, &got, nullptr) && got == n;
    }
private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
    uint64_t size_ = 0;
};

#pragma pack(push, 1)
struct ZipEocd {
    uint32_t sig;
    uint16_t disk, cdDisk, entriesHere, entriesTotal;
    uint32_t cdSize, cdOffset;
    uint16_t commentLen;
};
struct ZipCdEntry {
    uint32_t sig;
    uint16_t verMade, verNeed, flags, method, modTime, modDate;
    uint32_t crc, compSize, uncompSize;
    uint16_t nameLen, extraLen, commentLen, diskStart, intAttr;
    uint32_t extAttr, localOffset;
};
struct ZipLocalHeader {
    uint32_t sig;
    uint16_t verNeed, flags, method, modTime, modDate;
    uint32_t crc, compSize, uncompSize;
    uint16_t nameLen, extraLen;
};
#pragma pack(pop)

// ------------------------------------------------------------------ engines
class Engine {
public:
    virtual ~Engine() = default;
    virtual bool test(const std::string& pwd) = 0;
    // Fast path used by the workers: allowed to cache state between calls (same thread).
    virtual bool testFast(const std::string& pwd) { return test(pwd); }
    virtual bool confirm(const std::string& pwd) { (void)pwd; return true; }
    virtual const char* name() const = 0;
    virtual bool fastParallel() const = 0;
};

static bool testWith7z(const std::wstring& exe, const std::wstring& archive, const std::string& pwd) {
    std::wstring wpwd = utf8ToWide(pwd);
    std::wstring cmd = L"\"" + exe + L"\" t -y -p\"" + wpwd + L"\" -- \"" + archive + L"\"";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

class SevenZipEngine : public Engine {
public:
    SevenZipEngine(std::wstring exe, std::wstring archive) : exe_(std::move(exe)), archive_(std::move(archive)) {}
    bool test(const std::string& pwd) override { return testWith7z(exe_, archive_, pwd); }
    const char* name() const override { return "7-Zip backend"; }
    bool fastParallel() const override { return false; }
private:
    std::wstring exe_, archive_;
};

class ZipCryptoEngine : public Engine {
public:
    bool init(const std::wstring& archive) {
        if (!reader_.open(archive)) return false;
        archive_ = archive;
        uint64_t sz = reader_.size();
        if (sz < 22) return false;
        size_t tail = (size_t)std::min<uint64_t>(sz, 65557);
        std::vector<uint8_t> buf(tail);
        if (!reader_.readAt(sz - tail, buf.data(), tail)) return false;
        long eocdPos = -1;
        for (long i = (long)tail - 22; i >= 0; i--) {
            if (memcmp(&buf[i], "PK\x05\x06", 4) == 0) { eocdPos = i; break; }
        }
        if (eocdPos < 0) return false;
        ZipEocd e{};
        memcpy(&e, &buf[eocdPos], sizeof(e));
        if (e.entriesTotal == 0) return false;
        std::vector<uint8_t> cd(e.cdSize);
        if (e.cdSize == 0 || !reader_.readAt(e.cdOffset, cd.data(), e.cdSize)) return false;

        size_t p = 0;
        std::vector<Entry> found;
        for (uint16_t i = 0; i < e.entriesTotal && p + 46 <= cd.size(); i++) {
            ZipCdEntry ce{};
            memcpy(&ce, &cd[p], sizeof(ce));
            if (ce.sig != 0x02014b50) break;
            std::string name((const char*)&cd[p + 46], ce.nameLen);
            size_t extraOff = p + 46 + ce.nameLen;
            bool aes = false;
            if (ce.extraLen && extraOff + ce.extraLen <= cd.size()) {
                size_t q = extraOff;
                while (q + 4 <= extraOff + ce.extraLen) {
                    uint16_t id = *(uint16_t*)&cd[q];
                    uint16_t len = *(uint16_t*)&cd[q + 2];
                    if (id == 0x9901) { aes = true; break; }
                    q += 4 + len;
                }
            }
            p += 46 + ce.nameLen + ce.extraLen + ce.commentLen;
            if (!(ce.flags & 1) || aes) continue;
            if (ce.method != 0 && ce.method != 8) continue;

            ZipLocalHeader lh{};
            if (!reader_.readAt(ce.localOffset, &lh, sizeof(lh))) continue;
            if (lh.sig != 0x04034b50) continue;
            uint64_t dataOff = (uint64_t)ce.localOffset + 30 + lh.nameLen + lh.extraLen;
            uint8_t header[12];
            if (!reader_.readAt(dataOff, header, 12)) continue;
            Entry en;
            en.checkByte = (uint8_t)((ce.flags & 8) ? (ce.modTime >> 8) : (ce.crc >> 24));
            memcpy(en.header, header, 12);
            en.dataOff = dataOff;
            en.compSize = ce.compSize;
            en.uncompSize = ce.uncompSize;
            en.crc = ce.crc;
            en.method = ce.method;
            found.push_back(en);
            if (found.size() >= 8) break;
            (void)name;
        }
        if (found.empty()) return false;

        // Use the smallest entry as the verification target: full decryption stays cheap.
        size_t best = 0;
        for (size_t i = 1; i < found.size(); i++) {
            bool aOk = found[i].compSize > 12;
            bool bOk = found[best].compSize > 12;
            if (aOk && (!bOk || found[i].compSize < found[best].compSize)) best = i;
        }
        primary_ = found[best];
        for (size_t i = 0; i < found.size() && extra_.size() < 3; i++)
            if (i != best) extra_.push_back(found[i]);
        return true;
    }

    bool test(const std::string& pwd) override {
        ZipKeys k;
        for (unsigned char c : pwd) k.update(c);
        return checkHeader(k);
    }

    // The last password character changes fastest during enumeration, so reuse the
    // key state of the shared prefix instead of re-hashing the whole password.
    bool testFast(const std::string& pwd) override {
        thread_local std::string lastPrefix;
        thread_local ZipKeys baseKeys;
        size_t plen = pwd.size();
        while (plen > 0 && ((unsigned char)pwd[plen - 1] & 0xC0) == 0x80) plen--;
        if (plen > 0) plen--;
        if (plen != lastPrefix.size() || memcmp(lastPrefix.data(), pwd.data(), plen) != 0) {
            baseKeys = ZipKeys();
            for (size_t i = 0; i < plen; i++) baseKeys.update((unsigned char)pwd[i]);
            lastPrefix.assign(pwd.data(), plen);
        }
        ZipKeys k = baseKeys;
        for (size_t i = plen; i < pwd.size(); i++) k.update((unsigned char)pwd[i]);
        return checkHeader(k);
    }

    // Full check: other entries' header bytes first (cheap), then the CRC of the
    // smallest entry to reject the remaining 1/256 header false positives.
    bool confirm(const std::string& pwd) override {
        if (primary_.compSize == 0) return true;
        ZipKeys base;
        for (unsigned char c : pwd) base.update(c);
        for (const Entry& e : extra_) {
            ZipKeys k = base;
            uint8_t last = 0;
            for (int i = 0; i < 12; i++) {
                uint8_t c = (uint8_t)(e.header[i] ^ k.decryptByte());
                k.update(c);
                last = c;
            }
            if (last != e.checkByte) return false;
        }

        const Entry& e = primary_;
        const uint32_t kMaxVerify = 64u << 20;
        if (e.compSize <= 12 || e.compSize > kMaxVerify) return true;

        FileReader r;
        if (!r.open(archive_)) return true;
        // ZIP stores the 12-byte encryption header inside the compressed size.
        size_t total = (size_t)e.compSize;
        std::vector<uint8_t> enc(total);
        if (!r.readAt(e.dataOff, enc.data(), total)) return true;

        std::vector<uint8_t> plain(total);
        ZipKeys k = base;
        for (size_t i = 0; i < total; i++) {
            uint8_t c = (uint8_t)(enc[i] ^ k.decryptByte());
            k.update(c);
            plain[i] = c;
        }

        std::string out;
        size_t payload = total - 12;
        if (e.method == 0) {
            out.assign((const char*)plain.data() + 12, payload);
        } else if (!zinflate::inflateRaw(plain.data() + 12, payload, out)) {
            return false;
        }
        if (e.uncompSize && out.size() != e.uncompSize) return false;

        uint32_t crc = 0xFFFFFFFFu;
        for (unsigned char c : out) crc = gCrcTable[(crc ^ c) & 0xff] ^ (crc >> 8);
        crc ^= 0xFFFFFFFFu;
        return crc == e.crc;
    }

    const char* name() const override { return "ZipCrypto (native)"; }
    bool fastParallel() const override { return true; }

    static std::wstring find7z() {
        const wchar_t* cands[] = {
            L"C:\\Program Files\\7-Zip\\7z.exe",
            L"C:\\Program Files (x86)\\7-Zip\\7z.exe",
        };
        for (auto c : cands)
            if (GetFileAttributesW(c) != INVALID_FILE_ATTRIBUTES) return c;
        wchar_t found[MAX_PATH];
        if (SearchPathW(nullptr, L"7z.exe", nullptr, MAX_PATH, found, nullptr)) return found;
        return L"";
    }

private:
    struct Entry {
        uint8_t header[12];
        uint8_t checkByte;
        uint64_t dataOff = 0;
        uint32_t compSize = 0;
        uint32_t uncompSize = 0;
        uint32_t crc = 0;
        uint16_t method = 0;
    };
    bool checkHeader(const ZipKeys& base) const {
        const Entry& e = primary_;
        ZipKeys k = base;
        uint8_t last = 0;
        for (int i = 0; i < 12; i++) {
            uint8_t c = (uint8_t)(e.header[i] ^ k.decryptByte());
            k.update(c);
            last = c;
        }
        return last == e.checkByte;
    }
    FileReader reader_;
    std::wstring archive_;
    Entry primary_;
    std::vector<Entry> extra_;
};

// ------------------------------------------------------------------ job
struct JobConfig {
    std::wstring archive;
    bool dictMode = false;
    std::vector<std::string> charset;
    int minLen = 1, maxLen = 5;
    std::vector<std::string> dict;
    int threads = 4;
    uint64_t total = 0;
};

class Job {
public:
    std::atomic<bool> stop{false};     // halt all workers (user stop or password found)
    std::atomic<bool> aborted{false};  // user pressed stop
    std::atomic<uint64_t> cursor{0};   // index reservation (blocks)
    std::atomic<uint64_t> done{0};    // candidates actually tested
    std::atomic<int> alive{0};
    std::atomic<bool> finished{false};
    std::atomic<bool> found{false};
    uint64_t total = 0;
    int threadCount = 0;
    std::string foundPwd;
    std::string current;
    int curLen = 0;
    double elapsed = 0;
    std::string engineName;

    std::unique_ptr<Engine> engine;
    JobConfig cfg;
    std::vector<std::thread> workers;
    std::chrono::steady_clock::time_point t0;

    static uint64_t powCap(uint64_t base, int exp) {
        uint64_t r = 1;
        for (int i = 0; i < exp; i++) {
            if (base && r > UINT64_MAX / base) return UINT64_MAX;
            r *= base;
        }
        return r;
    }

    void computeTotal() {
        total = 0;
        if (cfg.dictMode) {
            total = cfg.dict.size();
            return;
        }
        uint64_t n = cfg.charset.size();
        for (int L = cfg.minLen; L <= cfg.maxLen; L++) {
            uint64_t c = powCap(n, L);
            if (total > UINT64_MAX - c) { total = UINT64_MAX; break; }
            total += c;
        }
    }

    // Flatten the charset once so candidates can be assembled with plain memcpy.
    void prepareCharset() {
        csOff_.assign(cfg.charset.size() + 1, 0);
        csLen_.assign(cfg.charset.size(), 0);
        csFlat_.clear();
        for (size_t i = 0; i < cfg.charset.size(); i++) {
            csOff_[i] = (uint32_t)csFlat_.size();
            csLen_[i] = (uint8_t)cfg.charset[i].size();
            csFlat_ += cfg.charset[i];
        }
        csOff_[cfg.charset.size()] = (uint32_t)csFlat_.size();
    }

    static int countChars(const std::string& s) {
        int n = 0;
        for (unsigned char c : s) if ((c & 0xC0) != 0x80) n++;
        return n;
    }

    void start() {
        stop = false;
        aborted = false;
        cursor = 0;
        done = 0;
        finished = false;
        found = false;
        foundPwd.clear();
        current.clear();
        curLen = 0;
        computeTotal();
        if (!cfg.dictMode) prepareCharset();
        threadCount = std::max(1, cfg.threads);
        t0 = std::chrono::steady_clock::now();
        alive = threadCount;
        for (int i = 0; i < threadCount; i++) workers.emplace_back([this] {
            worker();
            alive--;
        });
    }

    void join() {
        for (auto& t : workers) if (t.joinable()) t.join();
        workers.clear();
        finished = true;
    }

    void worker() {
        if (cfg.dictMode) { workerDict(); return; }

        const uint64_t n = cfg.charset.size();
        constexpr uint64_t kBlock = 512;
        std::string pwd;
        pwd.reserve(24);
        std::vector<int> digits;

        // Compute the digit vector (least significant = last character) for one index.
        auto loadIdx = [&](uint64_t idx) {
            uint64_t v = idx;
            int L = cfg.minLen;
            while (L < cfg.maxLen) {
                uint64_t c = powCap(n, L);
                if (v < c) break;
                v -= c;
                L++;
            }
            digits.assign((size_t)L, 0);
            for (int i = L - 1; i >= 0; i--) { digits[(size_t)i] = (int)(v % n); v /= n; }
        };
        auto build = [&]() {
            pwd.clear();
            for (int d : digits) pwd.append(csFlat_.data() + csOff_[(size_t)d], csLen_[(size_t)d]);
        };
        auto bump = [&]() -> bool {
            for (int i = (int)digits.size() - 1; i >= 0; i--) {
                if (++digits[(size_t)i] < (int)n) return true;
                digits[(size_t)i] = 0;
            }
            return false;
        };

        while (!stop) {
            uint64_t start = cursor.fetch_add(kBlock);
            if (start >= total) break;
            uint64_t end = std::min(start + kBlock, total);
            loadIdx(start);
            uint64_t processed = 0;
            bool hit = false;
            for (uint64_t idx = start; idx < end; idx++) {
                if (stop) break;
                build();
                processed++;
                if (idx == start) {
                    std::lock_guard<std::mutex> lk(mu_);
                    current = pwd;
                    curLen = (int)digits.size();
                }
                if (engine->testFast(pwd) && engine->confirm(pwd)) {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (!found.load()) {
                        foundPwd = pwd;
                        current = pwd;
                        found = true;
                    }
                    hit = true;
                    break;
                }
                if (!bump() && idx + 1 < end) loadIdx(idx + 1);
            }
            done.fetch_add(processed);
            if (hit) { stop = true; break; }
        }
    }

    void workerDict() {
        constexpr uint64_t kBlock = 64;
        while (!stop) {
            uint64_t start = cursor.fetch_add(kBlock);
            if (start >= total) break;
            uint64_t end = std::min(start + kBlock, total);
            uint64_t processed = 0;
            bool hit = false;
            for (uint64_t idx = start; idx < end; idx++) {
                const std::string& pwd = cfg.dict[(size_t)idx];
                processed++;
                if (idx == start) {
                    std::lock_guard<std::mutex> lk(mu_);
                    current = pwd;
                    curLen = countChars(pwd);
                }
                if (engine->testFast(pwd) && engine->confirm(pwd)) {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (!found.load()) {
                        foundPwd = pwd;
                        current = pwd;
                        found = true;
                    }
                    hit = true;
                    break;
                }
            }
            done.fetch_add(processed);
            if (hit) { stop = true; break; }
        }
    }

    double speed() const {
        double secs = elapsed > 0 ? elapsed : 1e-9;
        return (double)done.load() / secs;
    }
    std::string currentCopy() {
        std::lock_guard<std::mutex> lk(mu_);
        return current;
    }
    int curLenCopy() {
        std::lock_guard<std::mutex> lk(mu_);
        return curLen;
    }
    std::string foundCopy() {
        std::lock_guard<std::mutex> lk(mu_);
        return foundPwd;
    }
private:
    std::mutex mu_;
    std::string csFlat_;
    std::vector<uint32_t> csOff_;
    std::vector<uint8_t> csLen_;
};

// ------------------------------------------------------------------ GUI state
static Job gJob;
static bool gRunning = false;
static bool gFinished = false;
static std::chrono::steady_clock::time_point gTick;

static char gArchive[1024] = "";
static char gCharset[1024] = "abcdefghijklmnopqrstuvwxyz0123456789";
static int gMinLen = 1, gMaxLen = 5;
static int gThreads = [] {
    unsigned n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    return (int)std::max(1u, std::min(32u, n));
}();
static int gMode = 0;  // 0 brute force, 1 dictionary
static char gDict[1024] = "";
static std::string gError;
static std::string gCopyText;
static float gUiScale = 1.0f;

// UI language: 0 = 简体中文, 1 = English (follows the system language at startup).
static int gLang = (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE) ? 0 : 1;
static const char* L(const char* zh, const char* en) { return gLang ? en : zh; }

// All non-ASCII glyphs the UI can display. Keeping this list exact makes the
// font atlas tiny (a few hundred glyphs) instead of the 2500+ common set,
// which cuts startup time noticeably.
static const char* kUiGlyphs =
    "请先选择压缩包字典文件为空或无法读取符集最大长度过（建议≤）该不是加密，且未找到支持需安装方式暴力枚举码至候总数线程每行一个进引擎：条当前–速已用预计剩余就绪复制停止全部尝试开始仅于恢你自己拥有获授权的。走原生高；通本机校验受启动限简体中";

static bool openFileDialog(char* out, DWORD outSize, const wchar_t* filter) {
    OPENFILENAMEW ofn{};
    std::vector<wchar_t> buf(outSize);
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = outSize;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return false;
    std::string u8 = wideToUtf8(buf.data());
    snprintf(out, outSize, "%s", u8.c_str());
    return true;
}

static std::vector<std::string> loadWordlist(const std::string& path) {
    std::vector<std::string> lines;
    std::wstring w = utf8ToWide(path);
    FILE* f = _wfopen(w.c_str(), L"rb");
    if (!f) return lines;
    std::string cur;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                if (!cur.empty() && cur.back() == '\r') cur.pop_back();
                if (!cur.empty()) lines.push_back(cur);
                cur.clear();
            } else cur.push_back(buf[i]);
        }
    }
    if (!cur.empty()) {
        if (cur.back() == '\r') cur.pop_back();
        if (!cur.empty()) lines.push_back(cur);
    }
    fclose(f);
    return lines;
}

static void startJob() {
    gError.clear();
    if (gArchive[0] == 0) { gError = L("请先选择压缩包", "Select an archive first"); return; }
    JobConfig cfg;
    cfg.archive = utf8ToWide(gArchive);
    cfg.dictMode = (gMode == 1);
    cfg.threads = gThreads;
    if (cfg.dictMode) {
        if (gDict[0] == 0) { gError = L("请先选择字典文件", "Select a dictionary file first"); return; }
        cfg.dict = loadWordlist(gDict);
        if (cfg.dict.empty()) { gError = L("字典为空或无法读取", "Dictionary is empty or unreadable"); return; }
    } else {
        cfg.charset = splitUtf8(gCharset);
        if (cfg.charset.empty()) { gError = L("字符集为空", "Character set is empty"); return; }
        cfg.minLen = std::max(1, gMinLen);
        cfg.maxLen = std::max(cfg.minLen, gMaxLen);
        if (cfg.maxLen > 12) { gError = L("最大长度过大（建议 ≤ 12）", "Max length is too large (<= 12 recommended)"); return; }
    }

    auto zip = std::make_unique<ZipCryptoEngine>();
    if (zip->init(cfg.archive)) {
        gJob.engine = std::move(zip);
    } else {
        std::wstring exe = ZipCryptoEngine::find7z();
        if (exe.empty()) { gError = L("该压缩包不是 ZipCrypto 加密，且未找到 7-Zip（支持 AES/RAR/7z 需安装 7-Zip）",
                                      "Not ZipCrypto encrypted, and 7-Zip was not found (install 7-Zip for AES/RAR/7z)"); return; }
        gJob.engine = std::make_unique<SevenZipEngine>(exe, cfg.archive);
    }
    gJob.engineName = gJob.engine->name();
    cfg.threads = gThreads;
    // The 7-Zip backend spawns a process per candidate; keep the fan-out modest.
    if (!gJob.engine->fastParallel()) cfg.threads = std::max(1, std::min(cfg.threads, 8));
    gJob.cfg = cfg;
    gJob.start();
    gRunning = true;
    gFinished = false;
    gTick = std::chrono::steady_clock::now();
}

static void stopJob() {
    gJob.aborted = true;
    gJob.stop = true;
}

// ------------------------------------------------------------------ DX11
static ID3D11Device* gDevice = nullptr;
static ID3D11DeviceContext* gCtx = nullptr;
static IDXGISwapChain* gSwap = nullptr;
static ID3D11RenderTargetView* gRTV = nullptr;
static bool gResize = false;
static int gWidth = 0, gHeight = 0;

static void createRTV() {
    static const GUID kTex2D = { 0x6f15aaf2, 0xd208, 0x4e89, { 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c } };
    ID3D11Texture2D* back = nullptr;
    if (gSwap->GetBuffer(0, kTex2D, (void**)&back) == S_OK && back) {
        gDevice->CreateRenderTargetView(back, nullptr, &gRTV);
        back->Release();
    }
}

static bool initD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL lvl;
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    const D3D_DRIVER_TYPE types[] = { D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP };
    for (auto type : types) {
        HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, type, nullptr, 0, levels, 2,
                                                   D3D11_SDK_VERSION, &sd, &gSwap, &gDevice, &lvl, &gCtx);
        if (hr == S_OK) {
            createRTV();
            return true;
        }
    }
    return false;
}

static void cleanupD3D() {
    if (gRTV) { gRTV->Release(); gRTV = nullptr; }
    if (gSwap) { gSwap->Release(); gSwap = nullptr; }
    if (gCtx) { gCtx->Release(); gCtx = nullptr; }
    if (gDevice) { gDevice->Release(); gDevice = nullptr; }
}

// ------------------------------------------------------------------ WndProc
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return 0;
    switch (msg) {
    case WM_IME_CHAR: {
        ImGuiIO& io = ImGui::GetIO();
        if (io.WantTextInput) io.AddInputCharacter((unsigned short)wParam);
        return 0;
    }
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) gResize = true;
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ------------------------------------------------------------------ UI helpers
static void sectionTitle(const char* text) {
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.98f, 0.72f, 0.30f, 1.0f), "%s", text);
    ImGui::Separator();
    ImGui::Spacing();
}

// Path input with an "open file" button sized to its label.
static bool pathRow(const char* id, char* buf, size_t size, const char* btnLabel, const wchar_t* filter) {
    ImGuiStyle& st = ImGui::GetStyle();
    float btnW = ImGui::CalcTextSize(btnLabel).x + st.FramePadding.x * 2.0f;
    ImGui::SetNextItemWidth(-(btnW + st.ItemSpacing.x));
    ImGui::InputText(id, buf, size);
    ImGui::SameLine();
    if (ImGui::Button(btnLabel)) {
        openFileDialog(buf, (DWORD)size, filter);
        return true;
    }
    return false;
}

static std::string humanCount(double v) {
    char b[64];
    if (v >= 1e9) snprintf(b, sizeof(b), "%.2fG", v / 1e9);
    else if (v >= 1e6) snprintf(b, sizeof(b), "%.2fM", v / 1e6);
    else if (v >= 1e3) snprintf(b, sizeof(b), "%.2fK", v / 1e3);
    else snprintf(b, sizeof(b), "%.0f", v);
    return b;
}

static std::string humanTime(double secs) {
    char b[64];
    if (secs < 60) snprintf(b, sizeof(b), "%.0fs", secs);
    else if (secs < 3600) snprintf(b, sizeof(b), "%.0fm %.0fs", secs / 60, fmod(secs, 60));
    else if (secs < 86400) snprintf(b, sizeof(b), "%.0fh %.0fm", secs / 3600, fmod(secs / 60, 60));
    else snprintf(b, sizeof(b), "%.0fd %.0fh", secs / 86400, fmod(secs / 3600, 24));
    return b;
}

static void drawUI() {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));
    ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                      ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.98f, 0.72f, 0.30f, 1.0f));
    ImGui::Text("ArchiveCrack");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled("archive password recovery (for archives you own)");
    ImGui::SameLine(ImGui::GetWindowWidth() - 170 * gUiScale);
    ImGui::RadioButton("中文", &gLang, 0);
    ImGui::SameLine();
    ImGui::RadioButton("EN", &gLang, 1);

    sectionTitle(L("压缩包", "Archive"));

    pathRow("##archive", gArchive, sizeof(gArchive), L("选择文件", "Browse"),
            L"Archives (*.zip;*.rar;*.7z)\0*.zip;*.rar;*.7z\0All files (*.*)\0*.*\0");

    sectionTitle(L("方式", "Method"));
    ImGui::RadioButton(L("暴力枚举", "Brute force"), &gMode, 0);
    ImGui::SameLine();
    ImGui::RadioButton(L("字典文件", "Dictionary"), &gMode, 1);

    ImGui::Spacing();
    if (gMode == 0) {
        ImGui::TextDisabled(L("字符集", "Character set"));
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##charset", gCharset, sizeof(gCharset));
        ImGui::Spacing();
        ImGui::TextUnformatted(L("密码长度", "Password length"));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(150 * gUiScale);
        ImGui::InputInt("##minlen", &gMinLen);
        ImGui::SameLine();
        ImGui::TextUnformatted(L("至", "to"));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(150 * gUiScale);
        ImGui::InputInt("##maxlen", &gMaxLen);
        if (gMinLen < 1) gMinLen = 1;
        if (gMaxLen < gMinLen) gMaxLen = gMinLen;
        std::vector<std::string> cs = splitUtf8(gCharset);
        double total = 0;
        for (int Ln = gMinLen; Ln <= gMaxLen && Ln <= 12; Ln++) total += pow((double)cs.size(), Ln);
        ImGui::TextDisabled(L("字符集 %d 字符，候选总数 %s，线程 %d",
                              "%d characters, %s candidates, %d threads"),
                            (int)cs.size(), humanCount(total).c_str(), gThreads);
    } else {
        pathRow("##dict", gDict, sizeof(gDict), L("选择字典", "Browse"),
                L"Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0");
        ImGui::TextDisabled(L("每行一个密码，线程 %d", "One password per line, %d threads"), gThreads);
    }

    ImGui::Spacing();
    ImGui::SetNextItemWidth(260 * gUiScale);
    ImGui::SliderInt(L("线程数", "Threads"), &gThreads, 1, 32);

    sectionTitle(L("进度", "Progress"));

    if (!gJob.engineName.empty()) ImGui::TextDisabled(L("引擎：%s", "Engine: %s"), gJob.engineName.c_str());
    if (!gJob.engineName.empty()) {
        if (gJob.cfg.dictMode)
            ImGui::TextDisabled(L("线程 %d    字典 %s 条    当前长度 %d",
                                  "Threads %d    Dictionary %s entries    Current length %d"),
                                gJob.threadCount, humanCount((double)gJob.cfg.dict.size()).c_str(),
                                gJob.curLenCopy());
        else
            ImGui::TextDisabled(L("线程 %d    字符集 %d 字符    长度 %d–%d    当前长度 %d",
                                  "Threads %d    Charset %d chars    Length %d-%d    Current length %d"),
                                gJob.threadCount, (int)gJob.cfg.charset.size(), gJob.cfg.minLen,
                                gJob.cfg.maxLen, gJob.curLenCopy());
    }

    double secs = 0;
    if (gRunning) {
        auto now = std::chrono::steady_clock::now();
        secs = std::chrono::duration<double>(now - gJob.t0).count();
    }
    if (gRunning && gJob.alive.load() == 0) {
        gJob.join();
        gRunning = false;
        gFinished = true;
    }

    float frac = gJob.total ? (float)((double)gJob.done.load() / (double)gJob.total) : 0.0f;
    if (frac > 1.0f) frac = 1.0f;
    uint64_t shown = std::min<uint64_t>(gJob.done.load(), gJob.total ? gJob.total : gJob.done.load());
    char overlay[160];
    if (gJob.found.load()) snprintf(overlay, sizeof(overlay), "FOUND  %s", gJob.foundCopy().c_str());
    else snprintf(overlay, sizeof(overlay), "%s / %s  (%.2f%%)", humanCount((double)shown).c_str(),
                  gJob.total == UINT64_MAX ? "?" : humanCount((double)gJob.total).c_str(), frac * 100.0);
    ImGui::ProgressBar(frac, ImVec2(-1, 26 * gUiScale), overlay);

    if (gRunning) {
        double spd = gJob.done.load() / (secs > 0 ? secs : 1e-9);
        double remain = gJob.total == UINT64_MAX ? 0 : (double)(gJob.total - std::min<uint64_t>(gJob.done.load(), gJob.total));
        ImGui::Text(L("速度 %s/s    已用 %s    预计剩余 %s", "Speed %s/s    Elapsed %s    Remaining %s"),
                    humanCount(spd).c_str(), humanTime(secs).c_str(),
                    remain > 0 ? humanTime(remain / (spd > 0 ? spd : 1)).c_str() : "-");
        ImGui::TextDisabled(L("当前：%s", "Current: %s"), gJob.currentCopy().c_str());
    } else if (!gFinished) {
        ImGui::TextDisabled(L("就绪", "Ready"));
    }

    if (gFinished) {
        if (gJob.found.load()) {
            std::string pwd = gJob.foundCopy();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.92f, 0.55f, 1.0f));
            ImGui::Text(L("找到密码：%s", "Password found: %s"), pwd.c_str());
            ImGui::PopStyleColor();
            if (ImGui::Button(L("复制密码", "Copy"))) {
                ImGui::SetClipboardText(pwd.c_str());
                gCopyText = L("已复制", "Copied");
            }
            ImGui::SameLine();
            if (!gCopyText.empty()) ImGui::TextDisabled("%s", gCopyText.c_str());
        } else {
            if (gJob.aborted.load()) ImGui::TextDisabled(L("已停止", "Stopped"));
            else ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f),
                                    "%s", L("未找到密码（候选已全部尝试）",
                                            "Password not found (all candidates tried)"));
        }
    }

    if (!gError.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s", gError.c_str());
    }

    ImGui::Spacing();
    ImGui::BeginDisabled(gRunning);
    if (ImGui::Button(L("开始", "Start"), ImVec2(140 * gUiScale, 38 * gUiScale))) startJob();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!gRunning);
    if (ImGui::Button(L("停止", "Stop"), ImVec2(140 * gUiScale, 38 * gUiScale))) stopJob();
    ImGui::EndDisabled();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextDisabled(L("仅用于恢复你自己拥有或已获授权的压缩包。ZipCrypto 走原生高速引擎；",
                          "Use only on archives you own or are authorized to recover. ZipCrypto uses the native engine;"));
    ImGui::TextDisabled(L("AES / RAR / 7z 通过本机 7-Zip 校验，速度受进程启动限制。",
                          "AES / RAR / 7z are verified through the local 7-Zip, limited by process startup."));

    ImGui::End();
    ImGui::PopStyleVar();
}

// ------------------------------------------------------------------ CLI
static int runCli(int argc, wchar_t** argv) {
    if (argc < 5) return 2;
    std::string archivePath = wideToUtf8(argv[2]);
    std::string charset = wideToUtf8(argv[3]);
    int minLen = _wtoi(argv[4]);
    int maxLen = argc > 5 ? _wtoi(argv[5]) : minLen;

    JobConfig cfg;
    cfg.archive = argv[2];
    cfg.charset = splitUtf8(charset);
    cfg.minLen = minLen;
    cfg.maxLen = maxLen;
    cfg.threads = (int)std::max(1u, std::min(32u, std::thread::hardware_concurrency()));

    auto zip = std::make_unique<ZipCryptoEngine>();
    if (zip->init(cfg.archive)) {
        gJob.engine = std::move(zip);
    } else {
        std::wstring exe = ZipCryptoEngine::find7z();
        if (exe.empty()) { printf("no zipcrypto, no 7z\n"); return 3; }
        cfg.threads = 1;
        gJob.engine = std::make_unique<SevenZipEngine>(exe, cfg.archive);
    }
    gJob.cfg = cfg;
    gJob.start();
    gJob.join();
    if (gJob.found.load()) printf("FOUND %s\n", gJob.foundCopy().c_str());
    else printf("NOT FOUND\n");
    return gJob.found.load() ? 0 : 1;
}

// ------------------------------------------------------------------ entry
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    initCrcTable();

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc >= 2 && wcscmp(argv[1], L"--cli") == 0) {
        int rc = runCli(argc, argv);
        LocalFree(argv);
        return rc;
    }
    if (argc >= 2 && argv[1][0] != L'-') {
        snprintf(gArchive, sizeof(gArchive), "%s", wideToUtf8(argv[1]).c_str());
    }
    if (argv) LocalFree(argv);

    {
        HMODULE u32 = GetModuleHandleW(L"user32.dll");
        typedef BOOL(WINAPI * SetCtxFn)(HANDLE);
        if (u32) {
            auto fn = (SetCtxFn)GetProcAddress(u32, "SetProcessDpiAwarenessContext");
            if (!fn || !fn((HANDLE)-4)) SetProcessDPIAware();
        } else {
            SetProcessDPIAware();
        }
    }
    HDC screen = GetDC(nullptr);
    float dpi = (float)GetDeviceCaps(screen, LOGPIXELSX) / 96.0f;
    ReleaseDC(nullptr, screen);
    if (dpi < 1.0f) dpi = 1.0f;

    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    float workW = (float)(wa.right - wa.left), workH = (float)(wa.bottom - wa.top);
    float uiScale = dpi;
    if (workW / 1100.0f < uiScale) uiScale = workW / 1100.0f;
    if (workH / 810.0f < uiScale) uiScale = workH / 810.0f;
    if (uiScale < 1.0f) uiScale = 1.0f;
    gUiScale = uiScale;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0,
                                 LR_DEFAULTSIZE | LR_SHARED);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                   LR_SHARED);
    wc.lpszClassName = L"ArchiveCrackWnd";
    RegisterClassExW(&wc);

    RECT wa2{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa2, 0);
    int winW = std::min((int)(1100 * uiScale), (int)(wa2.right - wa2.left));
    int winH = std::min((int)(810 * uiScale), (int)(wa2.bottom - wa2.top));

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"ArchiveCrack", WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, winW, winH,
                              nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) return 1;
    if (!initD3D(hwnd)) return 1;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 10.0f;
    st.FrameRounding = 6.0f;
    st.GrabRounding = 6.0f;
    st.ScrollbarRounding = 8.0f;
    st.WindowBorderSize = 1.0f;
    st.FramePadding = ImVec2(10, 7);
    st.ItemSpacing = ImVec2(10, 10);
    st.Colors[ImGuiCol_WindowBg] = ImVec4(0.086f, 0.082f, 0.075f, 1.0f);
    st.Colors[ImGuiCol_ChildBg] = ImVec4(0.11f, 0.105f, 0.095f, 1.0f);
    st.Colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.15f, 0.135f, 1.0f);
    st.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.22f, 0.20f, 0.18f, 1.0f);
    st.Colors[ImGuiCol_Button] = ImVec4(0.98f, 0.72f, 0.30f, 0.85f);
    st.Colors[ImGuiCol_ButtonHovered] = ImVec4(1.0f, 0.80f, 0.42f, 1.0f);
    st.Colors[ImGuiCol_ButtonActive] = ImVec4(0.90f, 0.62f, 0.22f, 1.0f);
    st.Colors[ImGuiCol_Button].w = 0.20f;
    st.Colors[ImGuiCol_ButtonHovered].w = 0.35f;
    st.Colors[ImGuiCol_ButtonActive].w = 0.45f;
    st.Colors[ImGuiCol_CheckMark] = ImVec4(0.98f, 0.72f, 0.30f, 1.0f);
    st.Colors[ImGuiCol_SliderGrab] = ImVec4(0.98f, 0.72f, 0.30f, 0.9f);
    st.Colors[ImGuiCol_SliderGrabActive] = ImVec4(1.0f, 0.82f, 0.45f, 1.0f);
    st.Colors[ImGuiCol_Header] = ImVec4(0.98f, 0.72f, 0.30f, 0.18f);
    st.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.98f, 0.72f, 0.30f, 0.28f);
    st.Colors[ImGuiCol_HeaderActive] = ImVec4(0.98f, 0.72f, 0.30f, 0.35f);
    st.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.98f, 0.72f, 0.30f, 0.30f);
    st.ScaleAllSizes(uiScale);

    ImFont* font = nullptr;
    ImFontConfig fc;
    fc.OversampleH = 2;
    fc.OversampleV = 2;
    static ImVector<ImWchar> ranges;
    ImFontGlyphRangesBuilder builder;
    builder.AddRanges(io.Fonts->GetGlyphRangesDefault());
    builder.AddText(kUiGlyphs);
    builder.BuildRanges(&ranges);
    // Primary UI font: Cascadia Code. It contains no CJK glyphs, so a Chinese
    // font is merged in for exactly the characters the UI can display.
    const char* monoCandidates[] = { "C:\\Windows\\Fonts\\CascadiaCode.ttf",
                                     "C:\\Windows\\Fonts\\CascadiaMono.ttf" };
    const char* cjkCandidates[] = { "C:\\Windows\\Fonts\\simhei.ttf", "C:\\Windows\\Fonts\\msyh.ttc" };
    for (auto p : monoCandidates) {
        font = io.Fonts->AddFontFromFileTTF(p, 17.0f * uiScale, &fc, ranges.Data);
        if (font) break;
    }
    if (font) {
        ImFontConfig merge = fc;
        merge.MergeMode = true;
        for (auto p : cjkCandidates) {
            if (io.Fonts->AddFontFromFileTTF(p, 17.0f * uiScale, &merge, ranges.Data)) break;
        }
    } else {
        for (auto p : cjkCandidates) {
            font = io.Fonts->AddFontFromFileTTF(p, 17.0f * uiScale, &fc, ranges.Data);
            if (font) break;
        }
    }
    if (!font) io.Fonts->AddFontDefault();

    // Build the glyph atlas while the window is still hidden, so the first
    // visible frame is already complete instead of flashing an empty window.
    {
        unsigned char* pixels = nullptr;
        int fw = 0, fh = 0;
        io.Fonts->GetTexDataAsRGBA32(&pixels, &fw, &fh);
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(gDevice, gCtx);

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (gResize) {
            if (gDevice && gSwap) {
                if (gRTV) { gRTV->Release(); gRTV = nullptr; }
                gSwap->ResizeBuffers(0, 0, 0, DXGI_FORMAT_UNKNOWN, 0);
                createRTV();
            }
            gResize = false;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        drawUI();

        ImGui::Render();
        const float clear[4] = { 0.086f, 0.082f, 0.075f, 1.0f };
        gCtx->OMSetRenderTargets(1, &gRTV, nullptr);
        gCtx->ClearRenderTargetView(gRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        gSwap->Present(1, 0);
    }

    gJob.stop = true;
    if (gRunning) gJob.join();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanupD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}
