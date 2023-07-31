#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
using namespace std;

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
#include "panorama.h"

/* 存储状态转移表
 * <oldcode><syscall_id><flags> => <newcode> */
typedef pair<uint16_t, uint32_t> sys_flag_type;
typedef pair<uint32_t, vector<sys_flag_type>> syslist_type;

static unordered_map<uint64_t, uint32_t> stt_map;
static unordered_map<pid_t, syslist_type> syscallLists;
static vector<pair<uint64_t, uint32_t>> stt;

uint16_t getProcCode(string procName) {
    if (procName == "cat") return STATE_CAT;
    if (procName == "touch") return STATE_TOUCH;
    if (procName == "rm") return STATE_RM;
    if (procName == "mkdir") return STATE_MKDIR;
    if (procName == "rmdir") return STATE_RMDIR;
    if (procName == "mv") return STATE_MV;
    if (procName == "cp") return STATE_CP;
    if (procName == "gzip") return STATE_GZIP;
    if (procName == "zip") return STATE_ZIP;
    if (procName == "unzip") return STATE_UNZIP;
    if (procName == "split") return STATE_SPLIT;
    return 0xffff;
}

const char *getStateStr(uint32_t procCode) {
    switch (procCode) {
    case STATE_CAT: return "STATE_CAT";
    case STATE_TOUCH: return "STATE_TOUCH";
    case STATE_RM: return "STATE_RM";
    case STATE_MKDIR: return "STATE_MKDIR";
    case STATE_RMDIR: return "STATE_RMDIR";
    case STATE_MV: return "STATE_MV";
    case STATE_CP: return "STATE_CP";
    case STATE_GZIP: return "STATE_GZIP";
    case STATE_ZIP: return "STATE_ZIP";
    case STATE_UNZIP: return "STATE_UNZIP";
    case STATE_SPLIT: return "STATE_SPLIT";
    }
    return NULL;
}

const char *getSyscallStr(uint16_t sysid) {
    switch (sysid) {
    case SYSCALL_OPENAT: return "SYSCALL_OPENAT";
    case SYSCALL_DUP2: return "SYSCALL_DUP2";
    case SYSCALL_DUP3: return "SYSCALL_DUP3";
    case SYSCALL_WRITE: return "SYSCALL_WRITE";
    case SYSCALL_CLOSE: return "SYSCALL_CLOSE";
    case SYSCALL_UNLINK: return "SYSCALL_UNLINK";
    case SYSCALL_UNLINKAT: return "SYSCALL_UNLINKAT";
    case SYSCALL_MKDIR: return "SYSCALL_MKDIR";
    case SYSCALL_MKDIRAT: return "SYSCALL_MKDIRAT";
    case SYSCALL_RMDIR: return "SYSCALL_RMDIR";
    case SYSCALL_RENAME: return "SYSCALL_RENAME";
    case SYSCALL_RENAMEAT: return "SYSCALL_RENAMEAT";
    case SYSCALL_RENAMEAT2: return "SYSCALL_RENAMEAT2";
    }
    return NULL;
}

int getSysLists(const string& filename) {
    ifstream ifs;
    ifs.open(filename, ios::in);
    if (!ifs.is_open()) return -1;

    uint32_t state_code = 0;
    pid_t pid = 0;
    while (ifs >> pid) {
        string procName;
        string sysid;
        string flags;
        ifs >> procName >> sysid >> flags;
        syscallLists[pid].first = getProcCode(procName);
        syscallLists[pid].second.emplace_back(atoi(sysid.c_str()), atoi(flags.c_str()));
    }

    ifs.close();
    return 0;
}

static uint32_t newCode = 1;
void genStt() {
    uint32_t curCode = 0;
    for (const auto& syscalls: syscallLists) {
        curCode = 0;
        for (const auto& s: syscalls.second.second) {
            uint32_t nexCode = syscalls.second.first;
            uint16_t sysid = s.first;
            uint32_t flags = s.second;
            uint64_t key = STT_KEY(curCode, sysid, flags);
            size_t cnt = stt_map.count(key);
            if (cnt) {
                nexCode = stt_map[key];
            } else if (&s != &syscalls.second.second.back()) {
                nexCode = newCode++;
            }

            stt_map[key] = nexCode;
            curCode = nexCode;
            if (!cnt) stt.emplace_back(key, nexCode);
        }
    }
}

void printStt() {
    // vector<pair<__u64, __u32>> buffer(stt_map.begin(), stt_map.end());
    // sort(buffer.begin(), buffer.end(), [](const pair<__u64, __u32>& a, const pair<__u64, __u32>& b) -> bool {
    //     return a.first < b.first;
    // });
    for (const auto& p: stt) {
        __u32 oldCode, flags;
        __u16 sysid;
        DE_KEY(p.first, oldCode, sysid, flags);
        char oldCodeStr[32], newCodeStr[32];
        if (getStateStr(oldCode)) sprintf(oldCodeStr, "%s", getStateStr(oldCode));
        else sprintf(oldCodeStr, "%u", oldCode);
        if (getStateStr(p.second)) sprintf(newCodeStr, "%s", getStateStr(p.second));
        else sprintf(newCodeStr, "%u", p.second);
        printf("{STT_KEY(%s, %s, %u), %s},\n", oldCodeStr, getSyscallStr(sysid), flags, newCodeStr);
    }
}

int main() {
    int err = getSysLists("/var/log/genor.log");
    if (err < 0) return 0;
    genStt();
    printStt();

    return 0;
}