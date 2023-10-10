#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_map>
using namespace std;

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
#include "panorama.h"

/* 存储状态转移表
 * <oldcode><syscall_id><flags> => <newcode> */
typedef uint32_t sys_flag_type;
typedef pair<uint32_t, vector<sys_flag_type>> syslist_type;

static unordered_map<uint64_t, uint32_t> stt_map;
static map<pid_t, syslist_type> syscallLists;
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

__always_inline static const char *getEventStr(__u32 sysid) {
	switch (sysid) {
	case PEVENT_OPEN_READ: return "PEVENT_OPEN_READ";
	case PEVENT_OPEN_WRITE: return "PEVENT_OPEN_WRITE";
	case PEVENT_OPEN_COVER: return "PEVENT_OPEN_COVER";
	case PEVENT_OPEN_RDWR: return "PEVENT_OPEN_RDWR";
	case PEVENT_OPEN_CREAT: return "PEVENT_OPEN_CREAT";
	case PEVENT_OPEN_DIR: return "PEVENT_OPEN_DIR";
	case PEVENT_READ: return "PEVENT_READ";
	case PEVENT_WRITE: return "PEVENT_WRITE";
	case PEVENT_CLOSE: return "PEVENT_CLOSE";
	case PEVENT_UNLINK_FILE: return "PEVENT_UNLINK_FILE";
	case PEVENT_UNLINK_DIR: return "PEVENT_UNLINK_DIR";
	case PEVENT_MKDIR: return "PEVENT_MKDIR";
	case PEVENT_RENAME: return "PEVENT_RENAME";
	case PEVENT_DUP: return "PEVENT_DUP";
	case SYSCALL_EXIT_GROUP: return "exit_group";
	default:
		return "nil";
	}
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
        ifs >> procName >> sysid;
        syscallLists[pid].first = getProcCode(procName);
        syscallLists[pid].second.emplace_back(atoi(sysid.c_str()));
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
            uint16_t sysid = s;
            uint64_t key = ((__u64)curCode << 32) | sysid;
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
        __u32 oldCode;
        __u16 sysid;
        DE_KEY(p.first, oldCode, sysid);
        char oldCodeStr[32], newCodeStr[32];
        if (getStateStr(oldCode)) sprintf(oldCodeStr, "%s", getStateStr(oldCode));
        else sprintf(oldCodeStr, "%u", oldCode);
        if (getStateStr(p.second)) sprintf(newCodeStr, "%s", getStateStr(p.second));
        else sprintf(newCodeStr, "%u", p.second);
        printf("{STT_KEY(%s, %s), %s},\n", oldCodeStr, getEventStr(sysid), newCodeStr);
    }
}

int main() {
    int err = getSysLists("/var/log/genor.log");
    if (err < 0) return 0;
    genStt();
    printStt();

    return 0;
}