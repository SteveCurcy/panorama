#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <unordered_map>
#include <algorithm>

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#include "panorama.h"
using namespace std;

/* 前一个为进程名对应的 ID，后一个为该进程的事件序列 */
static vector<pair<__u32, vector<__u32>>> peventLists;
static unordered_map<__u64, __u32> sttMap;
static vector<pair<__u64, __u32>> stt;
static __u32 newCode = 1;

__u16 getProcCode(const string& processName);
const char *getStateStr(__u32 processStateCode);
const char *getEventStr(__u32 panoramaEventId);
int initPeventList(const string& filename);
void genStateTransitionTable();
/* 返回当前位置开始，<最长的包含循环序列的长度，每个循环的跨度> */
pair<int, int> getLps(const int *peventList, int len);
/* 输出构造好的状态转移表 */
void printStateTransitionTable();

int main(int argc, char* argv[]) {
    int err = 0;
    if (argc > 1) err = initPeventList(argv[1]);
    else err = initPeventList("/var/log/genor.log");
    if (err) {
        cerr << "[Error] " << (argc > 1? argv[1]: "/var/log/genor.log") << " log file cannot be loaded! The file may not exist or have wrong format!" << endl;
    }
    genStateTransitionTable();
    printStateTransitionTable();
    return 0;
}

void printStateTransitionTable() {
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

pair<int, int> getLps(const __u32 *list, int len) {
    vector<int> lps(len);
    int i = 1, j = 0;
    while (i < len) {
        if (list[i] == list[j]) {
            lps[i] = ++j;
        } else if (j == 0) lps[i] = 0;
        else {
            break;
        }
        i++;
    }
    int span = i, unit = i - lps[i - 1];
    if (j == 0 || span % unit) {
        /* 走到最后都还是为 0，则说明没有环，直接返回 0；
         * 或者，如果重复总长度不能整除重复单元，则说明 */
        return {0, 0};
    }
    return {span, unit};
}

int initPeventList(const string& filename) {
    ifstream ifs;
    ifs.open(filename, ios::in);
    if (!ifs.is_open()) return 1;

    __u32 peventType;
    pid_t pid;
    string procName, line;

    /* 利用 pid 将不同进程的事件序列分离，映射到不同的下标 */
    unordered_map<pid_t, int> indexs;
    int nextIndex = 0;
    while (getline(ifs, line)) {
        stringstream ss;
        ss << line;
        ss >> pid >> procName >> peventType;
        if (!indexs.count(pid)) {
            /* 当前进程之前没有出现过，将其添加到 pid 到下标映射中 */
            peventLists.emplace_back(getProcCode(procName), vector<__u32>());
            indexs.emplace(pid, nextIndex++);
        }
        peventLists[indexs[pid]].second.emplace_back(peventType);
    }
    // unordered_map<__u32, int> priority(nextIndex);    // 事先计算每个进程去重后的任务复杂度
    // for (int i = 0; i < nextIndex; i++) {
    //     int n = peventLists[i].second.size();
    //     for (int j = 0; j < n; j++) {
    //         int span, unit;
    //         tie(span, unit) = getLps(&peventLists[i].second[j], n - j);
    //         if (!span) {
    //             priority[peventLists[i].first]++;
    //         } else {
    //             priority[peventLists[i].first] += unit - 1;
    //             j += span - 1;
    //         }
    //     }
    // }
    /* 为了保证简单任务的事件序列不会被复杂任务的覆盖，
     * 将简单任务的排序到前面（这里认为简单任务的序列长度更短） */
    sort(peventLists.begin(), peventLists.end(), [](const auto& a, const auto& b) -> bool {
        return a.second.size() <= b.second.size();
        // return priority[a.first] <= priority[b.first];
    });

    ifs.close();
    return 0;
}

void genStateTransitionTable() {
    __u32 curCode = 0;
    for (const auto& peventInfo: peventLists) {
        /* 一个进程的事件序列 */
        curCode = 0;
        const auto& pevents = peventInfo.second;
        int len = pevents.size();
        for (int i = 0; i < len; i++) {
            /* 首先我们查看是否已经保存了对应的记录 */
            __u32 nextCode = peventInfo.first;
            __u32 finalCode = nextCode;
            __u32 pevent = pevents[i];
            __u64 key = ((__u64)curCode << 32) | pevent;
            auto cnt = sttMap.count(key);
            if (cnt) {
                /* 已经保存过相同的路径，直接继续走下去 */
                nextCode = sttMap[key];
                curCode = nextCode;
                continue;
            }
            /* 走到这里说明，之前没有遇到与当前相同的状态转移，查看是否有环 */
            int span, unit;
            tie(span, unit) = getLps(&pevents[i], len - i);
            /* 如果值为 0，则说明没有环，那么正常进行即可 */
            if (!span) {
                if (i != len - 1) nextCode = newCode++;
                else nextCode = finalCode;
                sttMap[key] = nextCode;
                stt.emplace_back(key, nextCode);
                curCode = nextCode;
            } else {
                /* 因为要构造环，首先保存当前状态，最后一次事件将回到当前状态 */
                /* 先处理前处理 unit - 1 个 */
                auto oldState = curCode;
                for (int j = 0; j < unit - 1; j++) {
                    /* 只有当前位置到了重复单元的最后部分，并且总重复长度后序列结束，才说明当前到达了序列的末端 */
                    if (likely(j != unit - 2 || i + span < len)) nextCode = newCode++;
                    else nextCode = finalCode;
                    key = ((__u64)curCode << 32) | pevents[i + j];
                    sttMap[key] = nextCode;
                    curCode = nextCode;
                    stt.emplace_back(key, nextCode);
                }
                /* 然后，最后一个事件回到原来的状态 */
                pevent = pevents[i + unit - 1];
                key = ((__u64)curCode << 32) | pevent;
                sttMap[key] = oldState;
                curCode = oldState;
                stt.emplace_back(key, oldState);
                /* 由于后面 span 长度的都是重复，直接跳转到最后即可 */
                i += span - 1;
            }
        }
    }
}

uint16_t getProcCode(const string& procName) {
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
    if (procName == "scp" || procName == "sshpass") return STATE_SCP;
    if (procName == "ssh") return STATE_SSH;
    if (procName == "sshd") return STATE_SSHD;
    return 0xffff;
}

const char *getStateStr(__u32 procCode) {
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
    case STATE_SCP: return "STATE_SCP";
    case STATE_SSH: return "STATE_SSH";
    case STATE_SSHD: return "STATE_SSHD";
    }
    return nullptr;
}

const char *getEventStr(__u32 sysid) {
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
	case PEVENT_CONNECT: return "PEVENT_CONNECT";
	case PEVENT_ACCEPT: return "PEVENT_ACCEPT";
	default:
		return "nil";
	}
}