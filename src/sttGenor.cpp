#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <cstdio>

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
/* 用于优化 CPU 预测分支 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#include "panorama.h"
using namespace std;

/* 前一个为进程名对应的 ID，后一个为该进程的事件序列 */
static vector<pair<__u32, vector<__u32>>> peventLists;
static unordered_map<__u64, __u32> sttMap;
static vector<pair<__u64, __u32>> stt;
/* 进程名到进程码的映射 */
unordered_map<string, __u32> procCodeMap;
/* 进程码字符串形式到进程名的映射 */
unordered_map<string, string> procNameMap;
/* 进程码到进程码字符串形式的映射 */
unordered_map<__u32, string> procCodeStr;
static __u32 nextStateCode = 1, nextProcCode = 0x80000000;
string null;

__u32 getProcCode(const string& processName);
const string& getProcCodeStr(__u32 processCode);
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
    FILE *textPtr = fopen("stateTransitionTable.txt", "w");
    FILE *binPtr = fopen("stateTransitionTable.stt", "wb");
    if (!textPtr || !binPtr) {
        fclose(textPtr);
        fclose(binPtr);
        cerr << "[Error] stt files open failed!" << endl;
        return;
    }
    for (const auto& p: stt) {
        __u32 oldCode;
        __u32 peventId;
        DE_KEY(p.first, oldCode, peventId);
        char oldCodeStr[32], newCodeStr[32];
        if (getProcCodeStr(oldCode).size()) sprintf(oldCodeStr, "%s", getProcCodeStr(oldCode).c_str());
        else sprintf(oldCodeStr, "%u", oldCode);
        if (getProcCodeStr(p.second).size()) sprintf(newCodeStr, "%s", getProcCodeStr(p.second).c_str());
        else sprintf(newCodeStr, "%u", p.second);
        fprintf(textPtr, "{STT_KEY(%s, %s), %s},\n", oldCodeStr, getEventStr(peventId), newCodeStr);
        fwrite(&p, sizeof(p), 1, binPtr);
    }

    fclose(textPtr);
    fclose(binPtr);
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
    ifstream ifs(filename, ios::in);
    ofstream ofs("../src/process.h", ios::out);
    if (!ifs.is_open() || !ofs.is_open()) {
        ifs.close();
        ofs.close();
        return 1;
    }

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
    /**
     * 事先计算每个进程去重后的任务复杂度。
     * 我们规定，一个进程的复杂度为整个事件列表去重后的长度：
     * 一个进程产生的事件越多则月复杂。
     * 
     * 同样的，这也描绘了每个进程加入状态转移表的优先级：
     * 我们规定，一个进程的复杂度越高，优先级越低。
     * 这是因为，当一个复杂的进程加入状态转移表后，后来的简单
     * 进程在加入状态转移表时可能会发现，可以一直沿着复杂进程
     * 的状态转移走下去，结果最后简单进程的状态转移过程根本没被
     * 记录。我们称之为“覆盖问题”。
     * 
     * 因此，为了解决覆盖问题，我们需要将简单的进程先加入
     * 状态转移表中，确保简单的进程一定会被记录而不会被覆盖。
     */
    unordered_map<__u32, int> priority(nextIndex);
    for (int i = 0; i < nextIndex; i++) {
        int n = peventLists[i].second.size();
        for (int j = 0; j < n; j++) {
            int span, unit;
            tie(span, unit) = getLps(&peventLists[i].second[j], n - j);
            if (!span) {
                priority[peventLists[i].first]++;
            } else {
                priority[peventLists[i].first] += unit - 1;
                j += span - 1;
            }
        }
    }
    /* 为了保证简单任务的事件序列不会被复杂任务的覆盖，
     * 将简单任务的排序到前面（这里认为简单任务的序列长度更短） */
    sort(peventLists.begin(), peventLists.end(), [&priority](const auto& a, const auto& b) -> bool {
        return priority[a.first] <= priority[b.first];
    });

    /* 将获得的所有进程码写入头文件中，构造对应的函数 */
    ofs << "#ifndef PROCESS_H\n#define PROCESS_H\n" << endl;
    for (const auto& p: procCodeStr) {
        ofs << "#define " << p.second << " 0x" << hex << p.first << endl;
    }
    ofs << "\ninline static const char *get_true_behave(__u32 state_code) {"
        << "\n\tswitch (state_code) {" << endl;
    for (const auto& p: procNameMap) {
        ofs << "\tcase " << p.first << ": return \""
            << p.second << "\";" << endl;
    }
    ofs << "\tdefault: break;\n\t}\n\treturn \"\";\n}\n#endif" << endl;

    ifs.close();
    ofs.close();
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
                if (i != len - 1) nextCode = nextStateCode++;
                else nextCode = finalCode;
                sttMap[key] = nextCode;
                stt.emplace_back(key, nextCode);
                curCode = nextCode;
            } else {
                /* 这个时候需要注意，当前事件会不会是进程的最后 */
                bool delay = false;
                if (i + span == len) {
                    if (likely(unit > 1 || i + span < len)) nextCode = nextStateCode++;
                    else nextCode = finalCode;
                    sttMap[key] = nextCode;
                    stt.emplace_back(key, nextCode);
                    curCode = nextCode;
                    delay = true;
                }
                /* 开始构造环，则先处理前 unit - 1 个事件，最后一个事件回到旧状态 */
                auto oldState = curCode;
                for (int j = (delay? 1: 0); j < (delay? unit: unit - 1); j++) {
                    /* 只有当前位置到了重复单元的最后部分，并且总重复长度后序列结束，才说明当前到达了序列的末端 */
                    if (likely(j != unit - 1 || i + span < len)) nextCode = nextStateCode++;
                    else nextCode = finalCode;
                    key = ((__u64)curCode << 32) | pevents[i + j];
                    sttMap[key] = nextCode;
                    curCode = nextCode;
                    stt.emplace_back(key, nextCode);
                }
                /* 然后，最后一个事件回到原来的状态 */
                pevent = pevents[i + (delay ? unit: unit - 1)];
                key = ((__u64)curCode << 32) | pevent;
                /* 这里需要注意，自旋的部分可能出现重复的状态转移 */
                if (!sttMap.count(key)) {
                    sttMap[key] = oldState;
                    stt.emplace_back(key, oldState);
                }
                curCode = oldState;
                /* 由于后面 span 长度的都是重复，直接跳转到最后即可 */
                i += span - 1;
            }
        }
    }
}



__u32 getProcCode(const string& procName) {
    if (procCodeMap.count(procName)) return procCodeMap[procName];
    procCodeMap.emplace(procName, nextProcCode);
    string codeStr = "STATE_" + procName;
    std::for_each(codeStr.begin() + 6, codeStr.end(), [](char& c) {
        c = toupper((unsigned char)c);
    });

    procNameMap.emplace(codeStr, procName);
    procCodeStr.emplace(nextProcCode, codeStr);
    return nextProcCode++;
}

const string& getProcCodeStr(__u32 procCode) {
    if (procCodeStr.count(procCode)) return procCodeStr[procCode];
    return null;
}

const char *getEventStr(__u32 peventId) {
	switch (peventId) {
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