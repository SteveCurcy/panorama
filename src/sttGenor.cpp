/**
 * @file 	sttGenor.cpp
 * @author 	Xu.Cao
 * @version v1.5.3
 * @date 	2023-11-02
 * @details 本程序根据 genor 程序生成的操作事件序列生成状态转移表。
 *  状态转移表分为两种形式，分别为二进制和文本形式。其中
 *  - 二进制形式用于读入并更新到内核 Map 中；
 *  - 文本形式通常用于问题排查，可以直观的看到状态转移表，发掘其中的问题
 * @note    注意：本文中出现的 stt/STT 为状态转移表的简写，state-transition table
 * @see 	genor.c, panorama.c
 * @history
 *  <author>    <time>    <version>    <desc>
 *  Xu.Cao      23/11/02    1.5.3    Format and Standardize this source
 *  Xu.Cao      23/11/03    1.5.4    生成二进制状态转移表源文件，而不再是头文件
 */
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <map>
#include <sys/types.h>
#include <unordered_map>
#include <algorithm>
#include <cstdio>

typedef u_int64_t __u64;
typedef u_int32_t __u32;
typedef u_int16_t __u16;
typedef u_int8_t __u8;

/* 用于优化 CPU 预测分支 */
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#include "panorama.h"
using namespace std;

/* 前一个为下标和进程状态码，后一个为该进程的事件序列 */
static vector<pair<pair<int, __u32>, vector<__u32>>> g_pevents;

/* 记录状态转移表，从旧状态和事件到新状态的事件 */
static unordered_map<__u64, __u32> g_stt;

/* 进程名到对应的终止状态 */
unordered_map<string, __u32> g_end_states;

/* 进程终止状态到字符串形式的映射 */
unordered_map<__u32, string> g_end_states_str;

static __u32 g_next_state = 1, g_next_end_state = 0x80000000;
string null;

__u32 get_end_state(const string& proc_name);
const string& get_end_state_str(__u32 proc_code);
int init_vec_pevents(const string& filename, bool to_sort = true);
void genor_STT();
void print_STT();
pair<int, int> find_ring(const __u32 *list, int len);

int main(int argc, char* argv[]) {

    int err = 0;
    if (argc > 1) err = init_vec_pevents(argv[1]);
    else err = init_vec_pevents("/var/log/genor.log");
    if (err) {
        cerr << "[Error] " << (argc > 1? argv[1]: "/var/log/genor.log")
             << " log file cannot be loaded! "\
             "The file may not exist or have wrong format!" << endl;
        return err;
    }

    genor_STT();

    print_STT();

    return 0;
}

/**
 * @brief  获取进程名对应的进程码
 * @param  proc_name: 进程名
 * @retval 进程码
 */
__u32 get_end_state(const string& proc_name) {

    if (g_end_states.count(proc_name)) {
        return g_end_states[proc_name];
    }

    g_end_states.emplace(proc_name, g_next_end_state);
    string codeStr = "STATE_" + proc_name;
    std::for_each(codeStr.begin() + 6, codeStr.end(), [](char& c) {
        c = toupper((unsigned char)c);
    });
    g_end_states_str.emplace(g_next_end_state, codeStr);

    return g_next_end_state++;
}

/**
 * @brief  获取进程码的字符串表示
 * @param  end_state: 进程码
 * @retval 进程码的字符串表示
 */
const string& get_end_state_str(__u32 end_state) {
    if (g_end_states_str.count(end_state)) return g_end_states_str[end_state];
    return null;
}

/**
 * @brief  加载文件中的操作事件序列
 * @note   文件中包含多个进程的操作事件序列，将其按照进程分类，
 *  并支持按照序列复杂程度从小到大排序。
 * @param  filename: 保存进程操作事件序列的文件名
 * @param  to_sort: 是否要进行复杂度排序，默认是开启（true）
 * @retval 加载是否成功：0 为成功，否则为失败
 */
int init_vec_pevents(const string& filename, bool to_sort) {

    ifstream ifs(filename, ios::in);
    ofstream ofs("./meta.stt", ios::out | ios::binary);
    if (!ifs.is_open() || !ofs.is_open()) {
        ifs.close();
        ofs.close();
        return 1;
    }

    __u32 pevent;
    pid_t pid;
    string sproc_name;
    unordered_map<pid_t, int> umap_pid_idx;
    int next_idx = 0;  // 下一个可用的下标

    while (ifs >> pid) {
        ifs >> sproc_name >> pevent;
        if (!umap_pid_idx.count(pid)) {
            g_pevents.emplace_back(make_pair(next_idx, get_end_state(sproc_name))
                                     , vector<__u32>());
            umap_pid_idx.emplace(pid, next_idx++);
        }
        g_pevents[umap_pid_idx[pid]].second.emplace_back(pevent);
    }

    if (to_sort) {
        vector<int> vec_complexities(next_idx); // 我们定义复杂度是去环后的序列长度
        for (int i = 0; i < next_idx; i++) {
            int n = g_pevents[i].second.size();
            for (int j = 0; j < n; j++) {
                int span, ring;
                tie(span, ring) = find_ring(&g_pevents[i].second[j], n - j);
                if (!span) {
                    vec_complexities[i]++;
                } else {
                    vec_complexities[i] += ring - 1;
                    j += span - 1;
                }
            }
        }

        sort(g_pevents.begin(), g_pevents.end(), [&vec_complexities](const auto& a, const auto& b) -> bool {
            return vec_complexities[a.first.first] < vec_complexities[b.first.first];
        });
    }

    int end_state_sz = g_end_states.size();
    ofs.write((char *)&end_state_sz, sizeof(int));
    for (const auto &end_state: g_end_states) {
        ofs.write((char *)&end_state.second, sizeof(__u32));
        unsigned char str_len = end_state.first.length();
        ofs.write((char *)&str_len, 1);
        ofs.write(end_state.first.c_str(), str_len);
    }

    ifs.close();
    ofs.close();
    return 0;
}

/**
 * @brief  根据各进程的操作事件序列生成状态转移表
 * @note   依次将进程的序列加入到状态转移表中，通常需要先排序
 * @todo   多个进程同时添加到状态转移表中，效果会更好
 * @retval None
 * @see    init_vec_pevents
 */
void genor_STT() {

    for (const auto& pair_pevents: g_pevents) {

        __u32 cur_state = 0;
        const auto& pevents_list = pair_pevents.second;
        int pevents_list_len = pevents_list.size();
        __u32 end_state = pair_pevents.first.second;

        for (int i = 0; i < pevents_list_len; i++) {
            
            __u32 next_state = end_state;
            __u32 pevent = pevents_list[i];
            __u64 key = ((__u64)cur_state << 32) | pevent;

            if (g_stt.count(key)) {
                cur_state = g_stt[key];
                continue;
            }

            int span, ring;
            tie(span, ring) = find_ring(&pevents_list[i], pevents_list_len - i);

            if (!span) {
                if (i != pevents_list_len - 1) {
                    next_state = g_next_state++;
                } else {
                    next_state = end_state;
                }
                g_stt[key] = next_state;
                cur_state = next_state;
            } else {

                bool delay = false;
                if (i + span == pevents_list_len) {
                    if (likely(ring > 1)) next_state = g_next_state++;
                    else next_state = end_state;

                    g_stt[key] = next_state;
                    cur_state = next_state;
                    delay = true;
                }

                auto stash_state = cur_state;
                int handle_start = delay ? 1 : 0,
                    handle_length = delay ? ring : ring - 1;
                for (int j = handle_start; j < handle_length; j++) {

                    if (likely(j != handle_length - 1 || i + span < pevents_list_len)) {
                        next_state = g_next_state++;
                    } else {
                        next_state = end_state; // 到达环的末尾，且环位于进程结束，到达终止态
                    }
                    key = ((__u64)cur_state << 32) | pevents_list[i + j];
                    g_stt[key] = next_state;
                    cur_state = next_state;
                }

                pevent = pevents_list[i + handle_length];
                key = ((__u64)cur_state << 32) | pevent;

                if (!g_stt.count(key)) {
                    g_stt[key] = stash_state;
                }
                cur_state = stash_state;

                i += span - 1;
            }
        }
    }
}

/**
 * @brief  打印当前获得的状态转移表
 * @retval None
 * @see    genor_STT
 */
void print_STT() {

    FILE *pfh_text = fopen("stateTransitionTable.txt", "w");
    FILE *pfh_bin = fopen("stateTransitionTable.stt", "wb");
    if (!pfh_text || !pfh_bin) {
        fclose(pfh_text);
        fclose(pfh_bin);
        cerr << "[Error] stt files open failed!" << endl;
        return;
    }

    for (const auto& p: g_stt) {

        __u32 cur_state;
        __u32 pevent;
        DE_KEY(p.first, cur_state, pevent);
        char old_state_str[32], new_state_str[32];

        if (get_end_state_str(cur_state).size()) {
            sprintf(old_state_str, "%s", get_end_state_str(cur_state).c_str());
        } else {
            sprintf(old_state_str, "%u", cur_state);
        }

        if (get_end_state_str(p.second).size()) {
            sprintf(new_state_str, "%s", get_end_state_str(p.second).c_str());
        } else {
            sprintf(new_state_str, "%u", p.second);
        }

        if (get_event_str(pevent)[0] == 'n') {
            printf("[Error] %s %d %s\n", old_state_str, pevent, new_state_str);
        }
        fprintf(pfh_text, "{STT_KEY(%s, %s), %s},\n", old_state_str, get_event_str(pevent), new_state_str);
        fwrite(&p, sizeof(p), 1, pfh_bin);
    }

    fclose(pfh_text);
    fclose(pfh_bin);
}

/**
 * @brief  找到序列当前位置的环
 * @note   利用最长公共前后缀找到当前位置存在的环
 * @param  list: 序列指针
 * @param  len: 序列最大长度
 * @retval span, ring 分别代表包含环的序列长度，和环的长度，如果为 0 则无环
 */
pair<int, int> find_ring(const __u32 *list, int len) {

    /* 以当前位置为结尾的序列，最长公共前后缀的长度 */
    vector<int> lps(len);
    int i = 1, j = 0;
    while (i < len) {
        if (list[i] == list[j]) {
            lps[i] = ++j;
        } else if (j == 0) {
            lps[i] = 0;
        } else {
            break;
        }
        i++;
    }

    int span = i, ring = i - lps[i - 1];
    if (j == 0 || span % ring) {
        /* 走到最后都还是为 0，则说明没有环，直接返回 0；
         * 或者，如果重复总长度不能整除重复单元，则不合法 */
        return {0, 0};
    }
    return {span, ring};
}