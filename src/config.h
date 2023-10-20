#ifndef CONFIG_H
#define CONFIG_H

#include "panorama.h"

const char *filter_entrys[] = {
    "panorama", /* 过滤掉对自身的日志捕获 */
    "rpm",
    "dnf",
    "irqbalance",
    "AliYunDunMonito",
    "ps",
    "git",
    // "cat",
    "sed",
    "node",
    "AliYunDun",
    "AliSecGuard",
    "sssd_nss",
    "AliYunDunUpdate"
};

/* 标识当前的内核版本号，必须指定，否则会报错；
 * xxxx 的形式指定，前两位为主版本号，后两位为此版本号 */
#define __KERNEL_VERSION 504
// #define __DEBUG_MOD 1

#endif