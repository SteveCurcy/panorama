#ifndef PROCESS_H
#define PROCESS_H

#define STATE_SSHD 0x8000000d
#define STATE_CAT 0x80000000
#define STATE_TOUCH 0x80000001
#define STATE_RM 0x80000002
#define STATE_MKDIR 0x80000003
#define STATE_RMDIR 0x80000004
#define STATE_GZIP 0x80000005
#define STATE_SPLIT 0x80000006
#define STATE_ZIP 0x80000007
#define STATE_UNZIP 0x80000008
#define STATE_CP 0x80000009
#define STATE_MV 0x8000000a
#define STATE_SCP 0x8000000b
#define STATE_SSH 0x8000000c

inline static const char *get_true_behave(__u32 state_code) {
	switch (state_code) {
	case STATE_CAT: return "cat";
	case STATE_TOUCH: return "touch";
	case STATE_RM: return "rm";
	case STATE_MKDIR: return "mkdir";
	case STATE_RMDIR: return "rmdir";
	case STATE_GZIP: return "gzip";
	case STATE_SSHD: return "sshd";
	case STATE_CP: return "cp";
	case STATE_SPLIT: return "split";
	case STATE_ZIP: return "zip";
	case STATE_UNZIP: return "unzip";
	case STATE_MV: return "mv";
	case STATE_SCP: return "scp";
	case STATE_SSH: return "ssh";
	default: break;
	}
	return "";
}
#endif
