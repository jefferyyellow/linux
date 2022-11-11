/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Linux Socket Filter Data Structures
 */

#ifndef _UAPI__LINUX_FILTER_H__
#define _UAPI__LINUX_FILTER_H__

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/bpf_common.h>

/*
 * Current version of the filter code architecture.
 */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 *	Try and keep these values and structures similar to BSD, especially
 *	the BPF code definitions which need to match so you can share filters
 */
// 实际上，可以把sock_filter结构数组看作一系列的指令集，和汇编指令很相似，
// 原理也差不多。内核在过滤过程中，会根据一条条指令对被过滤的包做出相应的动作。
// sock_filter结构为BPF过滤代码，结构定义如下： 
struct sock_filter {	/* Filter block */
	// 指令编码：动作包括“比较”、“偏移”、“返回”
	__u16	code;   /* Actual filter code */
	// 成功执行比较操作后跳转到指令数组jt处，做下一步过滤操作
	__u8	jt;	/* Jump true */
	// 执行比较操作失败后跳转到指令数组jf处，做下一步过滤操作
	__u8	jf;	/* Jump false */
	// 当动作code为“偏移”时，k是当前读取数据包的偏移值，单位字节或字或双字。
	// 当动作code为“比较”时，k是与指针指向的数据包当前位置比较的值。
	__u32	k;      /* Generic multiuse field */
};

// BPF过滤器结构
struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	// 为filter指向的sock_filter结构数组的长度
	unsigned short		len;	/* Number of filter blocks */
	// 指向sock_filter结构为BPF过滤代码
	struct sock_filter __user *filter;
};

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)  ((code) & 0x18)
#define         BPF_A           0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */
#define BPF_MEMWORDS 16

/* RATIONALE. Negative offsets are invalid in BPF.
   We use them to reference ancillary data.
   Unlike introduction new instructions, it does not break
   existing compilers/optimizers.
 */
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_IFINDEX 	8
#define SKF_AD_NLATTR	12
#define SKF_AD_NLATTR_NEST	16
#define SKF_AD_MARK 	20
#define SKF_AD_QUEUE	24
#define SKF_AD_HATYPE	28
#define SKF_AD_RXHASH	32
#define SKF_AD_CPU	36
#define SKF_AD_ALU_XOR_X	40
#define SKF_AD_VLAN_TAG	44
#define SKF_AD_VLAN_TAG_PRESENT 48
#define SKF_AD_PAY_OFFSET	52
#define SKF_AD_RANDOM	56
#define SKF_AD_VLAN_TPID	60
#define SKF_AD_MAX	64

#define SKF_NET_OFF	(-0x100000)
#define SKF_LL_OFF	(-0x200000)

#define BPF_NET_OFF	SKF_NET_OFF
#define BPF_LL_OFF	SKF_LL_OFF

#endif /* _UAPI__LINUX_FILTER_H__ */
