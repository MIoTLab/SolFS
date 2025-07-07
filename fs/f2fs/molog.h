#ifndef __F2FS_MOLOG_H__
#define __F2FS_MOLOG_H__
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/rbtree.h>
#include "f2fs.h"
#include "xattr.h"

// #define SOLFS_ENABLE_ASYNC_LOG_WRITEBACK
// #define SOLFS_ENABLE_COMPACT_MOLOG

// #define SOLFS_DEBUG

#ifdef SOLFS_DEBUG
#define mbfs_debug_log(fmt, ...) \
	do{printk("[SolFS]:(%s):%d: " fmt, __func__, __LINE__, ##__VA_ARGS__);} while(0)
#else
#define mbfs_debug_log(fmt, ...) \
	do{} while(0)
#endif

#define GRAUNALITY_CHANGE_RATIO 20
#define GRAUNALITY_CHANGE_NR_MOLOG 1000
#define NR_CACHED_MOLOGS 5
#define NR_DIFF_MOLOGS 128

enum {
    BYTE_LEVEL = 0,
    BLOCK_LEVEL = 1, // 512 bytes
    PAGE_LEVEL = 2,  // 4096 bytes
};

struct molog_info {
    unsigned int offset;
    unsigned int length;
};

struct molog_node {
    struct rb_node rb_node;
    struct molog_info info;
};

// FIFO cache
// struct cached_mologs {
// 	struct molog_info *entry;
// 	int head;
// 	int tail;
// 	int size;
// 	int capacity;
// };

struct molog_tree {
	char uptodate;
    char granularity;
    unsigned long version;
    unsigned long next_ino;
    unsigned long link;
    struct rb_root root;
    struct molog_info cache_info; // this is an optimization for the sequential update
    struct rw_semaphore mt_rwsem;
};

struct mo_xattr {
	unsigned long next_ino;
	unsigned long inode_version;
    unsigned long version_link;
    unsigned long granularity; // byte-level, block-level, we can store this feature in the tree disk layout
};

struct molog_ioc_info {
	int ctx_id;
	unsigned long cur_version;
	unsigned long new_version;
	int nr_entry;
	int capacity;
};

struct molog_ioc_param {
	struct molog_ioc_info info;
	struct molog_info entrys[NR_DIFF_MOLOGS];
};

struct persist_mgr {
	struct task_struct *molog_worker;
	struct list_head persist_list;
	struct radix_tree_root iroot;
    wait_queue_head_t wait_queue;
	spinlock_t list_lock;
};

struct persist_entry {
	struct list_head list;
	unsigned int ino;
};

struct molog_diff_ctx {
    int used;
    int cont; // continue to get diff
    struct inode *inode;
    struct rb_node *node; // for traversing the tree
    struct molog_tree *diff_tree;
};

struct molog_diff_mgr {
    unsigned long capacity;
    spinlock_t lock;
    struct molog_diff_ctx *ctx;
};

static inline void molog_init_xattr(struct mo_xattr *xattr, unsigned long next_ino, unsigned long inode_version, unsigned long version_link, unsigned long granularity)
{
	xattr->next_ino = next_ino;
	xattr->inode_version = inode_version;
	xattr->version_link = version_link;
    xattr->granularity = granularity;
}

static inline int molog_set_xattr(struct inode *inode, struct page *node_page, struct mo_xattr *xattr)
{
	return __f2fs_setxattr(inode, F2FS_XATTR_INDEX_USER, "user.mbfs", xattr, sizeof(struct mo_xattr), node_page, 0);
}

static inline int molog_get_xattr(struct inode *inode, struct page *node_page, struct mo_xattr *xattr)
{
	return __f2fs_getxattr(inode, F2FS_XATTR_INDEX_USER, "user.mbfs", xattr, sizeof(struct mo_xattr), node_page);
}

static inline unsigned int offset_unit_convert(unsigned int offset, unsigned int from, unsigned int to)
{
    if(from == to) {
        return offset;
    }
    
	if(from == BYTE_LEVEL && to == BLOCK_LEVEL) {
		return offset / BLOCK_SIZE;
	} else if(from == BLOCK_LEVEL && to == BYTE_LEVEL) {
		return offset * BLOCK_SIZE;
	} else if(from == BLOCK_LEVEL && to == PAGE_LEVEL) {
		return offset * (PAGE_SIZE / BLOCK_SIZE);
	} else if(from == PAGE_LEVEL && to == BLOCK_LEVEL) {
		return offset / (PAGE_SIZE / BLOCK_SIZE);
	} else if(from == BYTE_LEVEL && to == PAGE_LEVEL) {
		return offset / PAGE_SIZE;
	} else if(from == PAGE_LEVEL && to == BYTE_LEVEL) {
		return offset * PAGE_SIZE;
	}
    return offset;
}

static inline unsigned int length_unit_convert(unsigned int length, unsigned int from, unsigned int to)
{
    if(from == to)
        return length;

    if(from == BYTE_LEVEL && to == BLOCK_LEVEL) {
        return length % BLOCK_SIZE == 0 ? length / BLOCK_SIZE : length / BLOCK_SIZE + 1;
    } else if(from == BYTE_LEVEL && to == PAGE_LEVEL) {
        return length % PAGE_SIZE == 0 ? length / PAGE_SIZE : length / PAGE_SIZE + 1;
    } else if(from == BLOCK_LEVEL && to == PAGE_LEVEL) {
        return length % (PAGE_SIZE / BLOCK_SIZE) == 0 ? length / (PAGE_SIZE / BLOCK_SIZE) : length / (PAGE_SIZE / BLOCK_SIZE) + 1;
    } else if(from == BLOCK_LEVEL && to == BYTE_LEVEL) {
        return length * BLOCK_SIZE;
    } else if(from == PAGE_LEVEL && to == BLOCK_LEVEL) {
        return length * (PAGE_SIZE / BLOCK_SIZE);
    } else if(from == PAGE_LEVEL && to == BYTE_LEVEL) {
        return length * PAGE_SIZE;
    }
    return length;
}

struct molog_tree *alloc_molog_tree(struct inode *head_inode, int granularity);
void free_molog_tree(struct molog_tree *et);
void traverse_molog_tree(struct molog_tree *et, bool flush_cache);
int persist_molog_tree(struct inode *inode);
int read_file_mologs(struct inode *ver_inode, struct molog_tree *et);
#ifdef SOLFS_ENABLE_ASYNC_LOG_WRITEBACK
int add_molog_persist_entry(struct persist_mgr *pm, struct inode *inode);
#endif
void update_molog_tree(struct molog_tree *et, unsigned int offset, unsigned int len);
void update_cached_molog_tree(struct molog_tree *et, unsigned int offset, unsigned int len);

int molog_do_traverse(struct inode *host_inode);
int molog_open_diff_ctx(struct inode *inode);
void molog_close_diff_ctx(int ctx_id);
struct molog_diff_ctx *molog_get_diff_ctx(int ctx_id);
int molog_do_getdiff(struct inode *inode, struct molog_diff_ctx *ctx, struct molog_ioc_param *mim);
int f2fs_start_molog_worker(struct f2fs_sb_info *sbi);
void f2fs_stop_molog_worker(struct f2fs_sb_info *sbi);
int init_molog(void);
void exit_molog(void);

#endif