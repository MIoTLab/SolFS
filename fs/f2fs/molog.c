#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include "molog.h"
#include "segment.h"

#define MAX_DIFF_CTX_NR 1024
#define MOLOG_IS_COMPACT(value) (value & 0x80000000)
#define COMPACT_MOLOG_LENGTH(value) ((value & 0x7FFF0000) >> 16)
#define COMPACT_MOLOG_OFFSET(value) (value & 0xFFFF)
#define COMPACT_MOLOG(offset, len) (((len << 16) | offset) | 0x80000000)
#define MAX_COMPACT_MOLOG_LENGTH 0x7FFF
#define MAX_COMPACT_MOLOG_OFFSET 0xFFFF

#ifdef SOLFS_ENABLE_COMPACT_MOLOG
#define MOLOG_CAN_COMPACT(len, offset) ((len < MAX_COMPACT_MOLOG_LENGTH) && (offset < MAX_COMPACT_MOLOG_OFFSET))
#else
#define MOLOG_CAN_COMPACT(len, offset) 0
#endif


static struct kmem_cache *molog_tree_slab;
static struct kmem_cache *molog_node_slab;
static struct kmem_cache *molog_pentry_slab;
static struct molog_diff_mgr diff_ctx_mgr;

// lets get started with one list;

////////////////////////////////////////////////////////////////// molog tree operations
static int __updata_molog_cache(struct molog_info *new_info, struct molog_info *info)
{
	if((new_info->offset <= info->offset) && (new_info->offset + new_info->length >= info->offset + info->length)) {
		info->offset = new_info->offset;
		info->length = new_info->length;
		return 1;
	}

	if(info->offset <= new_info->offset && new_info->offset + new_info->length <= info->offset + info->length) {
		return 1;
	}

	if((new_info->offset < info->offset) && (new_info->offset + new_info->length >= info->offset + info->length - 1)) {
		info->offset = new_info->offset;
		info->length += info->offset - new_info->offset;
		return 1;
	}
        
	if((new_info->offset <= info->offset + info->length + 1) && (new_info->offset + new_info->length > info->offset + info->length)) {
		info->length += new_info->offset + new_info->length - info->offset - info->length;
		return 1;
	
	}
	return 0;
}

static struct molog_node *insert_molog(struct molog_tree *et, 
                struct molog_info *info,
				struct rb_node *parent, struct rb_node **p)
{
	struct molog_node *en;

	en = f2fs_kmem_cache_alloc(molog_node_slab, GFP_NOFS, true, NULL); //(struct molog_node *) mbfs_calloc(1, sizeof(struct molog_node));
	if (!en)
		return NULL;

    en->info.offset = info->offset;
    en->info.length = info->length;

	rb_link_node(&en->rb_node, parent, p);
	rb_insert_color(&en->rb_node, &et->root);
	return en;
}

static void remove_molog(struct molog_tree *et, struct molog_node *en)
{
    rb_erase(&en->rb_node, &et->root);
    // for fast path we need to consider here
	kmem_cache_free(molog_node_slab, en);
}

static struct rb_node **__lookup_rb_tree_for_insert(struct rb_root *root, struct rb_node **parent,
				unsigned int ofs)
{
	struct rb_node **p = &root->rb_node;
	struct rb_entry *re;

	while (*p) {
		*parent = *p;
		re = rb_entry(*parent, struct rb_entry, rb_node);

		if (ofs < re->ofs)
			p = &(*p)->rb_left;
		else if (ofs >= re->ofs + re->len)
			p = &(*p)->rb_right;
		else {
			mbfs_debug_log("BUG~~ lookup_rb_tree_for_insert: ofs = %u, re->ofs = %u, re->len = %u\n", ofs, re->ofs, re->len);
			BUG();
		}
	}

	return p;
}

static struct molog_node *insert_molog_tree(struct molog_tree *et, 
                struct molog_info *info,
				struct rb_node **insert_p,
				struct rb_node *insert_parent)
{
	struct rb_node **p = &et->root.rb_node;
	struct rb_node *parent = NULL;
	struct molog_node *en = NULL;

	if (insert_p && insert_parent) {
		parent = insert_parent;
		p = insert_p;
		goto do_insert;
	}

	p = __lookup_rb_tree_for_insert(&et->root, &parent, info->offset);
do_insert:
	en = insert_molog(et, info, parent, p);
	if (!en)
		return NULL;
	return en;
}

static struct molog_node *try_merge_mologs(struct molog_tree *et, struct molog_info *ei,
				struct molog_node *prev_ex,
				struct molog_node *next_ex)
{
	struct molog_node *en = NULL;

	if (prev_ex && (prev_ex->info.offset + prev_ex->info.length == ei->offset)) {
        prev_ex->info.length += ei->length;
        ei = &prev_ex->info;
        en = prev_ex;
	}

	if (next_ex && (ei->offset + ei->length == next_ex->info.offset)) { //  __is_front_mergeable(ei, &next_ex->ei)
        next_ex->info.offset = ei->offset;
        next_ex->info.length += ei->length;
		if (en)
			remove_molog(et, prev_ex);
		en = next_ex;
	}

	if (!en)
		return NULL;
	return en;
}


//////////////////////////////////////////////////////// update extents

static struct rb_entry *lookup_neighbor_mologs(struct rb_root *root,
				unsigned int ofs,
				struct rb_entry **prev_entry,
				struct rb_entry **next_entry,
				struct rb_node ***insert_p,
				struct rb_node **insert_parent,
				bool force)
{
	struct rb_node **pnode = &root->rb_node;
	struct rb_node *parent = NULL, *tmp_node;
	struct rb_entry *re;

	*insert_p = NULL;
	*insert_parent = NULL;
	*prev_entry = NULL;
	*next_entry = NULL;

	if (RB_EMPTY_ROOT(root))
		return NULL;

	while (*pnode) {
		parent = *pnode;
		re = rb_entry(*pnode, struct rb_entry, rb_node);

		if (ofs < re->ofs)
			pnode = &(*pnode)->rb_left;
		else if (ofs >= re->ofs + re->len)
			pnode = &(*pnode)->rb_right;
		else
			goto lookup_neighbors;
	}

	*insert_p = pnode;
	*insert_parent = parent;

	re = rb_entry(parent, struct rb_entry, rb_node);
	tmp_node = parent;
	if (parent && ofs > re->ofs)
		tmp_node = rb_next(parent);
	*next_entry = rb_entry_safe(tmp_node, struct rb_entry, rb_node);

	tmp_node = parent;
	if (parent && ofs < re->ofs)
		tmp_node = rb_prev(parent);
	*prev_entry = rb_entry_safe(tmp_node, struct rb_entry, rb_node);
	return NULL;

lookup_neighbors:
	if (ofs == re->ofs || force) {
		/* lookup prev node for merging backward later */
		tmp_node = rb_prev(&re->rb_node);
		*prev_entry = rb_entry_safe(tmp_node, struct rb_entry, rb_node);
	}
	if (ofs == re->ofs + re->len - 1 || force) {
		/* lookup next node for merging frontward later */
		tmp_node = rb_next(&re->rb_node);
		*next_entry = rb_entry_safe(tmp_node, struct rb_entry, rb_node);
	}
	return re;
}

static void __update_molog_tree(struct molog_tree *et, unsigned int offset, unsigned int len)
{
    struct molog_node *en, *en1, *prev_en, *next_en;
    struct molog_info ei, dei;
    struct rb_node **insert_p = NULL, *insert_parent = NULL;
    unsigned int expected_end = offset + len;

    if (!et) {
		return;
	}

	if(offset == 0 && len == 0) {
		return;
	}

	// mbfs_debug_log("update_molog_tree: offset=%u, len=%u\n", offset, len);
    dei.length = 0;
    en = (struct molog_node *) lookup_neighbor_mologs(&et->root, offset,
				(struct rb_entry **) &prev_en,
				(struct rb_entry **) &next_en,
				&insert_p, &insert_parent, false);
    
	if (!en) // 如果en是NULL，表示没有找到cover这个offset的extent
		en = next_en;

    // 此时需要插入一个新的extent, 由于offset + length可以横跨多个extent
    // 这里的合并多个extent的思路是，删除 [offset, offset + len - 1] 之间的所有extent
    // 然后插入一个新的extent
    while (en && en->info.offset < expected_end) { // 无论en是next还是offset所在en, 往后搜索就对了, 所以无所谓
        unsigned int org_end;
        int parts = 0;

        next_en = en1 = NULL; // en1是辅助
        dei = en->info;
        org_end = dei.offset + dei.length; // 当前的en的结束位置

        if (offset > dei.offset) { // pos 位于当前extent的内部
            /**
             * 这可能有多种情况
             * dei.offset < offset < org_end < expected_end
             * dei.offset < offset < expected_end < org_end
             * dei.offset < org_end < offset < expected_end
             */
	        en->info.length = offset - en->info.offset; // 以offset为界，截断当前extent
			prev_en = en;
			parts = 1;
		}

    	if (expected_end < org_end) {
			if (parts) {
                /**
                 * 现在将原来extent截断成了
                 * [dei.offset, offset - 1] 和 [expected_end, org_end - 1]
                 * 然后插入了一个新的extent [expected_end, expected_end - 1]
                 */
                ei.offset = expected_end;
                ei.length = org_end - expected_end;
				en1 = insert_molog_tree(et, &ei, NULL, NULL);
				next_en = en1;
			} else {
                /**
                 * 没有截断, 则表示dei.offset > offset, 而且expected_end < org_end，即情况
                 * offset < dei.offset < expected_end < org_end
                 * offset < expected_end < dei.offset < org_end
                 * 
                 * 那么将其更新[expected_end, org_end - 1]，而原来的extent也是本质被截断
                 * 
                 * 剩下的截断区域是
                 * [offset, expected_end - 1]
                 */
                en->info.offset = expected_end;
                en->info.length = org_end - expected_end;
				next_en = en;
			}
			parts++;
		}

        if (!next_en) { // 如果没有next_en了
			struct rb_node *node = rb_next(&en->rb_node);

			next_en = rb_entry_safe(node, struct molog_node,
						rb_node);
		}

    
        if(parts == 0) {
            remove_molog(et, en);
        }

		if (parts != 1) {
			insert_p = NULL;
			insert_parent = NULL;
		}
		en = next_en;
    }

    // merge or insert new extent
    ei.offset = offset;
    ei.length = len;

	if (!try_merge_mologs(et, &ei, prev_en, next_en))
		insert_molog_tree(et, &ei, insert_p, insert_parent);

}

void update_molog_tree(struct molog_tree *et, unsigned int offset, unsigned int len)
{
	if (!et)
        return;
	down_write(&et->mt_rwsem);
	__update_molog_tree(et, offset, len);
	up_write(&et->mt_rwsem);
}


void update_cached_molog_tree(struct molog_tree *et, unsigned int offset, unsigned int len)
{
	struct molog_info ei;

	ei.offset = offset;
	ei.length = len;

	down_write(&et->mt_rwsem);

	if(et->cache_info.length > 0 && __updata_molog_cache(&ei, &et->cache_info)) // update in cache...
		goto out;

	__update_molog_tree(et, ei.offset, ei.length);
	et->cache_info.offset = ei.offset;
	et->cache_info.length = ei.length;

	mbfs_debug_log("update_cached_molog_tree: et = %lu offset=%u, len=%u, uptodate = %d\n", (unsigned long) et, offset, len, et->uptodate);
out:
	if(et->uptodate)
		et->uptodate = 0;
	up_write(&et->mt_rwsem);
}

static inline void __flush_cached_mologs(struct molog_tree *et)
{
	__update_molog_tree(et, et->cache_info.offset, et->cache_info.length);
}

void traverse_molog_tree(struct molog_tree *et, bool flush_cache)
{
	struct rb_node *node;
	struct molog_node *en;
	int i = 0;
	mbfs_debug_log("------------------- traverse_molog_tree -------------------\n");
	if(flush_cache)
		__flush_cached_mologs(et);

	node = rb_first(&et->root);
	while (node) {
		en = rb_entry(node, struct molog_node, rb_node);
		if(en->info.length)
			mbfs_debug_log( "[%d] offset=%u, length=%u, [%u, %u]\n", i, en->info.offset, en->info.length, en->info.offset, en->info.offset + en->info.length - 1);
		else
			mbfs_debug_log( "[%d] offset=%u, length=%u\n", i, en->info.offset, en->info.length);
		
		node = rb_next(node);
		i++;
	}
	mbfs_debug_log("------------------- end traverse_molog_tree -------------------\n");
}



static int read_page_mologs(struct molog_tree *et, struct page *page, int max_read_mologs)
{
	int i;
	unsigned int *data_array;
	int nr_log_in_page = min_t(int, PAGE_SIZE / sizeof(unsigned int), max_read_mologs); // safe check
	int nr_mologs = 0;

	data_array = kmap_atomic(page);
	if (!data_array)
		return -ENOMEM;

	// read data from page
	for(i = 0; i < nr_log_in_page; i++) {
		unsigned int top_value = le32_to_cpu(data_array[i]);
		unsigned int is_compact = MOLOG_IS_COMPACT(top_value);
		unsigned int offset, len;
		struct molog_info mi;
		
		if(is_compact) {
			len = COMPACT_MOLOG_LENGTH(top_value);
			offset = COMPACT_MOLOG_OFFSET(top_value);
		} else {
			len = top_value;
			offset = le32_to_cpu(data_array[++i]);
		}

		mi.offset = offset;
		mi.length = len;

		mbfs_debug_log("read_page_mologs: max_read_mologs = %d, i = %d, ofs = %u, len = %u\n", max_read_mologs, i, mi.offset, mi.length);
		__update_molog_tree(et, mi.offset, mi.length);
		nr_mologs++;
	}

	kunmap_atomic(data_array);
	return nr_mologs;
}

int read_file_mologs(struct inode *ver_inode, struct molog_tree *et)
{
    loff_t i_size;
    int ret = 0, nr_pages, pgidx;
	int total_molog_read = 0;
	int nr_log_entry;

    i_size = i_size_read(ver_inode);
    if(i_size == 0) {
		mbfs_debug_log("read_file_mologs: i_size = 0\n");
		return 0;
	}

	nr_pages = i_size % PAGE_SIZE == 0 ? i_size / PAGE_SIZE : i_size / PAGE_SIZE + 1;
	nr_log_entry = i_size / sizeof(unsigned int);

	mbfs_debug_log("read_file_mologs: i_size = %lld, nr_pages = %d\n", i_size, nr_pages);

	for(pgidx = 0; pgidx < nr_pages; pgidx++) {
		struct page *page;
		int molog_read;
		int nr_log_in_page = min_t(int, nr_log_entry, PAGE_SIZE / sizeof(unsigned int));
		
		page = f2fs_find_data_page(ver_inode, pgidx, NULL); // shall we optimize for the next_pgofs?
		if (IS_ERR(page)) {
			ret = -ENOMEM;
			goto out;
		}
		
		molog_read = read_page_mologs(et, page, nr_log_in_page);
		mbfs_debug_log("read_file_mologs: pgidx = %d, molog_read = %d, total_molog_read = %d\n", pgidx, molog_read, total_molog_read);
		if(molog_read <= 0) {
			total_molog_read += molog_read;
			f2fs_put_page(page, 0);
			break;
		}
		total_molog_read += molog_read;
		f2fs_put_page(page, 0);
		nr_log_entry -= nr_log_in_page;
	}
	ret = total_molog_read;
out:
	return ret;
}

struct molog_tree *alloc_molog_tree(struct inode *head_inode, int granularity)
{
    int ret;
    struct molog_tree *et;

    et = f2fs_kmem_cache_alloc(molog_tree_slab, GFP_NOFS, true, NULL);
    if (!et)
		return NULL;

    memset(et, 0, sizeof(struct molog_tree));
	et->root = RB_ROOT;
	et->uptodate = 1;
	init_rwsem(&et->mt_rwsem);

	et->cache_info.offset = 0;
	et->cache_info.length = 0;

	if(!head_inode || IS_ERR(head_inode)) {
        et->granularity = granularity;
	} else {
		ret = read_file_mologs(head_inode, et);
		if(ret < 0) {
			goto err;
		}
		et->granularity = F2FS_I(head_inode)->granularity;
		et->version = F2FS_I(head_inode)->inode_version;
		et->next_ino = F2FS_I(head_inode)->next_ino;
		et->link = F2FS_I(head_inode)->version_link;
	}

    return et;
err:  
	kmem_cache_free(molog_tree_slab, et);
    return NULL;
}

void free_molog_tree(struct molog_tree *et)
{
	struct rb_node *node, *next;
	struct molog_node *en;
	down_write(&et->mt_rwsem);
	node = rb_first(&et->root);
	while (node) {
		next = rb_next(node);
		en = rb_entry(node, struct molog_node, rb_node);
		remove_molog(et, en);
		node = next;
	}
	up_write(&et->mt_rwsem);
	kmem_cache_free(molog_tree_slab, et);
}

void reset_molog_tree(struct molog_tree *et)
{
	struct rb_node *node, *next;
	struct molog_node *en;
	down_write(&et->mt_rwsem);
	node = rb_first(&et->root);
	while (node) {
		next = rb_next(node);
		en = rb_entry(node, struct molog_node, rb_node);
		remove_molog(et, en);
		node = next;
	}

	et->cache_info.offset = 0;
	et->cache_info.length = 0;

	up_write(&et->mt_rwsem);
}

static unsigned long average_len = 0;
static unsigned long avgcnt = 0;
static inline unsigned int molog_can_merge(unsigned int last_end_pos, unsigned int now_ofs, unsigned int granularity_size)
{
	unsigned int len = now_ofs - last_end_pos;
	average_len += len;
	avgcnt++;
	if(len <= granularity_size)
		return 1;
	else
		return 0;
}

static unsigned int convert_tree_to_data_array(struct molog_tree *ptree, unsigned int *data_array, unsigned int array_capacity, unsigned int granularity_size, unsigned int *merge_cnt)
{
	int i = 0;
	struct rb_node *node;
	struct molog_node *en;
	unsigned int last_end_pos = 0, nr_can_merge = 0;

	node = rb_first(&ptree->root);
	while (node) {
		en = rb_entry(node, struct molog_node, rb_node);
		
		if(i > 0) {
			nr_can_merge += molog_can_merge(last_end_pos, en->info.offset, granularity_size);
		}
		// printf("ofs = %u, length = %u\n", en->info.offset, en->info.length);
		////////////// persist
		if(MOLOG_CAN_COMPACT(en->info.length, en->info.offset)) {
			//mbfs_debug_log("[mbfs_persist_molog_tree] can compact~~~\n");
			mbfs_debug_log("---> compact: ofs = %u, len = %u\n", en->info.offset, en->info.length);
			data_array[i] = COMPACT_MOLOG(en->info.offset, en->info.length);
		} else {
			//mbfs_debug_log("[mbfs_persist_molog_tree] no compact~~~\n");
			mbfs_debug_log("---> no compact: ofs = %u, len = %u\n", en->info.offset, en->info.length);
			data_array[i] = en->info.length;
			data_array[i + 1] = en->info.offset;
			i++;
		}
		
		if(i >= array_capacity) {
			mbfs_debug_log("!!!! [convert_tree_to_data_array] exceed buffer size\n");
			BUG_ON(i == array_capacity);
		}
		//////////////
		last_end_pos = en->info.offset + en->info.length;
		node = rb_next(node);
		i++;
	}
	*merge_cnt = nr_can_merge;
	return i;
}

static int __persist_to_inode(struct inode *head_inode, unsigned int *data_array, int len)
{
	int i, j, k, ret;
	int nr_bytes = len * sizeof(unsigned int);
	int nr_pages = nr_bytes % PAGE_SIZE == 0 ? nr_bytes / PAGE_SIZE : nr_bytes / PAGE_SIZE + 1;
	size_t old_size = i_size_read(head_inode);
	size_t new_size = nr_bytes;

	if(new_size < old_size)	{
		mbfs_debug_log("truncate old_size = %lu, new_size = %d, nr_bytes = %d\n", old_size, new_size, nr_bytes);
		truncate_setsize(head_inode, new_size);	
		ret = f2fs_truncate_blocks(head_inode, new_size, 1);
		if(ret < 0) {
			mbfs_debug_log("Failed to truncate blocks, ret = %d\n", ret);
			goto err;
		}
	} else if(new_size > old_size) {
		mbfs_debug_log("expand old_size = %lu, new_size = %d, nr_bytes = %d\n", old_size, new_size, nr_bytes);
		ret = f2fs_expand_inode_data(head_inode, 0, new_size, 0);
		if(ret < 0) {
			mbfs_debug_log("Failed to expand inode data, ret = %d\n", ret);
			goto err;
		}
	}

	mbfs_debug_log("nr_pages = %d, new file size = %d\n", nr_pages, i_size_read(head_inode));
	k = 0;
	for(i = 0; i < nr_pages; i++) {
		struct page *page;
		unsigned int *data, copy_len;
		mbfs_debug_log("persist to inode: %d, nr_pages = %d\n", i, nr_pages);
		page = f2fs_get_lock_data_page(head_inode, i, true);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			mbfs_debug_log("Failed to get read data page, ret = %d\n", ret);
			goto err;
		}

		copy_len = min_t(unsigned int, nr_bytes - i * PAGE_SIZE, PAGE_SIZE);

		data = kmap(page);
		
		for(j = 0; j < copy_len / sizeof(unsigned int); j++) {
			data[j] = cpu_to_le32(data_array[k]);
			k++;
			if(k >= len) {
				break;
			}
		}

		kunmap(page);
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
	// shall we sync for the inode?
	return 0;
err:
	return ret;
}

static int __persist_molog_tree(struct inode *inode, struct inode *head_inode, struct molog_tree *ptree)
{
	unsigned int *data_array;
	char *buffer;
	const int buffer_size = PAGE_SIZE * 10; // For test: maximum 40960 * 1024 / 16 = 2560 mologs
	const int array_capacity = buffer_size / sizeof(unsigned int);
	unsigned int nr_molog, nr_can_merge = 0;
	unsigned int granularity_size = 0;

	if(ptree->granularity == BYTE_LEVEL) {
		granularity_size = BLOCK_SIZE;
	} else if(ptree->granularity == BLOCK_LEVEL) {
		granularity_size = PAGE_SIZE;
	}

	buffer = (char *) kmalloc(buffer_size, GFP_KERNEL); // for simplicity, we use a large-enough page size buffer
	if (!buffer)
		return -1;

	data_array = (unsigned int *) buffer;

	nr_molog = convert_tree_to_data_array(ptree, data_array, array_capacity, granularity_size, &nr_can_merge);


	/**
	 * when the number of extents that can be merged (i.e., nr_can_merge) is more than GRAUNALITY_CHANGE_RATIO of the total number of extents, we can change the granularity
	 * 
	 * note the conversion of granularity
	 * check its correctness..
	 * 
	 * (ptree->granularity == BYTE_LEVEL || ptree->granularity == BLOCK_LEVEL) --> PAGE LEVEL is the highest level, we can increase its granularity
	 */
	if(nr_molog > 0 && (ptree->granularity == BYTE_LEVEL || ptree->granularity == BLOCK_LEVEL)) {
		int ratio = nr_can_merge * 100 / nr_molog;
		unsigned int old_granularity = ptree->granularity;
		unsigned int new_granularity = old_granularity + 1; // next level
		int j;
		if(ratio > GRAUNALITY_CHANGE_RATIO && nr_molog > GRAUNALITY_CHANGE_NR_MOLOG) {
			struct molog_tree *new_tree = alloc_molog_tree(NULL, new_granularity);
			for(j = 0; j < nr_molog; j++) {
				unsigned int len, offset;
				if(MOLOG_IS_COMPACT(data_array[j])) {
					len = COMPACT_MOLOG_LENGTH(data_array[j]);
					offset = COMPACT_MOLOG_OFFSET(data_array[j]);
				} else {
					len = data_array[j];
					offset = data_array[j + 1];
					j++;
				}
				__update_molog_tree(new_tree, 
					offset_unit_convert(offset, old_granularity, new_granularity), 
					length_unit_convert(len, old_granularity, new_granularity));
			}

			F2FS_I(head_inode)->next_ino = ptree->next_ino;
			F2FS_I(head_inode)->inode_version = ptree->version;
			F2FS_I(head_inode)->version_link = ptree->link;
			F2FS_I(head_inode)->granularity = new_granularity;

			memset(buffer, 0, buffer_size);
			nr_molog = convert_tree_to_data_array(new_tree, data_array, array_capacity, 0, &nr_can_merge);

			F2FS_I(inode)->granularity = new_granularity; // it is ok as the file will be released or inserted a new inode.
			free_molog_tree(new_tree);
		}
	}

	if(nr_molog > 0) {
		int ret = __persist_to_inode(head_inode, data_array, nr_molog);
		if(ret < 0) {
			mbfs_debug_log("Failed to persist molog tree");
		}
	}

	kfree(buffer);
	return 0;
}

/**
 * we may need to a lock to protect the molog tree when persisting and allocating.
 */
int persist_molog_tree(struct inode *inode)
{
	int ret = 0;
	struct rb_node *node;
	struct molog_node *en;
	struct molog_tree *et, *ptree;
	struct inode *head_inode;

	et = F2FS_I(inode)->molog_tree;
	if(!et) {
		mbfs_debug_log("mbfs: invalid molog tree\n");
		return -1;
	}
	mbfs_debug_log("update_cached_molog_tree: ino = %u et = %lu, uptodate = %d\n", inode->i_ino, (unsigned long) et, et->uptodate);
	down_write(&et->mt_rwsem);
	if(et->uptodate) {
		mbfs_debug_log("mbfs: molog tree is up-to-date\n");
		goto out;
	}
	
	mbfs_debug_log("start to persist molog tree, host_inode = %lu, head_inode = %u\n", inode->i_ino, F2FS_I(inode)->next_ino);
	head_inode = f2fs_iget(inode->i_sb, F2FS_I(inode)->next_ino);
	if(IS_ERR(head_inode)) {
		mbfs_debug_log("[mbfs_persist_molog_tree] open head_inode fail, ret = %ld\n", PTR_ERR(head_inode));
		goto out;
	}

	// we ensure the granuarity of file->molog_tree is the same as the backend molog tree.
	ptree = alloc_molog_tree(head_inode, F2FS_I(inode)->granularity);

	BUG_ON(ptree->granularity != F2FS_I(inode)->granularity);
	// printf("[persist] granularity 2 = %d\n", ptree->granularity);
	// pthread_rwlock_wrlock(&et->lock);

	__flush_cached_mologs(et);
	mbfs_debug_log("flush cached mologs!!\n");
	traverse_molog_tree(et, false);

	node = rb_first(&et->root); // merge the file->molog_tree with the backend tree
	while (node) {
		en = rb_entry(node, struct molog_node, rb_node);
		__update_molog_tree(ptree, en->info.offset, en->info.length);
		node = rb_next(node);
	}

	// persist
	ret = __persist_molog_tree(inode, head_inode, ptree);
	if(ret < 0) {
		mbfs_debug_log("Failed to persist molog tree");
		goto release;
	}
	f2fs_mark_inode_dirty_sync(head_inode, true);
	et->uptodate = 1;
release:
	free_molog_tree(ptree);
	iput(head_inode);
out:
	up_write(&et->mt_rwsem);
	return ret;
}


///////////////////////// Get Diff Interfaces

int molog_do_traverse(struct inode *host_inode)
{
	unsigned long cur_ver;
	struct inode *cur_inode;

	if(F2FS_I(host_inode)->next_ino <= 0) {
		mbfs_debug_log("mbfs: invalid next_ino\n");
		return -ENOENT;
	}

	cur_inode = f2fs_iget(host_inode->i_sb, F2FS_I(host_inode)->next_ino);
    if(IS_ERR(cur_inode)) {
        mbfs_debug_log("mbfs: versioning, failed to open new head inode\n");
        return PTR_ERR(cur_inode);
    }

	mbfs_debug_log("[molog_do_traverse] ============== host ino = %lu, next ino = %lu, host ver = %lu\n", host_inode->i_ino, F2FS_I(host_inode)->next_ino, F2FS_I(host_inode)->inode_version);
	cur_ver = F2FS_I(cur_inode)->inode_version;
	while(cur_ver >= 0) {
		int next_ino;
		mbfs_debug_log("[molog_do_traverse] ============== cur ino = %lu, next ino = %lu, cur ver = %lu, i_size = %lu, vlink = %d, ilink = %d\n", 
			cur_inode->i_ino, F2FS_I(cur_inode)->next_ino, cur_ver, i_size_read(cur_inode), F2FS_I(cur_inode)->version_link, cur_inode->i_nlink);
		next_ino = F2FS_I(cur_inode)->next_ino;
		iput(cur_inode);

		if(next_ino <= 0)
			break;


		cur_inode = f2fs_iget(host_inode->i_sb, next_ino);
        if(IS_ERR(cur_inode)) {
            mbfs_debug_log("mbfs: versioning, failed to open new head file\n");
            return PTR_ERR(cur_inode);
        }

		cur_ver = F2FS_I(cur_inode)->inode_version;
	}

	return 0;
}

static struct molog_tree *traverse_versioned_file_for_diff(struct inode *inode, unsigned long tgt_ver, unsigned int *has_mologs)
{
	struct molog_tree *diff_tree;
	struct inode *cur_inode;
	unsigned long cur_ver;

	*has_mologs = 0;
	if(F2FS_I(inode)->next_ino <= 0) {
		mbfs_debug_log("mbfs: invalid next_ino\n");
		return NULL;
	}

	// traverse the versioned file to get the diff
	cur_inode = f2fs_iget(inode->i_sb, F2FS_I(inode)->next_ino);
    if(IS_ERR(cur_inode)) {
        mbfs_debug_log("mbfs: versioning, failed to open new head inode\n");
        return NULL;
    }

	diff_tree = alloc_molog_tree(0, BYTE_LEVEL);

    mbfs_debug_log("mbfs: versioning, start get_mbfs_xattr = %lu\n", cur_inode->i_ino);
	mbfs_debug_log("[traverse_versioned_file_for_diff] ============== init tgt_ver = %lu, next ino = %lu\n", tgt_ver, F2FS_I(cur_inode)->next_ino);

	cur_ver = F2FS_I(cur_inode)->inode_version;
	while(cur_ver >= tgt_ver) {
		int nr_mologs;
		int next_ino;
		mbfs_debug_log("[traverse_versioned_file_for_diff] ============== cur ver = %lu, tgt_ver = %lu, next ino = %lu\n", cur_ver, tgt_ver, F2FS_I(cur_inode)->next_ino);
		
		nr_mologs = read_file_mologs(cur_inode, diff_tree);
		if(nr_mologs > 0) {
			*has_mologs = 1;
		}

		next_ino = F2FS_I(cur_inode)->next_ino;
		iput(cur_inode);

		if(next_ino <= 0)
			break;

		cur_inode = f2fs_iget(inode->i_sb, next_ino);
        if(IS_ERR(cur_inode)) {
            mbfs_debug_log("mbfs: versioning, failed to open new head file\n");
			free_molog_tree(diff_tree);
            return NULL;
        }
        mbfs_debug_log("mbfs: versioning, start get_mbfs_xattr = %lu\n", cur_inode->i_ino);

		cur_ver = F2FS_I(cur_inode)->inode_version;
	}
	return diff_tree;
}

static int copy_ioc_mologs(struct molog_ioc_param *mim, struct molog_tree *et, struct rb_node **ten)
{
	struct rb_node *node;
	struct molog_node *en;
	
	mim->info.nr_entry = 0;
	mbfs_debug_log("start copy ioc mologs 1\n");
	if(et) {
		node = rb_first(&et->root);
	} else {
		node = *ten;
	}

	while (node) {
		en = rb_entry(node, struct molog_node, rb_node);
		if(en->info.length)
			mbfs_debug_log( "ttt [%d] offset=%u, length=%u, [%u, %u]\n", mim->info.nr_entry, en->info.offset, en->info.length, en->info.offset, en->info.offset + en->info.length - 1);
		else
			mbfs_debug_log( "ttt [%d] offset=%u, length=%u\n", mim->info.nr_entry, en->info.offset, en->info.length);
		
		if(mim->info.nr_entry < mim->info.capacity) {
			mim->entrys[mim->info.nr_entry] = en->info;
			mim->info.nr_entry++;
		} else {
			*ten = node;
			mbfs_debug_log("copy ioc mologs: exceed buffer size\n");
			return -EAGAIN;
		}
		node = rb_next(node);
	}

	return 0;
}


static void update_connection(struct inode *host_inode, struct inode *new_head_inode)
{
	F2FS_I(new_head_inode)->next_ino = F2FS_I(host_inode)->next_ino;
	F2FS_I(new_head_inode)->inode_version = F2FS_I(host_inode)->inode_version + 1;
	F2FS_I(new_head_inode)->version_link = 1;
	F2FS_I(new_head_inode)->granularity = F2FS_I(host_inode)->granularity;
	F2FS_I(host_inode)->next_ino = new_head_inode->i_ino;
	F2FS_I(host_inode)->inode_version += F2FS_I(new_head_inode)->inode_version;
}

static int insert_head_versioned_inode(struct inode *host_inode)
{
    int err = 0;
	struct inode *new_head_inode;
	struct page *page;
	struct f2fs_sb_info *sbi = F2FS_I_SB(host_inode);

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;
	if (!f2fs_is_checkpoint_ready(sbi))
		return -ENOSPC;

    if(is_inode_flag_set(host_inode, FI_HAS_MOLOG)) {
        reset_molog_tree(F2FS_I(host_inode)->molog_tree); // the molog tree is persisted before
    }

	new_head_inode = f2fs_new_version_inode(host_inode); // the head_inode is lcoked here
	if (IS_ERR(new_head_inode))
		return PTR_ERR(new_head_inode);

	new_head_inode->i_op = &f2fs_file_inode_operations;
	new_head_inode->i_fop = &f2fs_file_operations;
	new_head_inode->i_mapping->a_ops = &f2fs_dblock_aops;

	// new inode is already locked here
	f2fs_lock_op(sbi);
	err = f2fs_acquire_orphan_inode(sbi);
	if (err)
		goto fail_inode;

	f2fs_down_write(&F2FS_I(new_head_inode)->i_sem);

	page = f2fs_new_inode_page(new_head_inode); // logic of f2fs_init_inode_metadata
	if (IS_ERR(page)) {
		err = PTR_ERR(page);
		f2fs_up_write(&F2FS_I(new_head_inode)->i_sem);
		f2fs_release_orphan_inode(sbi);
		goto fail_inode;
	}

	f2fs_wait_on_page_writeback(page, NODE, true, true);
	f2fs_put_page(page, 1);

	clear_inode_flag(new_head_inode, FI_NEW_INODE);
	f2fs_update_time(sbi, REQ_TIME);

	f2fs_up_write(&F2FS_I(new_head_inode)->i_sem);

	f2fs_add_orphan_inode(new_head_inode); // add to orphan inode list
	f2fs_alloc_nid_done(sbi, new_head_inode->i_ino);

	// now we allocate a new inode with orphan state and its link is set to 0
	// for consistency, we need to update the connection between the head inode and the host inode
	// and then remove orphan state of the new inode

	f2fs_down_write(&F2FS_I(host_inode)->i_sem);
	f2fs_down_write(&F2FS_I(new_head_inode)->i_sem);
	
	update_connection(host_inode, new_head_inode);
	// f2fs_i_links_write(new_head_inode, true);

	f2fs_up_write(&F2FS_I(new_head_inode)->i_sem);
	f2fs_up_write(&F2FS_I(host_inode)->i_sem);
	
	spin_lock(&new_head_inode->i_lock);
	new_head_inode->i_state |= I_LINKABLE;
	spin_unlock(&new_head_inode->i_lock);

	f2fs_remove_orphan_inode(sbi, new_head_inode->i_ino); // removing the orphan inode will do the f2fs_release_orphan_inode

	f2fs_unlock_op(sbi);
	unlock_new_inode(new_head_inode);
	f2fs_balance_fs(sbi, true);

    if(!is_inode_flag_set(host_inode, FI_HAS_MOLOG)) {
		F2FS_I(host_inode)->molog_tree = alloc_molog_tree(NULL, BYTE_LEVEL);
		set_inode_flag(host_inode, FI_HAS_MOLOG);
		set_inode_flag(host_inode, FI_HAS_MOLOG_HOST);
    }
	set_inode_flag(new_head_inode, FI_HAS_MOLOG);
	f2fs_mark_inode_dirty_sync(host_inode, true);
	f2fs_mark_inode_dirty_sync(new_head_inode, true);
	
	mbfs_debug_log("host inode icount = %lu, ilink = %lu, new head inode icount = %lu, ilink = %lu\n", 
		atomic_read(&host_inode->i_count), host_inode->i_nlink, atomic_read(&new_head_inode->i_count), new_head_inode->i_nlink);

	// f2fs_mark_inode_dirty_sync(host_inode, false);
	// f2fs_mark_inode_dirty_sync(new_head_inode, false);

	iput(new_head_inode);
	return 0;
fail_inode:
	f2fs_unlock_op(sbi);
	f2fs_handle_failed_inode(new_head_inode);
	return err;
}

///////////////////////////////////////////////////  for get diff ctx
int molog_open_diff_ctx(struct inode *inode)
{
	int i;
	int ctx_id = -1;

	spin_lock(&diff_ctx_mgr.lock);
	for(i = 0; i < MAX_DIFF_CTX_NR; i++) {
		if(!diff_ctx_mgr.ctx[i].used) {
			ctx_id = i;
			diff_ctx_mgr.ctx[ctx_id].used = 1;
			diff_ctx_mgr.ctx[ctx_id].cont = 0;
			diff_ctx_mgr.ctx[ctx_id].inode = inode;
			diff_ctx_mgr.ctx[ctx_id].node = NULL;
			break;
		}
	}
	spin_unlock(&diff_ctx_mgr.lock);

	return ctx_id;
}

void molog_close_diff_ctx(int ctx_id)
{
	if(ctx_id < 0 || ctx_id >= MAX_DIFF_CTX_NR) {
		return;
	}

	spin_lock(&diff_ctx_mgr.lock);
	diff_ctx_mgr.ctx[ctx_id].used = 0;
	diff_ctx_mgr.ctx[ctx_id].cont = 0;
	diff_ctx_mgr.ctx[ctx_id].inode = NULL;
	diff_ctx_mgr.ctx[ctx_id].node = NULL;
	spin_unlock(&diff_ctx_mgr.lock);
}

struct molog_diff_ctx *molog_get_diff_ctx(int ctx_id)
{
	if(ctx_id < 0 || ctx_id >= MAX_DIFF_CTX_NR) {
		return NULL;
	}

	return &diff_ctx_mgr.ctx[ctx_id];
}
///////////////////////////////////////////////////

int molog_do_getdiff(struct inode *inode, struct molog_diff_ctx *ctx, struct molog_ioc_param *mim)
{
    int ret = 0;
    if(!inode || !mim || mim->info.capacity < 1) {
		return -EINVAL;
	}

	/**
     * if this file is not changed, we do not insert a new inode into the chain
	 * for this scenario, we need to check the version inputted by the cloud backup APP, and 
	 * if the version is zero, that means this is the first time to backup the file, so the version link + 1
	 * if the version is not zero, we need to traverse the versioned file to get the diff, and we do not need to update the version link
	 */

	mbfs_debug_log("point 1, has molog = %d\n", is_inode_flag_set(inode, FI_HAS_MOLOG));
	inode_lock(inode);

	if(ctx->cont) {
		mbfs_debug_log("------------------ cont!\n");
		ret = copy_ioc_mologs(mim, NULL, &ctx->node);
		if(ret < 0) {
			goto out;
		}
		// if the number of mologs is less than the capacity, we need to set the finished flag
		if(ctx->diff_tree)
			free_molog_tree(ctx->diff_tree);
		ctx->diff_tree = NULL;
		ctx->cont = 0;
		goto insert;
	}

	if(!is_inode_flag_set(inode, FI_HAS_MOLOG)) {
		ssize_t fsize = i_size_read(inode);
		mbfs_debug_log("point 2.2\n");
		mim->info.nr_entry = 1;
		mim->entrys[0].offset = 0;
		mim->entrys[0].length = length_unit_convert(fsize, BYTE_LEVEL, F2FS_I(inode)->granularity);
	} else {
		struct molog_tree *diff_tree;
		unsigned int has_mologs = 0;
		mbfs_debug_log("point 2.3, cur_version = %d\n", mim->info.cur_version);

		// shall we ensure all data writeback here, filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
		persist_molog_tree(inode);

		diff_tree = traverse_versioned_file_for_diff(inode, mim->info.cur_version, &has_mologs);
		if(!has_mologs) {
			mbfs_debug_log("mbfs: versioning, no mologs in head\n");
			mim->info.nr_entry = 0;
			mim->info.new_version = mim->info.cur_version;
			ctx->cont = 1;
			goto out;
		}

		// when has_mologs = true, the diff tree should be not NULL

		ret = copy_ioc_mologs(mim, diff_tree, &ctx->node);
		if(ret < 0) {
			ctx->diff_tree = diff_tree;
			ctx->cont = 1;
			goto out;
		} else {
			free_molog_tree(diff_tree);
		}	
	}

insert:
    ret = insert_head_versioned_inode(inode);
    if(ret < 0) {
        mbfs_debug_log("mbfs: versioning, failed to insert head versioned inode\n");
    }
	mim->info.new_version = F2FS_I(inode)->inode_version;
	mbfs_debug_log("mbfs: versioning, get diff done, next ino = %d, has molog = %d\n", F2FS_I(inode)->next_ino, is_inode_flag_set(inode, FI_HAS_MOLOG));
out:
	inode_unlock(inode);
    return ret;
}
#ifdef SOLFS_ENABLE_ASYNC_LOG_WRITEBACK
int add_molog_persist_entry(struct persist_mgr *pm, struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct persist_entry *pe;
	struct molog_tree *et;
	int ret = 0;
	
	et = F2FS_I(inode)->molog_tree;

	spin_lock(&pm->list_lock);
	down_read(&et->mt_rwsem);
	
	mbfs_debug_log("point 1: ino = %lu\n", inode->i_ino);

	if(et->uptodate) {
		mbfs_debug_log("mbfs: versioning, molog tree is up-to-date\n");
		goto out;
	}

	pe = radix_tree_lookup(&pm->iroot, inode->i_ino);
	if(pe)
		goto out;

	mbfs_debug_log("point 2: ino = %lu\n", inode->i_ino);
	pe = kmem_cache_alloc(molog_pentry_slab, GFP_KERNEL);
	if (!pe) {
		ret = -ENOMEM;
		goto out;
	}

	mbfs_debug_log("point 3: ino = %lu\n", inode->i_ino);
	pe->ino = inode->i_ino;
	radix_tree_insert(&pm->iroot, inode->i_ino, pe);
	list_add(&pe->list, &sbi->pst_mgr->persist_list);
	mbfs_debug_log("point 4: ino = %lu\n", inode->i_ino);
out:
	up_read(&et->mt_rwsem);
	spin_unlock(&pm->list_lock);
	return ret;
}

static int handle_persiste_task(struct f2fs_sb_info *sbi, struct list_head *plist)
{
	struct inode *host_inode;
	struct persist_entry *pe, *next_pe;
	list_for_each_entry_safe_reverse(pe, next_pe, plist, list) {
		mbfs_debug_log("mbfs: versioning 1, persist inode = %lu\n", pe->ino);
		if(!pe->ino) {
			goto next;
		}

		host_inode = f2fs_iget(sbi->sb, pe->ino);
		if (IS_ERR(host_inode)) {
			mbfs_debug_log("mbfs: versioning, failed to open host inode, err = %ld\n", PTR_ERR(host_inode));
			goto next;
		}

		// inode_lock(host_inode);
		mbfs_debug_log("mbfs: versioning 2, persist inode = %lu, next ino = %d\n", host_inode->i_ino, F2FS_I(host_inode)->next_ino);
		persist_molog_tree(host_inode);

		// inode_unlock(host_inode);
		iput(host_inode);
next:
		radix_tree_delete(&sbi->pst_mgr->iroot, pe->ino);
		list_del(&pe->list);
		kmem_cache_free(molog_pentry_slab, pe);
	}

	return 0;
}

static int molog_worker_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	wait_queue_head_t *wq = &sbi->pst_mgr->wait_queue;
	struct list_head to_persist_list;
    unsigned long wait_ms = 5000;
	int stop = 0;
	int nr_cnt = 0;

	INIT_LIST_HEAD(&to_persist_list);
    while(1) {
		struct persist_entry *pe, *next_pe;

		wait_event_interruptible_timeout(*wq,
								kthread_should_stop(),
								msecs_to_jiffies(wait_ms));

        if(kthread_should_stop())
            stop = 1;

		spin_lock(&sbi->pst_mgr->list_lock);

        // get requests from queue
		nr_cnt = 0;
		list_for_each_entry_safe_reverse(pe, next_pe, &sbi->pst_mgr->persist_list, list) {
			list_del(&pe->list);
			list_add(&pe->list, &to_persist_list);
			nr_cnt++;
		}

		// do persistence for to_persist_list
		if(nr_cnt > 0) {
			mbfs_debug_log("molog_worker_func: to_persist_list ... nr_cnt = %d \n", nr_cnt);
			handle_persiste_task(sbi, &to_persist_list);
		}

		spin_unlock(&sbi->pst_mgr->list_lock);

		if(stop)
			break;
    }

	return 0;
}
#endif

int f2fs_start_molog_worker(struct f2fs_sb_info *sbi)
{
#ifdef SOLFS_ENABLE_ASYNC_LOG_WRITEBACK
	sbi->pst_mgr = f2fs_kzalloc(sbi, sizeof(struct persist_mgr), GFP_KERNEL);
	if (!sbi->pst_mgr)
		return -ENOMEM;
	printk(KERN_INFO "f2fs: molog worker started, p1\n");
	/**
	 * we start with one thread for simplicity
	 * for multiple threads, we can refer to the implementation of cachesifter
	 */
	INIT_LIST_HEAD(&sbi->pst_mgr->persist_list);
	spin_lock_init(&sbi->pst_mgr->list_lock);
	INIT_RADIX_TREE(&sbi->pst_mgr->iroot, GFP_NOFS);

	init_waitqueue_head(&sbi->pst_mgr->wait_queue);
    sbi->pst_mgr->molog_worker = kthread_run(molog_worker_func, sbi, "f2fs_molog_worker");
    if (IS_ERR(sbi->pst_mgr->molog_worker)) {
        return PTR_ERR(sbi->pst_mgr->molog_worker);
    }
	printk(KERN_INFO "f2fs: molog worker started, p2\n");
#endif
    return 0;
}

void f2fs_stop_molog_worker(struct f2fs_sb_info *sbi)
{
#ifdef SOLFS_ENABLE_ASYNC_LOG_WRITEBACK
	if (!sbi->pst_mgr)
		return;
	printk(KERN_INFO "f2fs: stopping molog worker\n");
	kthread_stop(sbi->pst_mgr->molog_worker);
	kfree(sbi->pst_mgr);
#endif
}

int init_molog(void)
{
	molog_tree_slab = f2fs_kmem_cache_create("f2fs_molog_tree",
			sizeof(struct molog_tree));
	if (!molog_tree_slab)
		goto fail;

	molog_node_slab = f2fs_kmem_cache_create("f2fs_molog_entry",
			sizeof(struct molog_node));
	if (!molog_node_slab) {
		goto free_molog_tree_slab;
	}

	molog_pentry_slab = f2fs_kmem_cache_create("f2fs_molog_pentry",
			sizeof(struct persist_entry));
	if (!molog_pentry_slab) {
		goto free_molog_node_slab;
	}

	diff_ctx_mgr.capacity = MAX_DIFF_CTX_NR;
	diff_ctx_mgr.ctx = kmalloc(sizeof(struct molog_diff_ctx) * diff_ctx_mgr.capacity, GFP_KERNEL | __GFP_ZERO);
	if(!diff_ctx_mgr.ctx) {
		goto free_molog_pentry_slab;
	}
	spin_lock_init(&diff_ctx_mgr.lock);

	return 0;
free_molog_pentry_slab:
	kmem_cache_destroy(molog_pentry_slab);
free_molog_node_slab:
	kmem_cache_destroy(molog_node_slab);
free_molog_tree_slab:
	kmem_cache_destroy(molog_tree_slab);
fail:
	return -ENOMEM;
}

void exit_molog(void)
{
	kfree(diff_ctx_mgr.ctx);
	kmem_cache_destroy(molog_pentry_slab);
	kmem_cache_destroy(molog_node_slab);
	kmem_cache_destroy(molog_tree_slab);
}

