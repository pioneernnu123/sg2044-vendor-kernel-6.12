/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_RAMPAGE_H
#define _LINUX_RAMPAGE_H

struct page;
struct file_operations;

#ifdef CONFIG_RAMPAGE
/* Returns an allocated order-0 page with one reference, or NULL if busy. */
struct page *rampage_claim_page(unsigned long pfn);
/* Caller must own a claimed page until all PFN mappings have been removed. */
int rampage_mark_page_bad(struct page *page);
/* Used by the external module's original character-device registration. */
extern struct file_operations rampage_phys_mem_fops;
#endif

#endif /* _LINUX_RAMPAGE_H */
