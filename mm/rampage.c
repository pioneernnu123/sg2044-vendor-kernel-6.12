// SPDX-License-Identifier: GPL-2.0-only
/* Version-1 backend for the unmodified external RAMpage phys_mem module. */
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rampage.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define RAMPAGE_VERSION		1
#define RAMPAGE_SOURCE_BUDDY	0x00002
#define RAMPAGE_INVALID_PFN	0x80000

/* Match phys_mem.h and the existing RV64/x86-64 Python ctypes structures. */
struct rampage_frame_request {
	unsigned long pfn;
	unsigned long allowed_sources;
};

struct rampage_frame_status {
	struct rampage_frame_request request;
	u64 offset;
	unsigned long pfn;
	u64 cost_jiffies;
	unsigned long source;
	unsigned long page_cookie;
};

struct rampage_request {
	unsigned long version;
	unsigned long count;
	struct rampage_frame_request __user *frames;
};

struct rampage_poison_request {
	unsigned long version;
	unsigned long pfn;
};

#define RAMPAGE_REQUEST_PAGES	_IOW('K', 0, struct rampage_request)
#define RAMPAGE_MARK_BAD		_IOW('K', 1, struct rampage_poison_request)

struct rampage_frame {
	struct rampage_frame_status status;
	struct page *page;
};

struct rampage_session {
	struct mutex lock;
	struct module *owner;
	struct rampage_frame *frames;
	unsigned long nr_frames;
	unsigned long mapping_size;
	unsigned int mappings;
};

static_assert(sizeof(struct rampage_frame_status) == 56);
static_assert(RAMPAGE_REQUEST_PAGES == 0x40184b00);
static_assert(RAMPAGE_MARK_BAD == 0x40104b01);

static void rampage_clear_frames(struct rampage_session *session)
{
	unsigned long i;

	for (i = 0; i < session->nr_frames; i++)
		if (session->frames[i].page)
			put_page(session->frames[i].page);
	kvfree(session->frames);
	session->frames = NULL;
	session->nr_frames = 0;
	session->mapping_size = 0;
}

static int rampage_open(struct inode *inode, struct file *file)
{
	struct module *owner = inode->i_cdev->owner;
	struct rampage_session *session;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	/* These fops are built in; explicitly pin the registration module. */
	if (!try_module_get(owner))
		return -ENODEV;
	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) {
		module_put(owner);
		return -ENOMEM;
	}
	mutex_init(&session->lock);
	session->owner = owner;
	file->private_data = session;
	return 0;
}

static int rampage_release(struct inode *inode, struct file *file)
{
	struct rampage_session *session = file->private_data;
	struct module *owner = session->owner;

	/* VMA file references keep the session alive until its last unmap. */
	rampage_clear_frames(session);
	kfree(session);
	module_put(owner);
	return 0;
}

static long rampage_configure(struct file *file,
			     const struct rampage_request *request)
{
	struct rampage_session *session = file->private_data;
	struct rampage_frame_request *requests = NULL;
	unsigned long i;
	int ret = 0;

	if (request->version != RAMPAGE_VERSION)
		return -EINVAL;
	if (request->count > SSIZE_MAX / sizeof(struct rampage_frame) ||
	    request->count > ULONG_MAX / PAGE_SIZE)
		return -EOVERFLOW;
	/* Never fault on user memory while holding the VMA/session lock. */
	if (request->count) {
		requests = vmemdup_array_user(request->frames, request->count,
					     sizeof(*requests));
		if (IS_ERR(requests))
			return PTR_ERR(requests);
	}
	if (mutex_lock_interruptible(&session->lock)) {
		kvfree(requests);
		return -ERESTARTSYS;
	}
	if (session->mappings) {
		ret = -EINVAL;
		goto out;
	}
	rampage_clear_frames(session);
	file->f_pos = 0;
	if (!request->count)
		goto out;
	session->frames = kvcalloc(request->count, sizeof(*session->frames),
				   GFP_KERNEL);
	if (!session->frames) {
		ret = -ENOMEM;
		goto out;
	}
	session->nr_frames = request->count;
	for (i = 0; i < request->count; i++) {
		struct rampage_frame *frame = &session->frames[i];
		struct rampage_frame_status *status = &frame->status;
		u64 start = get_jiffies_64();

		status->request = requests[i];
		if (!pfn_valid(status->request.pfn) ||
		    !page_is_ram(status->request.pfn)) {
			status->source = RAMPAGE_INVALID_PFN;
		} else if (status->request.allowed_sources & RAMPAGE_SOURCE_BUDDY) {
			frame->page = rampage_claim_page(status->request.pfn);
			if (frame->page) {
				status->offset = session->mapping_size;
				status->pfn = page_to_pfn(frame->page);
				status->source = RAMPAGE_SOURCE_BUDDY;
				/* Userspace tests nonzero; do not expose a kernel pointer. */
				status->page_cookie = 1;
				session->mapping_size += PAGE_SIZE;
			}
		}
		status->cost_jiffies = get_jiffies_64() - start;
		cond_resched();
	}
out:
	mutex_unlock(&session->lock);
	kvfree(requests);
	return ret;
}

static long rampage_mark_bad(struct rampage_session *session,
			     const struct rampage_poison_request *request)
{
	unsigned long i;
	int ret = -EINVAL;

	if (request->version != RAMPAGE_VERSION)
		return -EINVAL;
	if (mutex_lock_interruptible(&session->lock))
		return -ERESTARTSYS;
	for (i = 0; i < session->nr_frames; i++) {
		struct rampage_frame *frame = &session->frames[i];

		if (frame->page && frame->status.pfn == request->pfn) {
			ret = rampage_mark_page_bad(frame->page);
			break;
		}
	}
	mutex_unlock(&session->lock);
	return ret;
}

static long rampage_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *ptr = (void __user *)arg;

	switch (cmd) {
	case RAMPAGE_REQUEST_PAGES: {
		struct rampage_request request;

		if (copy_from_user(&request, ptr, sizeof(request)))
			return -EFAULT;
		return rampage_configure(file, &request);
	}
	case RAMPAGE_MARK_BAD: {
		struct rampage_poison_request request;

		if (copy_from_user(&request, ptr, sizeof(request)))
			return -EFAULT;
		return rampage_mark_bad(file->private_data, &request);
	}
	default:
		return -ENOTTY;
	}
}

static ssize_t rampage_read(struct file *file, char __user *buf, size_t count,
			   loff_t *pos)
{
	struct rampage_session *session = file->private_data;
	size_t size = sizeof(struct rampage_frame_status), done = 0, bytes;
	char *snapshot = NULL;
	ssize_t ret = 0;
	loff_t cursor;

	if (mutex_lock_interruptible(&session->lock))
		return -ERESTARTSYS;
	if (!session->frames || *pos < 0) {
		ret = -EIO;
		goto out;
	}
	if (*pos >= session->nr_frames * size || !count)
		goto out;
	bytes = min_t(size_t, count, session->nr_frames * size - *pos);
	snapshot = kvmalloc(bytes, GFP_KERNEL);
	if (!snapshot) {
		ret = -ENOMEM;
		goto out;
	}
	cursor = *pos;
	while (done < bytes) {
		size_t index = cursor / size, offset = cursor % size;
		size_t chunk = min(bytes - done, size - offset);
		char *status = (char *)&session->frames[index].status;

		memcpy(snapshot + done, status + offset, chunk);
		cursor += chunk;
		done += chunk;
	}
	mutex_unlock(&session->lock);
	ret = bytes - copy_to_user(buf, snapshot, bytes);
	if (ret)
		*pos += ret;
	else
		ret = -EFAULT;
	kvfree(snapshot);
	return ret;
out:
	mutex_unlock(&session->lock);
	return ret;
}

static loff_t rampage_llseek(struct file *file, loff_t offset, int whence)
{
	struct rampage_session *session = file->private_data;
	loff_t ret;

	if (mutex_lock_interruptible(&session->lock))
		return -ERESTARTSYS;
	ret = fixed_size_llseek(file, offset, whence,
			session->nr_frames * sizeof(struct rampage_frame_status));
	mutex_unlock(&session->lock);
	return ret;
}

static void rampage_vma_open(struct vm_area_struct *vma)
{
	struct rampage_session *session = vma->vm_private_data;

	mutex_lock(&session->lock);
	session->mappings++;
	mutex_unlock(&session->lock);
}

static void rampage_vma_close(struct vm_area_struct *vma)
{
	struct rampage_session *session = vma->vm_private_data;

	mutex_lock(&session->lock);
	session->mappings--;
	mutex_unlock(&session->lock);
}

static const struct vm_operations_struct rampage_vm_ops = {
	.open = rampage_vma_open,
	.close = rampage_vma_close,
};

static int rampage_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct rampage_session *session = file->private_data;
	unsigned long i;
	int ret = 0;

	if (mutex_lock_interruptible(&session->lock))
		return -ERESTARTSYS;
	if (!session->mapping_size || vma->vm_pgoff ||
	    !(vma->vm_flags & VM_SHARED) ||
	    vma->vm_end - vma->vm_start != session->mapping_size) {
		ret = -EINVAL;
		goto out;
	}
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	for (i = 0; i < session->nr_frames; i++) {
		struct rampage_frame *frame = &session->frames[i];

		if (!frame->page)
			continue;
		ret = remap_pfn_range(vma, vma->vm_start + frame->status.offset,
				     frame->status.pfn, PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			goto out;
	}
	vma->vm_ops = &rampage_vm_ops;
	vma->vm_private_data = session;
	session->mappings++;
out:
	mutex_unlock(&session->lock);
	return ret;
}

struct file_operations rampage_phys_mem_fops = {
	.open = rampage_open,
	.release = rampage_release,
	.read = rampage_read,
	.llseek = rampage_llseek,
	.unlocked_ioctl = rampage_ioctl,
	.mmap = rampage_mmap,
};
EXPORT_SYMBOL_GPL(rampage_phys_mem_fops);
