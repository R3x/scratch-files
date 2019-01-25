/*      $NetBSD$        */

/*
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Siddharth Muralee.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/module.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <sys/conf.h>
#include <sys/condvar.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/queue.h>

#include <uvm/uvm_extern.h>
#include <sys/kcov.h>

#define KCOV_BUF_MAX_ENTRIES	(256 << 10)

/*
 * The KCOV descriptor. One per proc, associated to only one LWP within
 * the proc.
 */
typedef struct kcov_desc {
	pid_t pid;
	bool active;
	bool exitfree;
	kcov_int_t *buf;
	size_t bufnent;
	size_t bufsize;
	TAILQ_ENTRY(kcov_desc) entry;
} kcov_t;

struct kcov_mp_lock {
	kcondvar_t	cv;
	bool	    inuse_cv;
	kmutex_t	lock;
	kmutex_t	ioctl_lock;
};

static struct kcov_mp_lock kcov_lock;

static TAILQ_HEAD(, kcov_desc) kd_list = TAILQ_HEAD_INITIALIZER(kd_list);

static kcov_t *
kcov_lookup_pid(pid_t pid)
{
	kcov_t *kd;

	TAILQ_FOREACH(kd, &kd_list, entry) {
		if (kd->pid == pid)
			return kd;
	}
	return NULL;
}

static int
kcov_allocbuf(kcov_t *kd, uint64_t nent)
{
	size_t size;

	KASSERT(kd->buf == NULL);

	if (nent < 2 || nent > KCOV_BUF_MAX_ENTRIES) {
		return EINVAL;
	}
	if (kd->buf != NULL) {
		kmem_free(kd->buf, kd->bufsize);
		kd->buf = NULL;
		kd->bufnent = 0;
	}

	size = roundup(nent * sizeof(kcov_int_t), PAGE_SIZE);
	kd->buf = (kcov_int_t *)uvm_km_alloc(kernel_map, size, 0,
	    UVM_KMF_WIRED|UVM_KMF_ZERO);
	if (kd->buf == NULL)
		return ENOMEM;

	kd->bufnent = nent - 1;
	kd->bufsize = size;

	return 0;
}

static void
kcov_free(kcov_t *kd)
{
	TAILQ_REMOVE(&kd_list, kd, entry);
	if (kd->buf != NULL) {
		uvm_km_free(kernel_map, (vaddr_t)kd->buf, kd->bufsize,
		    UVM_KMF_WIRED);
	}
	kmem_free(kd, sizeof(*kd));
}

void
kcov_exit(struct lwp *l)
{
	kcov_t *kd = l->l_kcov;

	if (kd == NULL) {
		return;
	}
	l->l_kcov = NULL;
	kd->active = false;
	__insn_barrier();
	if (kd->exitfree) {
		kcov_free(kd);
	}
}

void
kcov_init(void)
{
	mutex_init(&kcov_lock.lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&kcov_lock.ioctl_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&kcov_lock.cv, "kcov condition variable");
}

/*
void
kcov_destroy(void)
{
	mutex_destroy(&kcov_lock.lock);
	mutex_destroy(&kcov_lock.read_lock);
	cv_destroy(&kcov_lock.cv);
}
*/

static int
kcov_open(dev_t dev, int flag, int mode, struct lwp *l)
{
	kcov_t *kd;
	int error;

	error = 0;

	mutex_enter(&kcov_lock.lock);
	while (kcov_lock.inuse_cv == true) {
		error = cv_wait_sig(&kcov_lock.cv, &kcov_lock.lock);
		if (error)
			break;
	}
	if (!error) {
		kcov_lock.inuse_cv = true;
	}
	mutex_exit(&kcov_lock.lock);

	if (kcov_lookup_pid(l->l_proc->p_pid) != NULL)
		return EBUSY;

	kd = kmem_zalloc(sizeof(*kd), KM_SLEEP);
	kd->pid = l->l_proc->p_pid;
	TAILQ_INSERT_TAIL(&kd_list, kd, entry);
	return 0;
}

static int
kcov_close(dev_t dev, int flag, int mode, struct lwp *l)
{
	kcov_t *kd;
	
	mutex_enter(&kcov_lock.lock);
	kcov_lock.inuse_cv = false;
	cv_signal(&kcov_lock.cv);
	mutex_exit(&kcov_lock.lock);

	kd = kcov_lookup_pid(l->l_proc->p_pid);
	if (kd == NULL)
		return EINVAL;

	if (kd->active) {
		/* Request free on exit. */
		kd->exitfree = true;
	} else {
		kcov_free(kd);
	}

   	return 0;
}

static int
kcov_ioctl(dev_t dev, u_long cmd, void *addr, int flag, struct lwp *l)
{
	int error = 0;
	kcov_t *kd;

	mutex_enter(&kcov_lock.ioctl_lock);

	kd = kcov_lookup_pid(l->l_proc->p_pid);
	if (kd == NULL) {
		error = ENXIO;
		mutex_exit(&kcov_lock.ioctl_lock);
		return error;
	}

	switch (cmd) {
	case KCOV_IOC_SETBUFSIZE:
		if (kd->active) {
			error = EBUSY;
			break;
		}
		error = kcov_allocbuf(kd, *((uint64_t *)addr));
		break;
	case KCOV_IOC_ENABLE:
		if (kd->active) {
			error = EBUSY;
			break;
		}
		if (kd->buf == NULL) {
			error = ENOBUFS;
			break;
		}
		kd->active = true;
		l->l_kcov = kd;
		break;
	case KCOV_IOC_DISABLE:
		if (!kd->active) {
			error = ENOENT;
			break;
		}
		if (l->l_kcov != kd) {
			error = EPERM;
			break;
		}
		kd->active = false;
		l->l_kcov = NULL;
		break;
	default:
		error = EINVAL;
	}

	mutex_exit(&kcov_lock.ioctl_lock);

	return error;
}

static paddr_t
kcov_mmap(dev_t dev, off_t offset, int prot)
{
	kcov_t *kd;
	paddr_t pa;
	vaddr_t va;

	kd = kcov_lookup_pid(curlwp->l_proc->p_pid);
	if (kd == NULL) {
		return (paddr_t)(-1);
	}
	if (offset < 0 || offset >= kd->bufnent * sizeof(kcov_int_t)) {
		return (paddr_t)(-1);
	}
	va = (vaddr_t)kd->buf + offset;
	if (!pmap_extract(pmap_kernel(), va, &pa)) {
		return (paddr_t)(-1);
	}

	return atop(pa);
}

static inline bool
in_interrupt(void)
{
	return curcpu()->ci_idepth >= 0;
}

void __sanitizer_cov_trace_pc(void);

void
__sanitizer_cov_trace_pc(void)
{
	extern int cold;
	uint64_t idx;
	kcov_t *kd;

	if (__predict_false(cold)) {
		/* Do not trace during boot. */
		return;
	}

	if (in_interrupt()) {
		/* Do not trace in interrupts. */
		return;
	}

	kd = curlwp->l_kcov;
	if (__predict_true(kd == NULL)) {
		/* Not traced. */
		return;
	}

	idx = kd->buf[0];
	if (idx < kd->bufnent) {
		kd->buf[idx+1] = (kcov_int_t)__builtin_return_address(0);
		kd->buf[0]++;
	}
}

/* -------------------------------------------------------------------------- */

const struct cdevsw kcov_cdevsw = {
	.d_open = kcov_open,
	.d_close = kcov_close,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = kcov_ioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = kcov_mmap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER | D_MPSAFE,
};

MODULE(MODULE_CLASS_MISC, kcov, NULL);

static int
kcov_modcmd(modcmd_t cmd, void *arg)
{
   	switch (cmd) {
	case MODULE_CMD_INIT:
	case MODULE_CMD_FINI:
		return 0;
	default:
		return ENOTTY;
	}
}
