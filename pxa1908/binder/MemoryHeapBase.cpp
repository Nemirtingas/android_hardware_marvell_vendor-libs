/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "MemoryHeapBase"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <cutils/log.h>
#include <cutils/ashmem.h>
#include <cutils/atomic.h>

#include "include/MemoryHeapBase.h"

#include <mvmem.h>

namespace android {

// ---------------------------------------------------------------------------

MemoryHeapBase::MemoryHeapBase()
    : mFD(-1), mSize(0), mBase(MAP_FAILED),
      mDevice(NULL), mNeedUnmap(false), mOffset(0), mFD2(-1)
{
}

MemoryHeapBase::MemoryHeapBase(size_t size, uint32_t flags, char const * name)
    : mFD(-1), mSize(0), mBase(MAP_FAILED), mFlags(flags),
      mDevice(0), mNeedUnmap(false), mOffset(0), mFD2(-1)
{
    const size_t pagesize = getpagesize();
    size = ((size + pagesize-1) & ~(pagesize-1));
    int fd = ashmem_create_region(name == NULL ? "MemoryHeapBase" : name, size);
    ALOGE_IF(fd<0, "error creating ashmem region: %s", strerror(errno));
    if (fd >= 0) {
        if (mapfd(fd, size) == NO_ERROR) {
            if (flags & READ_ONLY) {
                ashmem_set_prot_region(fd, PROT_READ);
            }
        }
    }
}

MemoryHeapBase::MemoryHeapBase(const char* device, size_t size, uint32_t flags)
    : mFD(-1), mSize(0), mBase(MAP_FAILED), mFlags(flags),
      mDevice(0), mNeedUnmap(false), mOffset(0), mFD2(-1)
{
    int open_flags = O_RDWR;
    if (flags & NO_CACHING)
        open_flags |= O_SYNC;

    int fd = open(device, open_flags);
    ALOGE_IF(fd<0, "error opening %s: %s", device, strerror(errno));
    if (fd >= 0) {
        const size_t pagesize = getpagesize();
        size = ((size + pagesize-1) & ~(pagesize-1));
        if (mapion(fd, size) == NO_ERROR) {
            mDevice = device;
        }
        else
            ALOGE("mapion failed");
    }
}

MemoryHeapBase::MemoryHeapBase(int fd, size_t size, uint32_t flags, uint32_t offset)
    : mFD(-1), mSize(0), mBase(MAP_FAILED), mFlags(flags),
      mDevice(0), mNeedUnmap(false), mOffset(0), mFD2(-1)
{
    const size_t pagesize = getpagesize();
    size = ((size + pagesize-1) & ~(pagesize-1));
    mapion(dup(fd), size, offset);
}

status_t MemoryHeapBase::init(int fd, void *base, int size, int flags, const char* device)
{
    if (mFD != -1) {
        return INVALID_OPERATION;
    }
    mFD = fd;
    mBase = base;
    mSize = size;
    mFlags = flags;
    mDevice = device;
    return NO_ERROR;
}

status_t MemoryHeapBase::mapion(int fd, size_t size, uint32_t offset)
{
    int flags = 0;

    if( size == 0 )
    {
        ALOGE("error: mapion size = 0");
        return -EINVAL;
    }

    if( mFlags & DONT_MAP_LOCALLY )
    {
        mBase = 0;
        mNeedUnmap = false;
        mFD = -1;
        mFD2 = fd;
        mSize = size;
        mOffset = offset;
        return 0;
    }

    if( !(mFlags & NO_CACHING) )
        flags = 0x30000;

    if( mFlags & 0x400 )
        flags |= 2;
    else
        flags |= 1;

    int handlefd = mvmem_alloc(size, flags, 4096);
    if( handlefd >= 0 )
    {
        mvmem_set_name(handlefd, "binder");
        void *base = mvmem_mmap(handlefd, size, offset);
        if( base == (void*)-1 )
        {
            close(fd);
            return -errno;
        }
        mBase = base;
        mNeedUnmap = true;
        mFD = handlefd;
        mFD2 = fd;
        mSize = size;
        mOffset = offset;
        return 0;
    }
    close(fd);
    return -errno;
}

status_t MemoryHeapBase::mapfd(int fd, size_t size, uint32_t offset)
{
    if (size == 0) {
        // try to figure out the size automatically
        struct stat sb;
        if (fstat(fd, &sb) == 0)
            size = sb.st_size;
        // if it didn't work, let mmap() fail.
    }

    if ((mFlags & DONT_MAP_LOCALLY) == 0) {
        void* base = (uint8_t*)mmap(0, size,
                PROT_READ|PROT_WRITE, MAP_SHARED, fd, offset);
        if (base == MAP_FAILED) {
            ALOGE("mmap(fd=%d, size=%u) failed (%s)",
                    fd, uint32_t(size), strerror(errno));
            close(fd);
            return -errno;
        }
        //ALOGD("mmap(fd=%d, base=%p, size=%lu)", fd, base, size);
        mBase = base;
        mNeedUnmap = true;
    } else  {
        mBase = 0; // not MAP_FAILED
        mNeedUnmap = false;
    }
    mFD = fd;
    mSize = size;
    mOffset = offset;
    return NO_ERROR;
}

MemoryHeapBase::~MemoryHeapBase()
{
    dispose();
}

void MemoryHeapBase::dispose()
{
    int fd = android_atomic_or(-1, &mFD);
    if (fd >= 0) {
        if( mBase )
        {
            if (mNeedUnmap) {
                //ALOGD("munmap(fd=%d, base=%p, size=%lu)", fd, mBase, mSize);
                mvmem_munmap(mBase, mSize);
            }
        }
        mvmem_free(fd);
        close(mFD2);
        mFD=-1;
        mFD2=-1;
        mBase = 0;
        mSize = 0;
    }
}

int MemoryHeapBase::getHeapID() const {
    return mFD;
}

void* MemoryHeapBase::getBase() const {
    return mBase;
}

size_t MemoryHeapBase::getSize() const {
    return mSize;
}

uint32_t MemoryHeapBase::getFlags() const {
    return mFlags;
}

const char* MemoryHeapBase::getDevice() const {
    return mDevice;
}

uint32_t MemoryHeapBase::getOffset() const {
    return mOffset;
}

// ---------------------------------------------------------------------------
}; // namespace android
