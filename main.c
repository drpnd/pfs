/*_
 * Copyright (c) 2018 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define FUSE_USE_VERSION  28

#include "config.h"
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

struct pfs {
    char *data;
    size_t size;
};
#define RAMFS_SIZE (1024ULL * 1024 * 1024)

static const char *ramfs_file_path = "/test";
static size_t ramfs_file_length = 0;
static size_t ramfs_file_flag = 0;

int
pfs_getattr(const char *path, struct stat *stbuf)
{
    int ret = 0;
    struct fuse_context *ctx;

    ctx = fuse_get_context();

    memset(stbuf, 0, sizeof(struct stat));
    if ( strcmp(path, "/") == 0 ) {
        stbuf->st_mode = S_IFDIR | 0777;
        stbuf->st_nlink = 2 + ramfs_file_flag;
        stbuf->st_uid = ctx->uid;
        stbuf->st_gid = ctx->gid;
        //ctx->umaskr;
    } else if ( strcmp(path, ramfs_file_path) == 0 && ramfs_file_flag ) {
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(ramfs_file_path);
        stbuf->st_atime = (time_t)1518016659;
        stbuf->st_mtime = (time_t)1518016659;
        stbuf->st_ctime = (time_t)1518016659;
#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIME
        stbuf->st_birthtime = (time_t)1518016659;
#endif
        stbuf->st_uid = ctx->uid;
        stbuf->st_gid = ctx->gid;
        stbuf->st_rdev = 0;
        stbuf->st_size = ramfs_file_length;
        stbuf->st_blksize = 4096;
        stbuf->st_blocks = 0;
    } else {
        ret = -ENOENT;
    }

    //printf("getattr(), %d: %s\n", ret, path);
    return ret;
}

int
pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
            off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if ( strcmp(path, "/") != 0 ) {
        return -ENOENT;
    }

    //printf("readdir(): %s\n", path);
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    if ( ramfs_file_flag ) {
        filler(buf, ramfs_file_path + 1, NULL, 0);
    }

    return 0;
}

int
pfs_open(const char *path, struct fuse_file_info *fi)
{
    if ( strcmp(path, ramfs_file_path) != 0 ) {
        return -ENOENT;
    }
    if ( (fi->flags & O_CREAT) == O_CREAT ) {
        ramfs_file_flag = 1;
    }
    //printf("open(): %s\n", path);

    return 0;
}

int
pfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    if ( strcmp(path, ramfs_file_path) == 0 ) {
        ramfs_file_flag = 1;
        return 0;
    }

    return -EACCES;
}

int
pfs_unlink(const char *path)
{
    if ( strcmp(path, ramfs_file_path) != 0 && !ramfs_file_flag ) {
        return -ENOENT;
    }
    ramfs_file_flag = 0;

    return 0;
}

int
pfs_mkdir(const char *path, mode_t mode)
{
    printf("Implement mkdir()\n");
    return -EACCES;
}

int
pfs_mknod(const char *path, mode_t mode, dev_t dev)
{
    printf("Implement mknod()\n");
    return -EACCES;
}

int
pfs_read(const char *path, char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi)
{
    struct fuse_context *ctx;
    struct pfs *pfs;

    //printf("read(): %s %zu\n", path, size);
    if ( strcmp(path, ramfs_file_path) != 0 && !ramfs_file_flag ) {
        return -ENOENT;
    }
    /* Permission check */
    if ( (fi->flags & 3) != O_RDONLY && (fi->flags & 3) != O_RDWR ) {
        return -EACCES;
    }

    /* Get the context */
    ctx = fuse_get_context();
    pfs = ctx->private_data;

    if ( offset < (off_t)ramfs_file_length ) {
        if ( offset + size > ramfs_file_length ) {
            size = ramfs_file_length - offset;
        }
        (void)memcpy(buf, pfs->data + offset, size);
    } else {
        size = 0;
    }

    return size;
}

int
pfs_write(const char *path, const char *buf, size_t size, off_t offset,
          struct fuse_file_info *fi)
{
    struct fuse_context *ctx;
    struct pfs *pfs;

    //printf("write(): %s %zu\n", path, size);
    if ( strcmp(path, ramfs_file_path) != 0 && !ramfs_file_flag ) {
        return -ENOENT;
    }

    /* Permission check */
    if ( (fi->flags & 3) != O_WRONLY && (fi->flags & 3) != O_RDWR ) {
        return -EACCES;
    }
    if ( size <= 0 ) {
        return 0;
    }

    /* Get the context */
    ctx = fuse_get_context();
    pfs = ctx->private_data;

    if ( offset + size > RAMFS_SIZE ) {
        return -EDQUOT;
    }
    (void)memcpy(&pfs->data[offset], buf, size);
    if ( ramfs_file_length < offset + size ) {
        ramfs_file_length = offset + size;
    }

    return size;
}

int
pfs_truncate(const char *path, off_t size)
{
    struct fuse_context *ctx;
    struct pfs *pfs;

    if ( strcmp(path, ramfs_file_path) != 0 && !ramfs_file_flag ) {
        return -ENOENT;
    }

    /* Get the context */
    ctx = fuse_get_context();
    pfs = ctx->private_data;

    while ( (off_t)ramfs_file_length < size ) {
        pfs->data[ramfs_file_length] = 0;
        ramfs_file_length++;
    }
    ramfs_file_length = size;

    return 0;
}

int
pfs_statfs(const char *path, struct statvfs *buf)
{
    (void)path;

    memset(buf, 0, sizeof(struct statvfs));

    buf->f_bsize = 4096;
    buf->f_frsize = 4096;
    buf->f_blocks = RAMFS_SIZE / 4096; /* in f_frsize unit */
    buf->f_bfree = (RAMFS_SIZE - ramfs_file_length) / 4096;
    buf->f_bavail = (RAMFS_SIZE - ramfs_file_length) / 4096;

    buf->f_files = 1000;
    buf->f_ffree = 100;
    buf->f_favail = 100;

    buf->f_fsid = 0;
    buf->f_flag = 0;
    buf->f_namemax = 255;

    return 0;
}

static struct fuse_operations pfs_oper = {
    .getattr    = pfs_getattr,
    .readdir    = pfs_readdir,
    .open       = pfs_open,
    .create     = pfs_create,
    .unlink     = pfs_unlink,
    .mkdir      = pfs_mkdir,
    .mknod      = pfs_mknod,
    .read       = pfs_read,
    .write      = pfs_write,
    .truncate   = pfs_truncate,
    .statfs     = pfs_statfs,
};

int
main(int argc, char *argv[])
{
    struct pfs *pfs;
    long pagesize;
    size_t size;
    void *ptr;

    /* Allocate memory */
    pagesize = sysconf(_SC_PAGESIZE);
    size = (RAMFS_SIZE + pagesize - 1) / pagesize * pagesize;
    ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if ( NULL == ptr ) {
        return EXIT_FAILURE;
    }

    /* Allocate pfs */
    pfs = malloc(sizeof(struct pfs));
    pfs->data = ptr;
    pfs->size = size;

    return fuse_main(argc, argv, &pfs_oper, pfs);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
