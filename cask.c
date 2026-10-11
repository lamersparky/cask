#define _GNU_SOURCE

/*
 * CASK - Container Archival & Secret Keeping
 *
 * CASK is the archival companion to EATER.  It stores an EATER container's
 * non-database data in a compressed tar.gz archive and keeps eater.db in an
 * authenticated AES-256-GCM record inside the CASK stomach.
 *
 * CASK record format version 1 is intentionally preserved:
 *   magic(8) version(4) record-id(16) archive-sha256(32) nonce(12)
 *   database-length(8) ciphertext-length(8) ciphertext(n) tag(16)
 *
 * The encrypted plaintext is:
 *   relative-path-length(2) relative-path(n) eater.db-bytes(m)
 *
 * AAD is exactly:
 *   CASK_MAGIC || CASK_VERSION || record-id || archive-sha256
 *
 * Linux/POSIX + OpenSSL libcrypto.  GNU tar and gzip are used for archive
 * creation/inspection/extraction; archive contents are preflight-validated
 * before extraction and symlink/hardlink/special-file entries are rejected.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CASK_PROGRAM_VERSION "1.0.0"
#define CASK_MAGIC "CASKDB1\0"
#define CASK_MAGIC_LEN 8U
#define CASK_VERSION 1U
#define CASK_ID_LEN 16U
#define CASK_KEY_LEN 32U
#define CASK_NONCE_LEN 12U
#define CASK_TAG_LEN 16U
#define CASK_ARCHIVE_HASH_LEN SHA256_DIGEST_LENGTH
#define CASK_MAX_DB_SIZE (1024ULL * 1024ULL * 1024ULL)
#define CASK_RELBUF 16384U
#define CASK_MAX_PATH_LEN 16383U
#define CASK_RECORD_HEADER_LEN (CASK_MAGIC_LEN + 4U + CASK_ID_LEN + CASK_ARCHIVE_HASH_LEN + CASK_NONCE_LEN + 8U + 8U)
#define CASK_MAX_PLAIN_SIZE (2ULL + CASK_MAX_PATH_LEN + CASK_MAX_DB_SIZE)

static const char *program_name = "cask";

static char g_container[PATH_MAX];
static char g_db_path[PATH_MAX];
static char g_db_rel[PATH_MAX];
static int g_db_count = 0;

struct record_header {
    unsigned char id[CASK_ID_LEN];
    unsigned char archive_hash[CASK_ARCHIVE_HASH_LEN];
    unsigned char nonce[CASK_NONCE_LEN];
    uint64_t db_len;
    uint64_t cipher_len;
};

struct command_options {
    const char *stomach;
    int force;
    int check;
};

static void usage(FILE *out) {
    fprintf(out,
        "CASK - Container Archival & Secret Keeping\n\n"
        "CASK archives EATER containers while securely preserving eater.db\n"
        "inside its encrypted stomach. CASK never deletes or modifies the\n"
        "source EATER container.\n\n"
        "COMMANDS:\n\n"
        "  %s archive <container> <archive.tar.gz> [--stomach DIR]\n"
        "      Archive an EATER container and store eater.db in the stomach.\n"
        "\n"
        "  %s stomach [--check] [--stomach DIR]\n"
        "      List databases stored in the CASK stomach.\n"
        "\n"
        "  %s inspect <record-id> [--stomach DIR]\n"
        "      Inspect and authenticate a stored CASK record.\n"
        "\n"
        "  %s find <archive.tar.gz> [--stomach DIR]\n"
        "      Find records associated with an archive SHA-256.\n"
        "\n"
        "  %s retrieve <record-id> <output-eater.db> [--force] [--stomach DIR]\n"
        "      Decrypt and retrieve eater.db. Existing output requires --force.\n"
        "\n"
        "  %s verify <archive.tar.gz> [--stomach DIR]\n"
        "      Verify gzip/tar integrity and the authenticated CASK association.\n"
        "\n"
        "  %s extract <archive.tar.gz> <output-dir>\n"
        "      Safely extract archive contents without eater.db.\n"
        "\n"
        "  %s restore <archive.tar.gz> <output-container> [--stomach DIR]\n"
        "      Reconstruct a complete EATER container atomically.\n"
        "\n"
        "OPTIONS:\n\n"
        "  --stomach DIR\n"
        "      Use an alternate CASK stomach.\n"
        "\n"
        "  --force\n"
        "      Permit replacement of an existing retrieve output file.\n"
        "\n"
        "  --check\n"
        "      With stomach, authenticate every readable record.\n"
        "\n"
        "  --help\n"
        "      Display this help.\n"
        "\n"
        "  --version\n"
        "      Display CASK version information.\n\n"
        "DEFAULT STOMACH:\n"
        "  $XDG_DATA_HOME/cask/stomach\n"
        "  or ~/.local/share/cask/stomach\n",
        program_name, program_name, program_name, program_name,
        program_name, program_name, program_name, program_name);
}

static void version(FILE *out) {
    fprintf(out, "CASK %s (record format v%u)\n", CASK_PROGRAM_VERSION, CASK_VERSION);
}

static void show_progress(const char *phase, unsigned int percent) {
    if (!isatty(STDOUT_FILENO)) return;
    if (percent > 100U) percent = 100U;
    printf("CASK: %-10s %3u%%\r", phase, percent);
    fflush(stdout);
    if (percent == 100U) putchar('\n');
}

static int is_dir_mode(mode_t mode) {
    return S_ISDIR(mode) ? 1 : 0;
}

static int ensure_dir(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof(tmp));
    if (len == 0U || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1U);

    for (char *p = tmp + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (tmp[0] != '\0' && mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;

    struct stat st;
    if (stat(tmp, &st) != 0) return -1;
    if (!is_dir_mode(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static int fsync_directory(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    return rc;
}

static int get_default_stomach(char *out, size_t out_sz) {
    const char *xdg = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    int n;

    if (xdg != NULL && xdg[0] != '\0') {
        n = snprintf(out, out_sz, "%s/cask/stomach", xdg);
    } else if (home != NULL && home[0] != '\0') {
        n = snprintf(out, out_sz, "%s/.local/share/cask/stomach", home);
    } else {
        errno = ENOENT;
        return -1;
    }
    if (n < 0 || (size_t)n >= out_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int get_parent_dir(const char *path, char *parent, size_t parent_sz, char *base, size_t base_sz) {
    char tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof(tmp));
    if (len == 0U || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1U);

    char *slash = strrchr(tmp, '/');
    const char *b = slash != NULL ? slash + 1 : tmp;
    if (*b == '\0') {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(base, base_sz, "%s", b) < 0 || strlen(b) + 1U > base_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (slash == NULL) {
        if (getcwd(parent, parent_sz) == NULL) return -1;
    } else if (slash == tmp) {
        if (snprintf(parent, parent_sz, "/") < 0 || parent_sz < 2U) {
            errno = ENAMETOOLONG;
            return -1;
        }
    } else {
        *slash = '\0';
        if (snprintf(parent, parent_sz, "%s", tmp) < 0 || strlen(tmp) + 1U > parent_sz) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }
    return 0;
}

static int absolute_path(const char *arg, char *out, size_t out_sz) {
    if (arg[0] == '/') {
        if (snprintf(out, out_sz, "%s", arg) < 0 || strlen(arg) + 1U > out_sz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return -1;
    int n = snprintf(out, out_sz, "%s/%s", cwd, arg);
    if (n < 0 || (size_t)n >= out_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int path_is_inside(const char *parent, const char *child) {
    size_t n = strlen(parent);
    if (strncmp(parent, child, n) != 0) return 0;
    return child[n] == '\0' || child[n] == '/';
}

static int resolve_path_for_check(const char *path, char *out, size_t out_sz) {
    char work[PATH_MAX];
    if (snprintf(work, sizeof(work), "%s", path) < 0 || strlen(path) + 1U > sizeof(work)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char suffix[PATH_MAX];
    suffix[0] = '\0';
    for (;;) {
        if (realpath(work, out) != NULL) {
            if (suffix[0] == '\0') return 0;
            size_t out_len = strlen(out);
            size_t suffix_len = strlen(suffix);
            if (out_len + suffix_len + 1U > out_sz) {
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(out + out_len, suffix, suffix_len + 1U);
            return 0;
        }
        if (errno != ENOENT) return -1;

        char parent[PATH_MAX];
        char base[PATH_MAX];
        if (get_parent_dir(work, parent, sizeof(parent), base, sizeof(base)) != 0) return -1;

        char next_suffix[PATH_MAX];
        int n;
        if (suffix[0] == '\0') n = snprintf(next_suffix, sizeof(next_suffix), "/%s", base);
        else n = snprintf(next_suffix, sizeof(next_suffix), "/%s%s", base, suffix);
        if (n < 0 || (size_t)n >= sizeof(next_suffix)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(suffix, next_suffix, (size_t)n + 1U);

        if (strcmp(parent, work) == 0) {
            if (realpath(parent, out) == NULL) return -1;
            size_t out_len = strlen(out);
            size_t suffix_len = strlen(suffix);
            if (out_len + suffix_len + 1U > out_sz) {
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(out + out_len, suffix, suffix_len + 1U);
            return 0;
        }
        memcpy(work, parent, strlen(parent) + 1U);
    }
}

static int output_path_ready(const char *archive_path, const char *container) {
    struct stat st;
    if (lstat(archive_path, &st) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) return -1;

    char parent[PATH_MAX];
    char base[PATH_MAX];
    if (get_parent_dir(archive_path, parent, sizeof(parent), base, sizeof(base)) != 0) return -1;
    (void)base;

    char real_container[PATH_MAX];
    char real_parent[PATH_MAX];
    if (realpath(container, real_container) == NULL) return -1;
    if (realpath(parent, real_parent) == NULL) return -1;

    char abs_archive[PATH_MAX];
    int n = snprintf(abs_archive, sizeof(abs_archive), "%s/%s", real_parent, base);
    if (n < 0 || (size_t)n >= sizeof(abs_archive)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (path_is_inside(real_container, abs_archive)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static void put_u16_be(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static uint16_t get_u16_be(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void put_u32_be(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static uint32_t get_u32_be(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_u64_be(unsigned char *p, uint64_t v) {
    for (unsigned int i = 8U; i > 0U; --i) {
        p[i - 1U] = (unsigned char)v;
        v >>= 8;
    }
}

static uint64_t get_u64_be(const unsigned char *p) {
    uint64_t v = 0U;
    for (unsigned int i = 0U; i < 8U; ++i) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static int read_all(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    size_t off = 0U;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t off = 0U;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void hex_encode(const unsigned char *in, size_t n, char *out, size_t out_sz) {
    static const char hex[] = "0123456789abcdef";
    if (out_sz == 0U || n > (out_sz - 1U) / 2U) return;
    for (size_t i = 0U; i < n; ++i) {
        out[i * 2U] = hex[in[i] >> 4];
        out[i * 2U + 1U] = hex[in[i] & 15U];
    }
    out[n * 2U] = '\0';
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

static int parse_record_id(const char *s, unsigned char id[CASK_ID_LEN]) {
    size_t len = strlen(s);
    if (len != CASK_ID_LEN * 2U) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0U; i < CASK_ID_LEN; ++i) {
        int hi = hex_value(s[i * 2U]);
        int lo = hex_value(s[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            errno = EINVAL;
            return -1;
        }
        id[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static int record_filename_matches_id(const char *filename, const unsigned char id[CASK_ID_LEN]) {
    const size_t stem_len = CASK_ID_LEN * 2U;
    const size_t suffix_len = 7U;
    size_t len = strlen(filename);
    if (len != stem_len + suffix_len || strcmp(filename + stem_len, ".caskdb") != 0) return 0;
    char stem[CASK_ID_LEN * 2U + 1U];
    memcpy(stem, filename, stem_len);
    stem[stem_len] = '\0';
    unsigned char parsed[CASK_ID_LEN];
    if (parse_record_id(stem, parsed) != 0) return 0;
    return memcmp(parsed, id, CASK_ID_LEN) == 0 ? 1 : 0;
}

static int make_record_path(const char *stomach, const unsigned char id[CASK_ID_LEN], char *out, size_t out_sz) {
    char hex[CASK_ID_LEN * 2U + 1U];
    hex_encode(id, CASK_ID_LEN, hex, sizeof(hex));
    int n = snprintf(out, out_sz, "%s/records/%s.caskdb", stomach, hex);
    if (n < 0 || (size_t)n >= out_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int secure_read_master_key(const char *stomach, unsigned char key[CASK_KEY_LEN]) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/master.key", stomach);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size != (off_t)CASK_KEY_LEN || (st.st_mode & 0077U) != 0U) {
        (void)close(fd);
        errno = EINVAL;
        return -1;
    }
    if (read_all(fd, key, CASK_KEY_LEN) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    int saved = errno;
    if (close(fd) != 0) return -1;
    errno = saved;
    return 0;
}

static int create_master_key(const char *stomach, unsigned char key[CASK_KEY_LEN]) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/master.key", stomach);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char tmp[PATH_MAX];
    n = snprintf(tmp, sizeof(tmp), "%s/.master.key.tmp.%ld", stomach, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;

    int ok = 0;
    int saved = 0;
    if (RAND_bytes(key, CASK_KEY_LEN) != 1 || write_all(fd, key, CASK_KEY_LEN) != 0 ||
        fchmod(fd, 0600) != 0 || fsync(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
    } else if (close(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
        fd = -1;
    } else {
        fd = -1;
        if (link(tmp, path) == 0) {
            ok = 1;
            (void)unlink(tmp);
            (void)fsync_directory(stomach);
        } else {
            saved = errno != 0 ? errno : EIO;
        }
    }

    if (fd >= 0) (void)close(fd);
    if (!ok) (void)unlink(tmp);
    if (!ok) {
        errno = saved != 0 ? saved : EIO;
        return -1;
    }
    return 0;
}

static int load_or_create_master_key(const char *stomach, unsigned char key[CASK_KEY_LEN]) {
    if (secure_read_master_key(stomach, key) == 0) return 0;
    if (errno != ENOENT) return -1;
    if (create_master_key(stomach, key) == 0) return 0;
    if (errno == EEXIST) return secure_read_master_key(stomach, key);
    return -1;
}

static int read_entire_file(const char *path, unsigned char **data, size_t *len) {
    *data = NULL;
    *len = 0U;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uintmax_t)st.st_size > CASK_MAX_DB_SIZE) {
        (void)close(fd);
        errno = st.st_size < 0 ? EINVAL : EFBIG;
        return -1;
    }

    size_t total = (size_t)st.st_size;
    unsigned char *buf = malloc(total != 0U ? total : 1U);
    if (buf == NULL) {
        (void)close(fd);
        errno = ENOMEM;
        return -1;
    }
    if (read_all(fd, buf, total) != 0) {
        int saved = errno;
        OPENSSL_cleanse(buf, total != 0U ? total : 1U);
        free(buf);
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        OPENSSL_cleanse(buf, total != 0U ? total : 1U);
        free(buf);
        errno = saved;
        return -1;
    }
    *data = buf;
    *len = total;
    return 0;
}

static int sha256_file(const char *path, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno != 0 ? errno : EINVAL;
        (void)close(fd);
        errno = saved;
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        (void)close(fd);
        errno = ENOMEM;
        return -1;
    }
    unsigned char buf[1024U * 1024U];
    int ok = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        if (got == 0) break;
        if (EVP_DigestUpdate(ctx, buf, (size_t)got) != 1) goto done;
    }
    if (EVP_DigestFinal_ex(ctx, digest, NULL) != 1) goto done;
    ok = 1;

done:
    {
        int saved = errno;
        EVP_MD_CTX_free(ctx);
        (void)close(fd);
        if (!ok) errno = saved != 0 ? saved : EIO;
    }
    return ok ? 0 : -1;
}

static int sha256_buffer(const unsigned char *data, size_t len, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        errno = ENOMEM;
        return -1;
    }
    int ok = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, len) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, NULL) == 1) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    if (!ok) errno = EIO;
    return ok ? 0 : -1;
}

static int aes256gcm_encrypt(const unsigned char key[CASK_KEY_LEN],
                             const unsigned char nonce[CASK_NONCE_LEN],
                             const unsigned char *aad, size_t aad_len,
                             const unsigned char *plain, size_t plain_len,
                             unsigned char *cipher,
                             unsigned char tag[CASK_TAG_LEN]) {
    if (aad_len > (size_t)INT_MAX || plain_len > (size_t)INT_MAX) {
        errno = EFBIG;
        return 0;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        errno = ENOMEM;
        return 0;
    }
    int len = 0;
    int out_len = 0;
    int ok = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)CASK_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len > 0U && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (plain_len > 0U && EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) != 1) goto done;
    out_len = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + out_len, &len) != 1) goto done;
    out_len += len;
    if (out_len != (int)plain_len) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)CASK_TAG_LEN, tag) != 1) goto done;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && errno == 0) errno = EIO;
    return ok;
}

static int aes256gcm_decrypt(const unsigned char key[CASK_KEY_LEN],
                             const unsigned char nonce[CASK_NONCE_LEN],
                             const unsigned char *aad, size_t aad_len,
                             const unsigned char *cipher, size_t cipher_len,
                             const unsigned char tag[CASK_TAG_LEN],
                             unsigned char *plain) {
    if (aad_len > (size_t)INT_MAX || cipher_len > (size_t)INT_MAX) {
        errno = EFBIG;
        return 0;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        errno = ENOMEM;
        return 0;
    }
    int len = 0;
    int out_len = 0;
    int ok = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)CASK_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len > 0U && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (cipher_len > 0U && EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len) != 1) goto done;
    out_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)CASK_TAG_LEN, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plain + out_len, &len) != 1) {
        errno = EACCES;
        goto done;
    }
    out_len += len;
    if (out_len != (int)cipher_len) {
        errno = EIO;
        goto done;
    }
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && errno == 0) errno = EIO;
    return ok;
}

static int open_temp_same_dir(const char *final_path, char *tmp_path, size_t tmp_sz) {
    char parent[PATH_MAX];
    char base[PATH_MAX];
    if (get_parent_dir(final_path, parent, sizeof(parent), base, sizeof(base)) != 0) return -1;

    for (unsigned int attempt = 0U; attempt < 100U; ++attempt) {
        int n = snprintf(tmp_path, tmp_sz, "%s/.%s.tmp.%ld.%u", parent, base, (long)getpid(), attempt);
        if (n < 0 || (size_t)n >= tmp_sz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    errno = EEXIST;
    return -1;
}

static int install_file(const char *tmp_path, const char *final_path, int force) {
    if (force) {
        struct stat st;
        if (lstat(final_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            errno = EISDIR;
            return -1;
        }
        if (rename(tmp_path, final_path) != 0) return -1;
    } else {
        if (link(tmp_path, final_path) != 0) return -1;
        if (unlink(tmp_path) != 0) return -1;
    }

    char parent[PATH_MAX];
    char base[PATH_MAX];
    if (get_parent_dir(final_path, parent, sizeof(parent), base, sizeof(base)) != 0) return -1;
    (void)base;
    (void)fsync_directory(parent);
    return 0;
}

static int install_buffer_atomically(const char *final_path, const unsigned char *data, size_t len, mode_t mode, int force) {
    if (len > CASK_MAX_DB_SIZE) {
        errno = EFBIG;
        return -1;
    }
    if (!force) {
        struct stat st;
        if (lstat(final_path, &st) == 0) {
            errno = EEXIST;
            return -1;
        }
        if (errno != ENOENT) return -1;
    }

    char tmp[PATH_MAX];
    int fd = open_temp_same_dir(final_path, tmp, sizeof(tmp));
    if (fd < 0) return -1;

    int ok = 0;
    int saved = 0;
    if (write_all(fd, data, len) != 0 || fchmod(fd, mode) != 0 || fsync(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
    } else if (close(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
        fd = -1;
    } else {
        fd = -1;
        if (install_file(tmp, final_path, force) == 0) {
            ok = 1;
        } else {
            saved = errno != 0 ? errno : EIO;
        }
    }
    if (fd >= 0) (void)close(fd);
    if (!ok) (void)unlink(tmp);
    if (!ok) errno = saved != 0 ? saved : EIO;
    return ok ? 0 : -1;
}

static int g_db_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    const char *base = strrchr(fpath, '/');
    base = base != NULL ? base + 1 : fpath;
    if (strcmp(base, "eater.db") != 0) return 0;

    ++g_db_count;
    if (g_db_count != 1) return 0;

    char canonical[PATH_MAX];
    if (realpath(fpath, canonical) == NULL) return 1;
    size_t canonical_len = strlen(canonical);
    if (canonical_len + 1U > sizeof(g_db_path)) {
        errno = ENAMETOOLONG;
        return 1;
    }
    memcpy(g_db_path, canonical, canonical_len + 1U);

    size_t base_len = strlen(g_container);
    if (strncmp(canonical, g_container, base_len) != 0 ||
        (canonical[base_len] != '/' && canonical[base_len] != '\0')) {
        errno = EINVAL;
        return 1;
    }
    const char *rel = canonical + base_len;
    if (*rel == '/') ++rel;
    size_t rel_len = strlen(rel);
    if (rel_len == 0U || rel_len + 1U > sizeof(g_db_rel)) {
        errno = ENAMETOOLONG;
        return 1;
    }
    memcpy(g_db_rel, rel, rel_len + 1U);
    return 0;
}

static int locate_eater_db(const char *container) {
    memset(g_db_path, 0, sizeof(g_db_path));
    memset(g_db_rel, 0, sizeof(g_db_rel));
    g_db_count = 0;
    if (nftw(container, g_db_callback, 32, FTW_PHYS) != 0) return -1;
    if (g_db_count == 0) {
        errno = ENOENT;
        return -1;
    }
    if (g_db_count != 1) {
        errno = EEXIST;
        return -1;
    }
    return 0;
}

static int create_archive(const char *container, const char *db_rel, const char *tmp_archive, int quiet_error) {
    char exclude[PATH_MAX + 8U];
    int n = snprintf(exclude, sizeof(exclude), "./%s", db_rel);
    if (n < 0 || (size_t)n >= sizeof(exclude)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int errpipe[2];
    if (pipe2(errpipe, O_CLOEXEC) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        errno = saved;
        return -1;
    }

    if (pid == 0) {
        (void)close(errpipe[0]);
        if (dup2(errpipe[1], STDERR_FILENO) < 0) _exit(126);
        (void)close(errpipe[1]);
        char *const argv[] = {
            (char *)"tar", (char *)"--create", (char *)"--gzip", (char *)"--file", (char *)tmp_archive,
            (char *)"--exclude", exclude, (char *)"--directory", (char *)container, (char *)".", NULL
        };
        (void)setenv("GZIP", "-9", 1);
        execvp(argv[0], argv);
        _exit(127);
    }

    (void)close(errpipe[1]);
    char errbuf[4096];
    size_t used = 0U;
    while (used < sizeof(errbuf) - 1U) {
        ssize_t r = read(errpipe[0], errbuf + used, sizeof(errbuf) - 1U - used);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        used += (size_t)r;
    }
    (void)close(errpipe[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (!quiet_error && used > 0U) {
            errbuf[used] = '\0';
            fprintf(stderr, "CASK ERROR: tar failed: %s", errbuf);
        }
        errno = EIO;
        return -1;
    }
    return 0;
}

static int validate_tar_paths(const char *archive_path, int *db_count) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        errno = saved;
        return -1;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDERR_FILENO);
            (void)close(devnull);
        }
        (void)close(pipefd[1]);
        char *const argv[] = {
            (char *)"tar", (char *)"--list", (char *)"--gzip", (char *)"--quoting-style=escape",
            (char *)"--file", (char *)archive_path, NULL
        };
        execvp(argv[0], argv);
        _exit(127);
    }

    (void)close(pipefd[1]);
    char line[PATH_MAX * 2U];
    size_t used = 0U;
    int bad = 0;
    int dbs = 0;
    unsigned char chunk[8192U];

    for (;;) {
        ssize_t r = read(pipefd[0], chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR) continue;
            bad = 1;
            break;
        }
        if (r == 0) break;
        for (size_t i = 0U; i < (size_t)r; ++i) {
            unsigned char c = chunk[i];
            if (c == '\n') {
                line[used] = '\0';
                if (line[0] == '\0') {
                    bad = 1;
                    break;
                }
                const char *p = line;
                while (p[0] == '.' && p[1] == '/') p += 2;
                if (*p == '/') {
                    bad = 1;
                    break;
                }
                char work[PATH_MAX * 2U];
                size_t plen = strlen(p);
                if (plen + 1U > sizeof(work)) {
                    bad = 1;
                    break;
                }
                memcpy(work, p, plen + 1U);
                char *save = NULL;
                char *part = strtok_r(work, "/", &save);
                while (part != NULL) {
                    if (strcmp(part, "..") == 0) {
                        bad = 1;
                        break;
                    }
                    part = strtok_r(NULL, "/", &save);
                }
                if (bad) break;
                const char *base = strrchr(p, '/');
                base = base != NULL ? base + 1 : p;
                if (strcmp(base, "eater.db") == 0) ++dbs;
                used = 0U;
            } else {
                if (used + 1U >= sizeof(line)) {
                    bad = 1;
                    break;
                }
                line[used++] = (char)c;
            }
        }
        if (bad) break;
    }
    (void)close(pipefd[0]);

    int status = 0;
    int wait_ok = waitpid(pid, &status, 0);
    if (!bad && used != 0U) bad = 1;
    if (bad || wait_ok < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EINVAL;
        return -1;
    }
    *db_count = dbs;
    return 0;
}

static int validate_tar_types(const char *archive_path) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        errno = saved;
        return -1;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDERR_FILENO);
            (void)close(devnull);
        }
        (void)close(pipefd[1]);
        char *const argv[] = {
            (char *)"tar", (char *)"--list", (char *)"--verbose", (char *)"--gzip",
            (char *)"--quoting-style=escape", (char *)"--file", (char *)archive_path, NULL
        };
        execvp(argv[0], argv);
        _exit(127);
    }

    (void)close(pipefd[1]);
    char line[PATH_MAX * 2U];
    size_t used = 0U;
    int bad = 0;
    unsigned char chunk[8192U];
    for (;;) {
        ssize_t r = read(pipefd[0], chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR) continue;
            bad = 1;
            break;
        }
        if (r == 0) break;
        for (size_t i = 0U; i < (size_t)r; ++i) {
            unsigned char c = chunk[i];
            if (c == '\n') {
                if (used == 0U) {
                    bad = 1;
                    break;
                }
                char type = line[0];
                if (type != '-' && type != 'd') {
                    bad = 1;
                    break;
                }
                used = 0U;
            } else {
                if (used + 1U >= sizeof(line)) {
                    bad = 1;
                    break;
                }
                line[used++] = (char)c;
            }
        }
        if (bad) break;
    }
    (void)close(pipefd[0]);
    int status = 0;
    int wait_ok = waitpid(pid, &status, 0);
    if (!bad && used != 0U) bad = 1;
    if (bad || wait_ok < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int run_quiet_program(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull >= 0) {
            (void)dup2(devnull, STDIN_FILENO);
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            (void)close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int validate_gzip(const char *archive_path) {
    char *const argv[] = { (char *)"gzip", (char *)"-t", (char *)"--", (char *)archive_path, NULL };
    return run_quiet_program(argv);
}

static int validate_archive(const char *archive_path, int *db_count) {
    struct stat st;
    if (lstat(archive_path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    if (validate_tar_paths(archive_path, db_count) != 0) return -1;
    if (validate_tar_types(archive_path) != 0) return -1;
    return 0;
}

static int read_record_header(const char *path, struct record_header *hdr) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)CASK_RECORD_HEADER_LEN + (off_t)CASK_TAG_LEN) {
        (void)close(fd);
        errno = EINVAL;
        return -1;
    }

    unsigned char raw[CASK_RECORD_HEADER_LEN];
    if (read_all(fd, raw, sizeof(raw)) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }

    size_t off = 0U;
    if (memcmp(raw + off, CASK_MAGIC, CASK_MAGIC_LEN) != 0) {
        (void)close(fd);
        errno = EINVAL;
        return -1;
    }
    off += CASK_MAGIC_LEN;
    uint32_t version = get_u32_be(raw + off);
    off += 4U;
    if (version != CASK_VERSION) {
        (void)close(fd);
        errno = EPROTONOSUPPORT;
        return -1;
    }
    memcpy(hdr->id, raw + off, CASK_ID_LEN);
    off += CASK_ID_LEN;
    memcpy(hdr->archive_hash, raw + off, CASK_ARCHIVE_HASH_LEN);
    off += CASK_ARCHIVE_HASH_LEN;
    memcpy(hdr->nonce, raw + off, CASK_NONCE_LEN);
    off += CASK_NONCE_LEN;
    hdr->db_len = get_u64_be(raw + off);
    off += 8U;
    hdr->cipher_len = get_u64_be(raw + off);

    if (hdr->db_len > CASK_MAX_DB_SIZE || hdr->cipher_len > CASK_MAX_PLAIN_SIZE ||
        hdr->cipher_len < 3U || hdr->cipher_len > (uint64_t)SIZE_MAX) {
        (void)close(fd);
        errno = EFBIG;
        return -1;
    }

    uint64_t expected = (uint64_t)CASK_RECORD_HEADER_LEN + hdr->cipher_len + (uint64_t)CASK_TAG_LEN;
    if ((uintmax_t)st.st_size != (uintmax_t)expected) {
        (void)close(fd);
        errno = EIO;
        return -1;
    }

    int saved = errno;
    if (close(fd) != 0) return -1;
    errno = saved;
    return 0;
}

static int read_record_plaintext(const char *record_path, const struct record_header *hdr,
                                 const unsigned char key[CASK_KEY_LEN],
                                 unsigned char **plain_out, size_t *plain_len_out,
                                 char *db_rel_out, size_t db_rel_out_sz,
                                 unsigned char **db_out, size_t *db_len_out) {
    *plain_out = NULL;
    *plain_len_out = 0U;
    *db_out = NULL;
    *db_len_out = 0U;
    if (hdr->cipher_len > (uint64_t)SIZE_MAX || hdr->db_len > (uint64_t)SIZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    size_t cipher_len = (size_t)hdr->cipher_len;
    size_t db_len = (size_t)hdr->db_len;
    unsigned char *cipher = malloc(cipher_len != 0U ? cipher_len : 1U);
    unsigned char *plain = malloc(cipher_len != 0U ? cipher_len : 1U);
    if (cipher == NULL || plain == NULL) {
        free(cipher);
        free(plain);
        errno = ENOMEM;
        return -1;
    }

    int fd = open(record_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int saved = errno;
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
        return -1;
    }
    if (lseek(fd, (off_t)CASK_RECORD_HEADER_LEN, SEEK_SET) < 0) {
        int saved = errno;
        (void)close(fd);
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
        return -1;
    }
    unsigned char tag[CASK_TAG_LEN];
    if (read_all(fd, cipher, cipher_len) != 0 || read_all(fd, tag, sizeof(tag)) != 0) {
        int saved = errno;
        (void)close(fd);
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
        return -1;
    }

    unsigned char aad[CASK_MAGIC_LEN + 4U + CASK_ID_LEN + CASK_ARCHIVE_HASH_LEN];
    size_t off = 0U;
    memcpy(aad + off, CASK_MAGIC, CASK_MAGIC_LEN);
    off += CASK_MAGIC_LEN;
    put_u32_be(aad + off, CASK_VERSION);
    off += 4U;
    memcpy(aad + off, hdr->id, CASK_ID_LEN);
    off += CASK_ID_LEN;
    memcpy(aad + off, hdr->archive_hash, CASK_ARCHIVE_HASH_LEN);

    if (!aes256gcm_decrypt(key, hdr->nonce, aad, sizeof(aad), cipher, cipher_len, tag, plain)) {
        int saved = errno != 0 ? errno : EACCES;
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
        return -1;
    }

    if (cipher_len < 2U) {
        errno = EINVAL;
        goto fail;
    }
    uint16_t rel_len16 = get_u16_be(plain);
    size_t rel_len = (size_t)rel_len16;
    if (rel_len == 0U || rel_len >= CASK_RELBUF || rel_len + 2U > cipher_len ||
        2U + rel_len + db_len != cipher_len || rel_len + 1U > db_rel_out_sz) {
        errno = EINVAL;
        goto fail;
    }
    const unsigned char *path_bytes = plain + 2U;
    if (memchr(path_bytes, '\0', rel_len) != NULL) {
        errno = EINVAL;
        goto fail;
    }
    if (path_bytes[0] == '/') {
        errno = EINVAL;
        goto fail;
    }
    char reltmp[CASK_RELBUF];
    memcpy(reltmp, path_bytes, rel_len);
    reltmp[rel_len] = '\0';

    char work[CASK_RELBUF];
    memcpy(work, reltmp, rel_len + 1U);
    char *save = NULL;
    char *part = strtok_r(work, "/", &save);
    if (part == NULL) {
        errno = EINVAL;
        goto fail;
    }
    while (part != NULL) {
        if (strcmp(part, "..") == 0) {
            errno = EINVAL;
            goto fail;
        }
        part = strtok_r(NULL, "/", &save);
    }
    const char *base = strrchr(reltmp, '/');
    base = base != NULL ? base + 1 : reltmp;
    if (strcmp(base, "eater.db") != 0) {
        errno = EINVAL;
        goto fail;
    }

    memcpy(db_rel_out, reltmp, rel_len + 1U);
    unsigned char *db = malloc(db_len != 0U ? db_len : 1U);
    if (db == NULL) {
        errno = ENOMEM;
        goto fail;
    }
    if (db_len > 0U) memcpy(db, plain + 2U + rel_len, db_len);
    OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
    free(cipher);
    *plain_out = plain;
    *plain_len_out = cipher_len;
    *db_out = db;
    *db_len_out = db_len;
    return 0;

fail:
    {
        int saved = errno != 0 ? errno : EIO;
        OPENSSL_cleanse(cipher, cipher_len != 0U ? cipher_len : 1U);
        OPENSSL_cleanse(plain, cipher_len != 0U ? cipher_len : 1U);
        free(cipher);
        free(plain);
        errno = saved;
    }
    return -1;
}

static int store_db_record(const char *stomach, const char *db_rel,
                           const unsigned char *db, size_t db_len,
                           const unsigned char archive_hash[CASK_ARCHIVE_HASH_LEN],
                           unsigned char out_id[CASK_ID_LEN],
                           char *out_record, size_t out_record_sz) {
    if (db_len > CASK_MAX_DB_SIZE || strlen(db_rel) == 0U || strlen(db_rel) >= CASK_RELBUF) {
        errno = EFBIG;
        return -1;
    }
    unsigned char key[CASK_KEY_LEN];
    unsigned char nonce[CASK_NONCE_LEN];
    unsigned char tag[CASK_TAG_LEN];
    unsigned char *plain = NULL;
    unsigned char *cipher = NULL;
    int fd = -1;
    char tmp[PATH_MAX];
    tmp[0] = '\0';
    int ok = 0;
    int saved = 0;

    if (load_or_create_master_key(stomach, key) != 0) return -1;
    if (RAND_bytes(out_id, CASK_ID_LEN) != 1 || RAND_bytes(nonce, CASK_NONCE_LEN) != 1) {
        errno = EIO;
        goto cleanup;
    }

    size_t rel_len = strlen(db_rel);
    size_t plain_len = 2U + rel_len + db_len;
    if (plain_len > (size_t)INT_MAX) {
        errno = EFBIG;
        goto cleanup;
    }
    plain = malloc(plain_len != 0U ? plain_len : 1U);
    cipher = malloc(plain_len != 0U ? plain_len : 1U);
    if (plain == NULL || cipher == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }
    put_u16_be(plain, (uint16_t)rel_len);
    memcpy(plain + 2U, db_rel, rel_len);
    if (db_len > 0U) memcpy(plain + 2U + rel_len, db, db_len);

    unsigned char aad[CASK_MAGIC_LEN + 4U + CASK_ID_LEN + CASK_ARCHIVE_HASH_LEN];
    size_t aad_off = 0U;
    memcpy(aad + aad_off, CASK_MAGIC, CASK_MAGIC_LEN);
    aad_off += CASK_MAGIC_LEN;
    put_u32_be(aad + aad_off, CASK_VERSION);
    aad_off += 4U;
    memcpy(aad + aad_off, out_id, CASK_ID_LEN);
    aad_off += CASK_ID_LEN;
    memcpy(aad + aad_off, archive_hash, CASK_ARCHIVE_HASH_LEN);

    if (!aes256gcm_encrypt(key, nonce, aad, sizeof(aad), plain, plain_len, cipher, tag)) goto cleanup;

    char records_dir[PATH_MAX];
    int n = snprintf(records_dir, sizeof(records_dir), "%s/records", stomach);
    if (n < 0 || (size_t)n >= sizeof(records_dir)) {
        errno = ENAMETOOLONG;
        goto cleanup;
    }
    if (ensure_dir(records_dir, 0700) != 0) goto cleanup;
    if (make_record_path(stomach, out_id, out_record, out_record_sz) != 0) goto cleanup;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", out_record, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        goto cleanup;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) goto cleanup;

    unsigned char hdr[CASK_RECORD_HEADER_LEN];
    size_t off = 0U;
    memcpy(hdr + off, CASK_MAGIC, CASK_MAGIC_LEN);
    off += CASK_MAGIC_LEN;
    put_u32_be(hdr + off, CASK_VERSION);
    off += 4U;
    memcpy(hdr + off, out_id, CASK_ID_LEN);
    off += CASK_ID_LEN;
    memcpy(hdr + off, archive_hash, CASK_ARCHIVE_HASH_LEN);
    off += CASK_ARCHIVE_HASH_LEN;
    memcpy(hdr + off, nonce, CASK_NONCE_LEN);
    off += CASK_NONCE_LEN;
    put_u64_be(hdr + off, (uint64_t)db_len);
    off += 8U;
    put_u64_be(hdr + off, (uint64_t)plain_len);

    if (write_all(fd, hdr, sizeof(hdr)) != 0 || write_all(fd, cipher, plain_len) != 0 ||
        write_all(fd, tag, sizeof(tag)) != 0 || fchmod(fd, 0600) != 0 || fsync(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
    } else if (close(fd) != 0) {
        saved = errno != 0 ? errno : EIO;
        fd = -1;
    } else {
        fd = -1;
        if (install_file(tmp, out_record, 0) == 0) {
            ok = 1;
        } else {
            saved = errno != 0 ? errno : EIO;
        }
    }

cleanup:
    if (fd >= 0) (void)close(fd);
    if (!ok && tmp[0] != '\0') (void)unlink(tmp);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plain, plain != NULL ? plain_len : 0U);
    OPENSSL_cleanse(cipher, cipher != NULL ? plain_len : 0U);
    free(plain);
    free(cipher);
    if (!ok) {
        if (errno == 0) errno = saved != 0 ? saved : EIO;
        else if (saved != 0) errno = saved;
        return -1;
    }
    return 0;
}

static int archive_command(const char *container_arg, const char *archive_arg, const char *stomach_arg) {
    char container[PATH_MAX];
    char archive[PATH_MAX];
    char stomach[PATH_MAX];
    if (!realpath(container_arg, container)) return -1;
    struct stat cst;
    if (stat(container, &cst) != 0) return -1;
    if (!S_ISDIR(cst.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    if (snprintf(g_container, sizeof(g_container), "%s", container) < 0 || strlen(container) + 1U > sizeof(g_container)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (absolute_path(archive_arg, archive, sizeof(archive)) != 0) return -1;
    if (output_path_ready(archive, container) != 0) return -1;
    if (stomach_arg != NULL) {
        if (absolute_path(stomach_arg, stomach, sizeof(stomach)) != 0) return -1;
    } else if (get_default_stomach(stomach, sizeof(stomach)) != 0) {
        return -1;
    }
    char resolved_stomach[PATH_MAX];
    if (resolve_path_for_check(stomach, resolved_stomach, sizeof(resolved_stomach)) != 0) return -1;
    if (path_is_inside(container, resolved_stomach)) {
        errno = EINVAL;
        return -1;
    }
    if (ensure_dir(stomach, 0700) != 0) return -1;
    if (locate_eater_db(container) != 0) return -1;

    struct stat db_before;
    if (lstat(g_db_path, &db_before) != 0 || !S_ISREG(db_before.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    unsigned char *db = NULL;
    size_t db_len = 0U;
    if (read_entire_file(g_db_path, &db, &db_len) != 0) return -1;

    printf("CASK: locating eater.db...\n");
    printf("CASK: database found: %s\n", g_db_rel);
    printf("CASK: creating compressed archive...\n");
    printf("CASK: preserving source container; no files will be deleted.\n");
    fflush(stdout);

    char tmp_archive[PATH_MAX];
    int fd = open_temp_same_dir(archive, tmp_archive, sizeof(tmp_archive));
    if (fd < 0) {
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        return -1;
    }
    if (close(fd) != 0) {
        int saved = errno;
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }

    if (create_archive(container, g_db_rel, tmp_archive, 0) != 0) {
        int saved = errno;
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }

    int db_count = 0;
    if (validate_archive(tmp_archive, &db_count) != 0 || db_count != 0) {
        int saved = errno != 0 ? errno : EEXIST;
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }

    if (lstat(g_db_path, &db_before) != 0) {
        int saved = errno;
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }
    unsigned char db_hash_before[SHA256_DIGEST_LENGTH];
    unsigned char db_hash_after[SHA256_DIGEST_LENGTH];
    if (sha256_buffer(db, db_len, db_hash_before) != 0 || sha256_file(g_db_path, db_hash_after) != 0 ||
        memcmp(db_hash_before, db_hash_after, sizeof(db_hash_before)) != 0 ||
        db_before.st_size != (off_t)db_len) {
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = EAGAIN;
        return -1;
    }

    if (install_file(tmp_archive, archive, 0) != 0) {
        int saved = errno;
        (void)unlink(tmp_archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }
    show_progress("Archiving", 100U);
    unsigned char archive_hash[CASK_ARCHIVE_HASH_LEN];
    if (sha256_file(archive, archive_hash) != 0) {
        int saved = errno;
        (void)unlink(archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }
    printf("CASK: archive SHA-256 calculated.\n");
    printf("CASK: encrypting eater.db...\n");

    unsigned char record_id[CASK_ID_LEN];
    char record_path[PATH_MAX];
    if (store_db_record(stomach, g_db_rel, db, db_len, archive_hash, record_id, record_path, sizeof(record_path)) != 0) {
        int saved = errno;
        (void)unlink(archive);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }
    OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
    free(db);

    char idhex[CASK_ID_LEN * 2U + 1U];
    char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
    hex_encode(record_id, CASK_ID_LEN, idhex, sizeof(idhex));
    hex_encode(archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
    show_progress("Encrypting", 100U);
    printf("CASK: storing database in CASK stomach...\n");
    printf("\nCASK ARCHIVE COMPLETE\n");
    printf("  Archive:        %s\n", archive);
    printf("  CASK record ID: %s\n", idhex);
    printf("  CASK record:    %s\n", record_path);
    printf("  Archive SHA256: %s\n", hashhex);
    printf("  Source changed: NO\n");
    return 0;
}

static int record_authenticate(const char *record_path, const struct record_header *hdr,
                               const unsigned char key[CASK_KEY_LEN], char *db_rel, size_t db_rel_sz,
                               unsigned char **db, size_t *db_len) {
    unsigned char *plain = NULL;
    size_t plain_len = 0U;
    int rc = read_record_plaintext(record_path, hdr, key, &plain, &plain_len, db_rel, db_rel_sz, db, db_len);
    if (plain != NULL) {
        OPENSSL_cleanse(plain, plain_len != 0U ? plain_len : 1U);
        free(plain);
    }
    return rc;
}

static int inspect_record(const char *stomach, const char *record_id_text) {
    unsigned char id[CASK_ID_LEN];
    if (parse_record_id(record_id_text, id) != 0) return -1;
    char record_path[PATH_MAX];
    if (make_record_path(stomach, id, record_path, sizeof(record_path)) != 0) return -1;

    struct record_header hdr;
    if (read_record_header(record_path, &hdr) != 0) return -1;
    if (!record_filename_matches_id(strrchr(record_path, '/') != NULL ? strrchr(record_path, '/') + 1 : record_path, hdr.id)) {
        errno = EPROTO;
        return -1;
    }

    unsigned char key[CASK_KEY_LEN];
    if (secure_read_master_key(stomach, key) != 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "CASK: master key is missing.\n");
            fprintf(stderr, "CASK records cannot be decrypted without the original master key.\n");
        } else {
            fprintf(stderr, "CASK: master key is unreadable.\n");
        }
        return -1;
    }
    char db_rel[CASK_RELBUF];
    unsigned char *db = NULL;
    size_t db_len = 0U;
    int auth_rc = record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len);
    OPENSSL_cleanse(key, sizeof(key));
    if (db != NULL) {
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
    }

    char idhex[CASK_ID_LEN * 2U + 1U];
    char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
    hex_encode(hdr.id, CASK_ID_LEN, idhex, sizeof(idhex));
    hex_encode(hdr.archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
    printf("CASK RECORD\n\n");
    printf("Record ID:       %s\n", idhex);
    printf("CASK Version:    %u\n", CASK_VERSION);
    printf("Database path:   %s\n", auth_rc == 0 ? db_rel : "[unavailable]");
    printf("Database size:   %llu bytes\n", (unsigned long long)hdr.db_len);
    printf("Archive SHA-256: %s\n", hashhex);
    printf("Ciphertext size: %llu bytes\n", (unsigned long long)hdr.cipher_len);
    printf("Encryption:      AES-256-GCM\n");
    if (auth_rc == 0) {
        printf("Authentication:  VALID\n");
        return 0;
    }
    printf("Authentication:  FAILED\n");
    errno = EACCES;
    return -1;
}

static int list_records(const char *stomach, int check) {
    char records_dir[PATH_MAX];
    int n = snprintf(records_dir, sizeof(records_dir), "%s/records", stomach);
    if (n < 0 || (size_t)n >= sizeof(records_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    DIR *dir = opendir(records_dir);
    if (dir == NULL) {
        if (errno == ENOENT) {
            printf("CASK STOMACH\n\nRecords: 0\n");
            if (check) {
                printf("\nRecords scanned:       0\nValid:                 0\nCorrupt:               0\nAuthentication failed: 0\nUnreadable:             0\n");
            }
            return 0;
        }
        return -1;
    }

    unsigned char key[CASK_KEY_LEN];
    int key_ok = secure_read_master_key(stomach, key) == 0;
    int key_errno = errno;

    unsigned long records = 0UL;
    unsigned long valid = 0UL;
    unsigned long corrupt = 0UL;
    unsigned long auth_failed = 0UL;
    unsigned long unreadable = 0UL;

    if (!check) {
        printf("CASK STOMACH\n\n");
    }
    if (!check) {
        printf("%-32s %-24s %-14s %-64s %s\n", "ID", "DATABASE", "SIZE", "ARCHIVE SHA-256", "STATUS");
        printf("---------------------------------------------------------------------------------------------------------------\n");
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t len = strlen(name);
        if (len != CASK_ID_LEN * 2U + 7U || strcmp(name + CASK_ID_LEN * 2U, ".caskdb") != 0) continue;
        char record_path[PATH_MAX];
        n = snprintf(record_path, sizeof(record_path), "%s/%s", records_dir, name);
        if (n < 0 || (size_t)n >= sizeof(record_path)) continue;

        ++records;
        unsigned char filename_id[CASK_ID_LEN];
        char idstem[CASK_ID_LEN * 2U + 1U];
        memcpy(idstem, name, CASK_ID_LEN * 2U);
        idstem[CASK_ID_LEN * 2U] = '\0';
        if (parse_record_id(idstem, filename_id) != 0) continue;

        struct record_header hdr;
        int header_rc = read_record_header(record_path, &hdr);
        if (header_rc != 0 || !record_filename_matches_id(name, hdr.id)) {
            ++corrupt;
            if (!check) printf("%-32s %-24s %-14s %-64s [CORRUPT]\n", idstem, "?", "?", "? ");
            continue;
        }
        if (!key_ok) {
            ++unreadable;
            if (!check) {
                char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
                hex_encode(hdr.archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
                printf("%-32s %-24s %-14llu %-64s [KEY UNAVAILABLE]\n", idstem, "[encrypted]", (unsigned long long)hdr.db_len, hashhex);
            }
            continue;
        }

        char db_rel[CASK_RELBUF];
        unsigned char *db = NULL;
        size_t db_len = 0U;
        int auth_rc = record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len);
        if (auth_rc != 0) {
            ++auth_failed;
            if (!check) {
                char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
                hex_encode(hdr.archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
                printf("%-32s %-24s %-14llu %-64s [AUTHENTICATION FAILED]\n", idstem, "?", (unsigned long long)hdr.db_len, hashhex);
            }
        } else {
            ++valid;
            if (!check) {
                char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
                hex_encode(hdr.archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
                printf("%-32s %-24s %-14llu %-64s VALID\n", idstem, db_rel, (unsigned long long)hdr.db_len, hashhex);
            }
        }
        if (db != NULL) {
            OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
            free(db);
        }
    }
    int dir_saved = errno;
    (void)closedir(dir);
    if (key_ok) OPENSSL_cleanse(key, sizeof(key));
    else errno = key_errno;

    if (check) {
        printf("Records scanned:       %lu\n", records);
        printf("Valid:                 %lu\n", valid);
        printf("Corrupt:               %lu\n", corrupt);
        printf("Authentication failed: %lu\n", auth_failed);
        printf("Unreadable:             %lu\n", unreadable);
        if (records == 0UL) return 0;
        if (corrupt != 0UL || auth_failed != 0UL || unreadable != 0UL) {
            errno = EIO;
            return -1;
        }
        return 0;
    }

    if (dir_saved != 0) errno = dir_saved;
    return 0;
}

static int stomach_command(const char *stomach_arg, int check) {
    char stomach[PATH_MAX];
    if (stomach_arg != NULL) {
        if (absolute_path(stomach_arg, stomach, sizeof(stomach)) != 0) return -1;
    } else if (get_default_stomach(stomach, sizeof(stomach)) != 0) {
        return -1;
    }
    return list_records(stomach, check);
}

static int scan_matching_records(const char *stomach, const unsigned char archive_hash[CASK_ARCHIVE_HASH_LEN],
                                 unsigned int *match_count, unsigned char match_ids[][CASK_ID_LEN],
                                 size_t max_matches) {
    *match_count = 0U;
    char records_dir[PATH_MAX];
    int n = snprintf(records_dir, sizeof(records_dir), "%s/records", stomach);
    if (n < 0 || (size_t)n >= sizeof(records_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    DIR *dir = opendir(records_dir);
    if (dir == NULL) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t len = strlen(name);
        if (len != CASK_ID_LEN * 2U + 7U || strcmp(name + CASK_ID_LEN * 2U, ".caskdb") != 0) continue;
        char idstem[CASK_ID_LEN * 2U + 1U];
        memcpy(idstem, name, CASK_ID_LEN * 2U);
        idstem[CASK_ID_LEN * 2U] = '\0';
        unsigned char id[CASK_ID_LEN];
        if (parse_record_id(idstem, id) != 0) continue;
        char record_path[PATH_MAX];
        n = snprintf(record_path, sizeof(record_path), "%s/%s", records_dir, name);
        if (n < 0 || (size_t)n >= sizeof(record_path)) continue;
        struct record_header hdr;
        if (read_record_header(record_path, &hdr) != 0) continue;
        if (!record_filename_matches_id(name, hdr.id)) continue;
        if (memcmp(hdr.archive_hash, archive_hash, CASK_ARCHIVE_HASH_LEN) != 0) continue;
        if (*match_count < (unsigned int)max_matches) {
            memcpy(match_ids[*match_count], id, CASK_ID_LEN);
        }
        ++(*match_count);
    }
    int saved = errno;
    (void)closedir(dir);
    errno = saved;
    return 0;
}

static int resolve_stomach(const char *stomach_arg, char stomach[PATH_MAX]) {
    if (stomach_arg != NULL) return absolute_path(stomach_arg, stomach, PATH_MAX);
    return get_default_stomach(stomach, PATH_MAX);
}

static int find_command(const char *archive_arg, const char *stomach_arg) {
    char archive[PATH_MAX];
    char stomach[PATH_MAX];
    if (absolute_path(archive_arg, archive, sizeof(archive)) != 0) return -1;
    if (resolve_stomach(stomach_arg, stomach) != 0) return -1;

    unsigned char hash[CASK_ARCHIVE_HASH_LEN];
    if (sha256_file(archive, hash) != 0) return -1;
    unsigned char ids[1024][CASK_ID_LEN];
    unsigned int matches = 0U;
    if (scan_matching_records(stomach, hash, &matches, ids, 1024U) != 0) return -1;

    char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
    hex_encode(hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
    printf("CASK: archive SHA-256: %s\n", hashhex);
    if (matches == 0U) {
        printf("CASK: no matching database found.\n");
        return 1;
    }

    unsigned char key[CASK_KEY_LEN];
    int key_ok = secure_read_master_key(stomach, key) == 0;
    for (unsigned int i = 0U; i < matches; ++i) {
        char idhex[CASK_ID_LEN * 2U + 1U];
        char record_path[PATH_MAX];
        if (make_record_path(stomach, ids[i], record_path, sizeof(record_path)) != 0) continue;
        struct record_header hdr;
        if (read_record_header(record_path, &hdr) != 0) continue;
        hex_encode(ids[i], CASK_ID_LEN, idhex, sizeof(idhex));
        printf("CASK: matching record found\n");
        printf("  CASK record ID: %s\n", idhex);
        printf("  Database size:  %llu bytes\n", (unsigned long long)hdr.db_len);
        if (key_ok) {
            char db_rel[CASK_RELBUF];
            unsigned char *db = NULL;
            size_t db_len = 0U;
            if (record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len) == 0) {
                printf("  Database:        %s\n", db_rel);
            } else {
                printf("  Database:        [AUTHENTICATION FAILED]\n");
            }
            if (db != NULL) {
                OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
                free(db);
            }
        } else {
            printf("  Database:        [master key unavailable]\n");
        }
        if (matches > 1U) printf("  Association:     AMBIGUOUS\n");
    }
    if (key_ok) OPENSSL_cleanse(key, sizeof(key));
    return 0;
}

static int verify_archive_command(const char *archive_arg, const char *stomach_arg) {
    char archive[PATH_MAX];
    char stomach[PATH_MAX];
    if (absolute_path(archive_arg, archive, sizeof(archive)) != 0) return -1;
    if (resolve_stomach(stomach_arg, stomach) != 0) return -1;

    printf("CASK VERIFY\n\n");
    printf("Archive:          %s\n", archive);

    if (validate_gzip(archive) != 0) {
        printf("GZIP:             INVALID\n");
        errno = EINVAL;
        return -1;
    }
    printf("GZIP:             VALID\n");

    int db_count = 0;
    if (validate_tar_paths(archive, &db_count) != 0) {
        printf("TAR:              INVALID\n");
        errno = EINVAL;
        return -1;
    }
    printf("TAR:              VALID\n");
    if (db_count != 0) {
        printf("CASK CONTENT:     INVALID (contains eater.db)\n");
        errno = EEXIST;
        return -1;
    }
    if (validate_tar_types(archive) != 0) {
        printf("ARCHIVE SAFETY:   REJECTED (links or special files present)\n");
        errno = EINVAL;
        return -1;
    }
    printf("ARCHIVE SAFETY:   VALID\n");

    unsigned char hash[CASK_ARCHIVE_HASH_LEN];
    if (sha256_file(archive, hash) != 0) return -1;
    char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
    hex_encode(hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
    printf("Archive SHA-256:  %s\n", hashhex);

    unsigned char ids[1024][CASK_ID_LEN];
    unsigned int matches = 0U;
    if (scan_matching_records(stomach, hash, &matches, ids, 1024U) != 0) return -1;
    if (matches == 0U) {
        printf("CASK RECORD:      MISSING\n");
        errno = ENOENT;
        return -1;
    }
    if (matches > 1U) {
        printf("CASK RECORD:      AMBIGUOUS (%u matches)\n", matches);
        errno = EEXIST;
        return -1;
    }
    printf("CASK RECORD:      FOUND\n");

    unsigned char key[CASK_KEY_LEN];
    if (secure_read_master_key(stomach, key) != 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "CASK: master key is missing.\n");
            fprintf(stderr, "CASK records cannot be decrypted without the original master key.\n");
        } else {
            fprintf(stderr, "CASK: master key is unreadable.\n");
        }
        return -1;
    }
    char record_path[PATH_MAX];
    if (make_record_path(stomach, ids[0], record_path, sizeof(record_path)) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }
    struct record_header hdr;
    if (read_record_header(record_path, &hdr) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }
    char db_rel[CASK_RELBUF];
    unsigned char *db = NULL;
    size_t db_len = 0U;
    if (record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        if (db != NULL) {
            OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
            free(db);
        }
        printf("DATABASE RECORD:  AUTHENTICATION FAILED\n");
        errno = EACCES;
        return -1;
    }
    OPENSSL_cleanse(key, sizeof(key));
    if (db != NULL) {
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
    }
    printf("DATABASE:         %s\n", db_rel);
    printf("DATABASE RECORD:  AUTHENTIC\n");
    return 0;
}

static int mkdir_parents_for_file(const char *path) {
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0U || len >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1U);
    char *slash = strrchr(tmp, '/');
    if (slash == NULL) return 0;
    *slash = '\0';
    return ensure_dir(tmp, 0700);
}

static int make_relative_safe_path(const char *root, const char *rel, char *out, size_t out_sz) {
    size_t rel_len = strlen(rel);
    if (rel_len == 0U || rel_len >= PATH_MAX || rel[0] == '/') {
        errno = EINVAL;
        return -1;
    }
    char work[PATH_MAX];
    memcpy(work, rel, rel_len + 1U);
    char *save = NULL;
    char *part = strtok_r(work, "/", &save);
    if (part == NULL) {
        errno = EINVAL;
        return -1;
    }
    while (part != NULL) {
        if (strcmp(part, "..") == 0 || part[0] == '\0') {
            errno = EINVAL;
            return -1;
        }
        part = strtok_r(NULL, "/", &save);
    }
    int n = snprintf(out, out_sz, "%s/%s", root, rel);
    if (n < 0 || (size_t)n >= out_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* rm_tree callback */
static int rm_tree_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_DP) return rmdir(fpath);
    return unlink(fpath);
}

static int remove_tree(const char *path) {
    return nftw(path, rm_tree_cb, 32, FTW_PHYS | FTW_DEPTH);
}

static int extract_archive_into_dir(const char *archive, const char *output_dir) {
    int errpipe[2];
    if (pipe2(errpipe, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        errno = saved;
        return -1;
    }
    if (pid == 0) {
        (void)close(errpipe[0]);
        if (dup2(errpipe[1], STDERR_FILENO) < 0) _exit(126);
        (void)close(errpipe[1]);
        char *const argv[] = {
            (char *)"tar", (char *)"--extract", (char *)"--gzip", (char *)"--file", (char *)archive,
            (char *)"--directory", (char *)output_dir,
            (char *)"--no-same-owner", (char *)"--no-same-permissions", NULL
        };
        execvp(argv[0], argv);
        _exit(127);
    }
    (void)close(errpipe[1]);
    char errbuf[4096];
    size_t used = 0U;
    while (used < sizeof(errbuf) - 1U) {
        ssize_t r = read(errpipe[0], errbuf + used, sizeof(errbuf) - 1U - used);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        used += (size_t)r;
    }
    (void)close(errpipe[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (used > 0U) {
            errbuf[used] = '\0';
            fprintf(stderr, "CASK ERROR: extraction failed: %s", errbuf);
        }
        errno = EIO;
        return -1;
    }
    return 0;
}

static int safe_extract_to(const char *archive, const char *output_dir) {
    struct stat st;
    if (lstat(output_dir, &st) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) return -1;

    char parent[PATH_MAX];
    char base[PATH_MAX];
    if (get_parent_dir(output_dir, parent, sizeof(parent), base, sizeof(base)) != 0) return -1;
    (void)base;
    char real_parent[PATH_MAX];
    if (realpath(parent, real_parent) == NULL) return -1;

    int db_count = 0;
    if (validate_archive(archive, &db_count) != 0) return -1;
    if (db_count != 0) {
        errno = EEXIST;
        return -1;
    }

    char tmpl[PATH_MAX];
    int n = snprintf(tmpl, sizeof(tmpl), "%s/.cask-extract-XXXXXX", real_parent);
    if (n < 0 || (size_t)n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char *temp_dir = mkdtemp(tmpl);
    if (temp_dir == NULL) return -1;

    if (extract_archive_into_dir(archive, temp_dir) != 0) {
        int saved = errno;
        (void)remove_tree(temp_dir);
        errno = saved;
        return -1;
    }
    if (fsync_directory(temp_dir) != 0) {
        int saved = errno;
        (void)remove_tree(temp_dir);
        errno = saved;
        return -1;
    }
    if (rename(temp_dir, output_dir) != 0) {
        int saved = errno;
        (void)remove_tree(temp_dir);
        errno = saved;
        return -1;
    }
    (void)fsync_directory(real_parent);
    return 0;
}

static int extract_command(const char *archive_arg, const char *output_arg) {
    char archive[PATH_MAX];
    char output[PATH_MAX];
    if (absolute_path(archive_arg, archive, sizeof(archive)) != 0) return -1;
    if (absolute_path(output_arg, output, sizeof(output)) != 0) return -1;
    if (safe_extract_to(archive, output) != 0) return -1;
    printf("CASK: extraction complete.\n");
    printf("  Archive:   %s\n", archive);
    printf("  Directory: %s\n", output);
    printf("  eater.db:  not present in archive by design.\n");
    return 0;
}

static int retrieve_command(const char *stomach_arg, const char *record_id_text, const char *output_arg, int force) {
    char stomach[PATH_MAX];
    if (resolve_stomach(stomach_arg, stomach) != 0) return -1;
    unsigned char id[CASK_ID_LEN];
    if (parse_record_id(record_id_text, id) != 0) return -1;
    char record_path[PATH_MAX];
    if (make_record_path(stomach, id, record_path, sizeof(record_path)) != 0) return -1;

    struct record_header hdr;
    if (read_record_header(record_path, &hdr) != 0) return -1;
    if (memcmp(id, hdr.id, CASK_ID_LEN) != 0) {
        errno = EPROTO;
        return -1;
    }

    unsigned char key[CASK_KEY_LEN];
    if (secure_read_master_key(stomach, key) != 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "CASK: master key is missing.\n");
            fprintf(stderr, "CASK records cannot be decrypted without the original master key.\n");
        } else {
            fprintf(stderr, "CASK: master key is unreadable.\n");
        }
        return -1;
    }
    char db_rel[CASK_RELBUF];
    unsigned char *db = NULL;
    size_t db_len = 0U;
    if (record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len) != 0) {
        int saved = errno;
        OPENSSL_cleanse(key, sizeof(key));
        if (db != NULL) {
            OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
            free(db);
        }
        errno = saved;
        return -1;
    }
    OPENSSL_cleanse(key, sizeof(key));

    char output[PATH_MAX];
    if (absolute_path(output_arg, output, sizeof(output)) != 0) {
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        return -1;
    }
    if (install_buffer_atomically(output, db, db_len, 0600, force) != 0) {
        int saved = errno;
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
        return -1;
    }
    OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
    free(db);

    printf("CASK: eater.db retrieved.\n");
    printf("  Record:    %s\n", record_id_text);
    printf("  Database:  %s\n", db_rel);
    printf("  Output:    %s\n", output);
    printf("  Size:      %llu bytes\n", (unsigned long long)db_len);
    return 0;
}

static int g_restore_db_count = 0;

static int restore_db_count_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (typeflag == FTW_F && sb != NULL && S_ISREG(sb->st_mode)) {
        const char *base = strrchr(fpath, '/');
        base = base != NULL ? base + 1 : fpath;
        if (strcmp(base, "eater.db") == 0) ++g_restore_db_count;
    }
    return 0;
}

static int restore_command(const char *archive_arg, const char *output_container_arg, const char *stomach_arg) {
    char archive[PATH_MAX];
    char output_container[PATH_MAX];
    char stomach[PATH_MAX];
    if (absolute_path(archive_arg, archive, sizeof(archive)) != 0) return -1;
    if (absolute_path(output_container_arg, output_container, sizeof(output_container)) != 0) return -1;
    if (resolve_stomach(stomach_arg, stomach) != 0) return -1;

    struct stat existing;
    if (lstat(output_container, &existing) == 0) {
        errno = EEXIST;
        return -1;
    }
    if (errno != ENOENT) return -1;

    int archive_db_count = 0;
    if (validate_archive(archive, &archive_db_count) != 0) return -1;
    if (archive_db_count != 0) {
        errno = EEXIST;
        return -1;
    }
    unsigned char archive_hash[CASK_ARCHIVE_HASH_LEN];
    if (sha256_file(archive, archive_hash) != 0) return -1;

    unsigned char ids[1024][CASK_ID_LEN];
    unsigned int matches = 0U;
    if (scan_matching_records(stomach, archive_hash, &matches, ids, 1024U) != 0) return -1;
    if (matches == 0U) {
        errno = ENOENT;
        return -1;
    }
    if (matches > 1U) {
        errno = EEXIST;
        return -1;
    }

    unsigned char key[CASK_KEY_LEN];
    if (secure_read_master_key(stomach, key) != 0) {
        if (errno == ENOENT) {
            fprintf(stderr, "CASK: master key is missing.\n");
            fprintf(stderr, "CASK records cannot be decrypted without the original master key.\n");
        } else {
            fprintf(stderr, "CASK: master key is unreadable.\n");
        }
        return -1;
    }
    char record_path[PATH_MAX];
    if (make_record_path(stomach, ids[0], record_path, sizeof(record_path)) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }
    struct record_header hdr;
    if (read_record_header(record_path, &hdr) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        return -1;
    }

    char db_rel[CASK_RELBUF];
    unsigned char *db = NULL;
    size_t db_len = 0U;
    if (record_authenticate(record_path, &hdr, key, db_rel, sizeof(db_rel), &db, &db_len) != 0) {
        OPENSSL_cleanse(key, sizeof(key));
        if (db != NULL) {
            OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
            free(db);
        }
        errno = EACCES;
        return -1;
    }
    OPENSSL_cleanse(key, sizeof(key));

    char parent[PATH_MAX];
    char base[PATH_MAX];
    if (get_parent_dir(output_container, parent, sizeof(parent), base, sizeof(base)) != 0) goto restore_fail;
    (void)base;
    char real_parent[PATH_MAX];
    if (realpath(parent, real_parent) == NULL) goto restore_fail;

    char tmpl[PATH_MAX];
    int n = snprintf(tmpl, sizeof(tmpl), "%s/.cask-restore-XXXXXX", real_parent);
    if (n < 0 || (size_t)n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        goto restore_fail;
    }
    char *temp_dir = mkdtemp(tmpl);
    if (temp_dir == NULL) goto restore_fail;

    printf("CASK: validating archive...\n");
    if (extract_archive_into_dir(archive, temp_dir) != 0) goto restore_temp_fail;
    show_progress("Restoring", 100U);

    char db_target[PATH_MAX];
    if (make_relative_safe_path(temp_dir, db_rel, db_target, sizeof(db_target)) != 0) goto restore_temp_fail;
    if (mkdir_parents_for_file(db_target) != 0) goto restore_temp_fail;
    if (install_buffer_atomically(db_target, db, db_len, 0600, 0) != 0) goto restore_temp_fail;

    struct stat dbst;
    if (lstat(db_target, &dbst) != 0 || !S_ISREG(dbst.st_mode) || dbst.st_size != (off_t)db_len) {
        errno = EIO;
        goto restore_temp_fail;
    }
    g_restore_db_count = 0;
    if (nftw(temp_dir, restore_db_count_cb, 32, FTW_PHYS) != 0 || g_restore_db_count != 1) {
        errno = EIO;
        goto restore_temp_fail;
    }
    if (fsync_directory(temp_dir) != 0) goto restore_temp_fail;
    if (rename(temp_dir, output_container) != 0) goto restore_temp_fail_no_remove;
    (void)fsync_directory(real_parent);

    {
        char idhex[CASK_ID_LEN * 2U + 1U];
        char hashhex[CASK_ARCHIVE_HASH_LEN * 2U + 1U];
        hex_encode(ids[0], CASK_ID_LEN, idhex, sizeof(idhex));
        hex_encode(archive_hash, CASK_ARCHIVE_HASH_LEN, hashhex, sizeof(hashhex));
        printf("\nCASK RESTORE COMPLETE\n");
        printf("  Archive:           %s\n", archive);
        printf("  Record:            %s\n", idhex);
        printf("  Container:         %s\n", output_container);
        printf("  Database:          %s\n", db_rel);
        printf("  Database size:     %llu bytes\n", (unsigned long long)db_len);
        printf("  Archive SHA-256:   %s\n", hashhex);
        printf("\nSource archive changed: NO\n");
        printf("CASK record changed:    NO\n");
    }
    OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
    free(db);
    return 0;

restore_temp_fail:
    {
        int saved = errno != 0 ? errno : EIO;
        (void)remove_tree(temp_dir);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
    }
    return -1;

restore_temp_fail_no_remove:
    {
        int saved = errno != 0 ? errno : EIO;
        /* If rename failed, temp_dir still exists. */
        (void)remove_tree(temp_dir);
        OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
        free(db);
        errno = saved;
    }
    return -1;


restore_fail:
    OPENSSL_cleanse(db, db_len != 0U ? db_len : 1U);
    free(db);
    return -1;
}

static int parse_command_options(int argc, char **argv, int start, struct command_options *opts,
                                 const char **positional, size_t max_positional, size_t *npos) {
    *npos = 0U;
    for (int i = start; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--stomach") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "CASK ERROR: --stomach requires a directory.\n");
                return 2;
            }
            opts->stomach = argv[++i];
        } else if (strcmp(arg, "--force") == 0) {
            opts->force = 1;
        } else if (strcmp(arg, "--check") == 0) {
            opts->check = 1;
        } else if (strcmp(arg, "--help") == 0) {
            usage(stdout);
            exit(EXIT_SUCCESS);
        } else if (strcmp(arg, "--version") == 0) {
            version(stdout);
            exit(EXIT_SUCCESS);
        } else if (arg[0] == '-') {
            fprintf(stderr, "CASK ERROR: unknown option: %s\n", arg);
            return 2;
        } else {
            if (*npos >= max_positional) {
                fprintf(stderr, "CASK ERROR: too many positional arguments.\n");
                return 2;
            }
            positional[*npos] = arg;
            ++*npos;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 1) {
        usage(stderr);
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        version(stdout);
        return 0;
    }

    const char *command = argv[1];
    struct command_options opts = {0};
    const char *positional[4];
    size_t npos = 0U;
    int parse_rc = parse_command_options(argc, argv, 2, &opts, positional, 4U, &npos);
    if (parse_rc != 0) return parse_rc;

    int rc = 0;
    errno = 0;
    if (strcmp(command, "archive") == 0) {
        if (npos != 2U || opts.force || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask archive <container> <output.tar.gz> [--stomach DIR]\n");
            return 2;
        }
        rc = archive_command(positional[0], positional[1], opts.stomach);
    } else if (strcmp(command, "stomach") == 0) {
        if (npos != 0U || opts.force) {
            fprintf(stderr, "CASK ERROR: usage: cask stomach [--check] [--stomach DIR]\n");
            return 2;
        }
        rc = stomach_command(opts.stomach, opts.check);
    } else if (strcmp(command, "inspect") == 0) {
        if (npos != 1U || opts.force || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask inspect <record-id> [--stomach DIR]\n");
            return 2;
        }
        char stomach[PATH_MAX];
        if (resolve_stomach(opts.stomach, stomach) != 0) rc = -1;
        else rc = inspect_record(stomach, positional[0]);
    } else if (strcmp(command, "find") == 0) {
        if (npos != 1U || opts.force || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask find <archive.tar.gz> [--stomach DIR]\n");
            return 2;
        }
        rc = find_command(positional[0], opts.stomach);
        if (rc == 1) return 1;
    } else if (strcmp(command, "retrieve") == 0) {
        if (npos != 2U || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask retrieve <record-id> <output-eater.db> [--force] [--stomach DIR]\n");
            return 2;
        }
        rc = retrieve_command(opts.stomach, positional[0], positional[1], opts.force);
    } else if (strcmp(command, "verify") == 0) {
        if (npos != 1U || opts.force || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask verify <archive.tar.gz> [--stomach DIR]\n");
            return 2;
        }
        rc = verify_archive_command(positional[0], opts.stomach);
    } else if (strcmp(command, "extract") == 0) {
        if (npos != 2U || opts.force || opts.check || opts.stomach != NULL) {
            fprintf(stderr, "CASK ERROR: usage: cask extract <archive.tar.gz> <output-dir>\n");
            return 2;
        }
        rc = extract_command(positional[0], positional[1]);
    } else if (strcmp(command, "restore") == 0) {
        if (npos != 2U || opts.force || opts.check) {
            fprintf(stderr, "CASK ERROR: usage: cask restore <archive.tar.gz> <output-container> [--stomach DIR]\n");
            return 2;
        }
        rc = restore_command(positional[0], positional[1], opts.stomach);
    } else if (strcmp(command, "--help") == 0) {
        usage(stdout);
        return 0;
    } else if (strcmp(command, "--version") == 0) {
        version(stdout);
        return 0;
    } else {
        fprintf(stderr, "CASK ERROR: unknown command: %s\n", command);
        usage(stderr);
        return 2;
    }

    if (rc != 0) {
        if (errno != 0) fprintf(stderr, "CASK ERROR: %s\n", strerror(errno));
        else fprintf(stderr, "CASK ERROR: operation failed.\n");
        return 1;
    }
    return 0;
}
