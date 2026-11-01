/* ncg_native.c -- N-API addon that drives the TV's libncg_agent.so for the RO
 * (Right Object) exchange. Cross-compiled for 32-bit ARM (see build.sh) and
 * loaded by tv/ro-exchange.js on the TV.
 *
 * Why an addon: the RO request body and the DH session/decryption are computed
 * inside LG's opaque libncg_agent.so; only its exported C API can be trusted.
 * Binding it here (a few hundred lines) keeps the whole exchange in one node
 * process -- the signed SDX headers never touch disk, and the HTTP POST uses
 * node's own networking (no static-glibc DNS caveat).
 *
 * JS bindings (all synchronous):
 *   init(libPath, deviceId, secretDir) -> NCG_Init rc
 *   makeRequest(rsid)                  -> Buffer (form-urlencoded body)
 *   save(response)                     -> NCG_SaveROResponseMsg rc
 *   addLicenseXml(xml)                 -> rc (offline test / log recovery)
 *   cekList()                          -> [{cid, cekB64}]
 *   openFile(path)                     -> id (-1 on failure)
 *   cekFromHandle(id)                  -> cekB64 or null
 *   readFile(id)                       -> Buffer (plaintext)
 *   closeFile(id)                      -> true
 *
 * rc semantics: 0 = ok; 0xF0000422 = "license accepted but not persisted"
 * (expected for <verificationmethod>online); other 0xF0000xxx = failure.
 *
 * License list layout (RE'd from libncg_agent.so.2.0.0 and verified empirically
 * 2026-10-31 by injecting a known-good license XML via the exported
 * _ncg_AddLicenseXML and reading the CEK back -- it matched the live-cached
 * value byte for byte):
 *   agent+0x314 = int count, agent+0x318 = list head
 *   node+0x02   = 32-byte zero-padded cid
 *   node+0x23   = 32-byte CEK (aes_key || ctr_iv)
 *   node+0x94   = next node
 *
 * Build: see build.sh. The addon must be compiled with the ubuntu:20.04 cross
 * toolchain (Dockerfile), whose armhf glibc is 2.31: the dlopen/dlsym/dlclose
 * references then bind to their original GLIBC_2.4 versions. Toolchains with
 * glibc >= 2.34 re-version those symbols to GLIBC_2.34, which the TV's glibc
 * may not provide (the firmware's libncg_agent.so.2.0.0 only proves
 * glibc >= 2.33). Pinning the 2.4 versions back with .symver is rejected by the
 * u24 linker for shared libraries
 * ("version node not found for symbol dlsym@GLIBC_2.4"), so the toolchain
 * choice is the fix.
 *
 * Node-API declarations come from ncg_napi.h, a minimal self-maintained ABI
 * surface (see that file for the provenance of each fact).
 */
#include "ncg_napi.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

/* Exported C API of libncg_agent.so (signatures verified against the firmware's
 * own caller, libsm_appdrm.so SM_APPDRM_OpenDrmFile:
 * NCG_OpenAndVerifyFile(path, 1, 1, 0, 0, &handle) returns 0 on success and
 * delivers the file handle through the 6th argument; the library writes that
 * pointer unconditionally at entry, so a 5-argument call segfaults on
 * stack garbage). */
typedef int (*NCG_Init_t)(void **, const char *, const char *, const char *);
typedef int (*NCG_EnableLog_t)(int);
typedef int (*NCG_EnableLogParsedXML_t)(int);
typedef int (*NCG_MakeRORequestMsgWithSSID_t)(void *, const char *, char *, int *);
typedef int (*NCG_SaveROResponseMsg_t)(void *, const char *);
typedef int (*ncg_AddLicenseXML_t)(void *, const char *);
typedef int (*NCG_OpenAndVerifyFile_t)(const char *, int, int, int, int,
                                       void **);
typedef void *(*NCG_GetCEKForce_t)(void *, void *);
/* NCG_Read(handle, buf, len, outBytes): 4th arg is a pointer the library fills
 * (firmware caller seeds it 0 and reads it back); the return value is also the
 * byte count (see _ncg_fread in the disassembly). */
typedef int (*NCG_Read_t)(void *, void *, int, int *);

static void *g_lib = NULL;
static void *g_agent = NULL;
static NCG_MakeRORequestMsgWithSSID_t g_make = NULL;
static NCG_SaveROResponseMsg_t g_save = NULL;
static ncg_AddLicenseXML_t g_addxml = NULL;
static NCG_OpenAndVerifyFile_t g_openvf = NULL;
static NCG_GetCEKForce_t g_getcek = NULL;
static NCG_Read_t g_read = NULL;

#define MAX_HANDLES 16
static void *g_handles[MAX_HANDLES];

static napi_value throwErr(napi_env env, const char *msg) {
    napi_value undef = NULL;
    napi_throw_error(env, NULL, msg);
    napi_get_undefined(env, &undef);
    return undef;
}

static int isNumber(napi_env env, napi_value v) {
    napi_valuetype t = napi_undefined;
    return napi_typeof(env, v, &t) == napi_ok && t == napi_number;
}

static napi_value getIntArg(napi_env env, napi_callback_info info,
                            size_t idx, int *out) {
    size_t argc = 1;
    napi_value argv[1];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok)
        return NULL;
    if (argc <= idx || !isNumber(env, argv[idx]) ||
        napi_get_value_int32(env, argv[idx], out) != napi_ok) {
        return throwErr(env, "expected a number argument");
    }
    return NULL;
}

static napi_value getStringArg(napi_env env, napi_callback_info info,
                               size_t idx, char *buf, size_t bufsz) {
    /* Capacity for the widest binding (init is called with idx 0..2). */
    size_t argc = 3;
    napi_value argv[3];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok)
        return NULL;
    if (argc <= idx) return throwErr(env, "missing argument");
    size_t len = 0;
    if (napi_get_value_string_utf8(env, argv[idx], NULL, 0, &len) != napi_ok)
        return throwErr(env, "expected a string argument");
    if (len >= bufsz) return throwErr(env, "argument too long");
    if (napi_get_value_string_utf8(env, argv[idx], buf, bufsz, &len) != napi_ok)
        return throwErr(env, "expected a string argument");
    buf[len] = 0;
    return NULL;
}

static const char B64TAB[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const unsigned char *in, int n, char *out) {
    int i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        out[o++] = B64TAB[in[i] >> 2];
        out[o++] = B64TAB[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = B64TAB[((in[i + 1] & 0xF) << 2) | (in[i + 2] >> 6)];
        out[o++] = B64TAB[in[i + 2] & 0x3F];
    }
    if (n - i == 1) {
        out[o++] = B64TAB[in[i] >> 2];
        out[o++] = B64TAB[(in[i] & 3) << 4];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2) {
        out[o++] = B64TAB[in[i] >> 2];
        out[o++] = B64TAB[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = B64TAB[(in[i + 1] & 0xF) << 2];
        out[o++] = '=';
    }
    out[o] = 0;
}

/* -- init(libPath, deviceId, secretDir) ------------------------------------ */
static napi_value JsInit(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok ||
        argc != 3)
        return throwErr(env, "init(libPath, deviceId, secretDir)");
    char libpath[1024], deviceid[64], secret[1024];
    napi_value err;
    if ((err = getStringArg(env, info, 0, libpath, sizeof(libpath)))) return err;
    if ((err = getStringArg(env, info, 1, deviceid, sizeof(deviceid)))) return err;
    if ((err = getStringArg(env, info, 2, secret, sizeof(secret)))) return err;

    if (g_lib) dlclose(g_lib);
    g_lib = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) {
        return throwErr(env, "dlopen(libncg_agent.so) failed");
    }
    NCG_Init_t init = (NCG_Init_t)dlsym(g_lib, "NCG_Init");
    g_make = (NCG_MakeRORequestMsgWithSSID_t)dlsym(g_lib,
            "NCG_MakeRORequestMsgWithSSID");
    g_save = (NCG_SaveROResponseMsg_t)dlsym(g_lib, "NCG_SaveROResponseMsg");
    g_addxml = (ncg_AddLicenseXML_t)dlsym(g_lib, "_ncg_AddLicenseXML");
    g_openvf = (NCG_OpenAndVerifyFile_t)dlsym(g_lib, "NCG_OpenAndVerifyFile");
    g_getcek = (NCG_GetCEKForce_t)dlsym(g_lib, "NCG_GetCEKForce");
    g_read = (NCG_Read_t)dlsym(g_lib, "NCG_Read");
    if (!init || !g_make || !g_save || !g_addxml || !g_openvf || !g_getcek ||
        !g_read) {
        return throwErr(env, "libncg_agent.so is missing required symbols");
    }
    /* Library log to /var/log/ncgdrm-*.log: the CEK fallback capture path when
     * the driver dies before printing its JSON line. */
    NCG_EnableLog_t enlog = (NCG_EnableLog_t)dlsym(g_lib, "NCG_EnableLog");
    NCG_EnableLogParsedXML_t enxml =
        (NCG_EnableLogParsedXML_t)dlsym(g_lib, "NCG_EnableLogParsedXML");
    if (enlog) enlog(1);
    if (enxml) enxml(1);
    g_agent = NULL;
    memset(g_handles, 0, sizeof(g_handles));
    int rc = init(&g_agent, deviceid, "webostv", secret);
    if (!g_agent) return throwErr(env, "NCG_Init returned no agent");
    napi_value out;
    napi_create_int32(env, rc, &out);
    return out;
}

/* -- makeRequest(rsid) ----------------------------------------------------- */
static napi_value JsMakeRequest(napi_env env, napi_callback_info info) {
    char rsid[32];
    napi_value err;
    if ((err = getStringArg(env, info, 0, rsid, sizeof(rsid)))) return err;
    if (!g_make) return throwErr(env, "call init() first");
    char body[8192];
    int len = sizeof(body);
    int rc = g_make(g_agent, rsid, body, &len);
    if (rc != 0 || len <= 0 || len >= (int)sizeof(body))
        return throwErr(env, "NCG_MakeRORequestMsgWithSSID failed");
    void *data = NULL;
    napi_value ab;
    if (napi_create_arraybuffer(env, (size_t)len, &data, &ab) != napi_ok)
        return throwErr(env, "create_arraybuffer failed");
    memcpy(data, body, (size_t)len);
    return ab;
}

/* -- save(response) -------------------------------------------------------- */
static napi_value JsSave(napi_env env, napi_callback_info info) {
    char resp[131072];
    napi_value err;
    if ((err = getStringArg(env, info, 0, resp, sizeof(resp)))) return err;
    if (!g_save) return throwErr(env, "call init() first");
    int rc = g_save(g_agent, resp);
    napi_value out;
    napi_create_int32(env, rc, &out);
    return out;
}

/* -- addLicenseXml(xml) ---------------------------------------------------- */
static napi_value JsAddLicenseXml(napi_env env, napi_callback_info info) {
    char xml[131072];
    napi_value err;
    if ((err = getStringArg(env, info, 0, xml, sizeof(xml)))) return err;
    if (!g_addxml) return throwErr(env, "call init() first");
    int rc = g_addxml(g_agent, xml);
    napi_value out;
    napi_create_int32(env, rc, &out);
    return out;
}

/* -- cekList() ----------------------------------------------------------------
 * Walk the in-memory license list (layout in the header).
 */
static napi_value JsCekList(napi_env env, napi_callback_info info) {
    (void)info;
    if (!g_agent) return throwErr(env, "call init() first");
    int count = *(int *)((char *)g_agent + 0x314);
    void *node = *(void **)((char *)g_agent + 0x318);
    napi_value arr;
    napi_create_array(env, &arr);
    int n = 0;
    while (node && n < 64 && n <= count) {
        char cids[33] = {0}, cex[65] = {0};
        char b64[48];
        memcpy(cids, (char *)node + 2, 32);
        memcpy(cex, (char *)node + 0x23, 32);
        b64_encode((const unsigned char *)node + 0x23, 32, b64);
        napi_value obj, cidv, ceqv;
        napi_create_object(env, &obj);
        napi_create_string_utf8(env, cids, NAPI_AUTO_LENGTH, &cidv);
        napi_set_named_property(env, obj, "cid", cidv);
        napi_create_string_utf8(env, b64, NAPI_AUTO_LENGTH, &ceqv);
        napi_set_named_property(env, obj, "cekB64", ceqv);
        napi_set_element(env, arr, (uint32_t)n, obj);
        n++;
        node = *(void **)((char *)node + 0x94);
    }
    return arr;
}

/* -- openFile(path) -------------------------------------------------------- */
static napi_value JsOpenFile(napi_env env, napi_callback_info info) {
    char path[1024];
    napi_value err;
    if ((err = getStringArg(env, info, 0, path, sizeof(path)))) return err;
    if (!g_openvf) return throwErr(env, "call init() first");
    void *fh = NULL;
    int rc = g_openvf(path, 1, 1, 0, 0, &fh);
    int id = -1;
    if (rc == 0 && fh) {
        for (int i = 0; i < MAX_HANDLES; i++) {
            if (!g_handles[i]) { g_handles[i] = fh; id = i; break; }
        }
    }
    napi_value out;
    napi_create_int32(env, id, &out);
    return out;
}

static void *handleAt(napi_env env, int id) {
    if (id < 0 || id >= MAX_HANDLES) return NULL;
    return g_handles[id];
}

/* -- cekFromHandle(id) ----------------------------------------------------- */
static napi_value JsCekFromHandle(napi_env env, napi_callback_info info) {
    int id;
    napi_value err;
    if ((err = getIntArg(env, info, 0, &id))) return err;
    void *fh = handleAt(env, id);
    if (!fh) {
        napi_value undef;
        napi_get_undefined(env, &undef);
        return undef;
    }
    /* The CEK inside a file handle is at +1020 (RE'd from the firmware). */
    const unsigned char *cek = (const unsigned char *)fh + 1020;
    void *p = g_getcek ? g_getcek(g_agent, fh) : NULL;
    if (p && p != (void *)cek) {
        /* The library's own accessor wins over the hardcoded offset. */
        cek = (const unsigned char *)p;
    }
    char b64[48];
    b64_encode(cek, 32, b64);
    napi_value out;
    napi_create_string_utf8(env, b64, NAPI_AUTO_LENGTH, &out);
    return out;
}

/* -- readFile(id) ---------------------------------------------------------- */
static napi_value JsReadFile(napi_env env, napi_callback_info info) {
    int id;
    napi_value err;
    if ((err = getIntArg(env, info, 0, &id))) return err;
    void *fh = handleAt(env, id);
    if (!fh) return throwErr(env, "unknown file handle");
    unsigned char chunk[65536];
    size_t cap = 262144, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return throwErr(env, "malloc failed");
    for (;;) {
        int outbytes = 0;
        int n = g_read(fh, chunk, (int)sizeof(chunk), &outbytes);
        if (n <= 0) break;
        if (len + (size_t)n > cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return throwErr(env, "realloc failed"); }
            buf = nb;
        }
        memcpy(buf + len, chunk, (size_t)n);
        len += (size_t)n;
        if (len > (1u << 28)) { free(buf); return throwErr(env, "file too large"); }
    }
    void *data = NULL;
    napi_value ab;
    if (napi_create_arraybuffer(env, len, &data, &ab) != napi_ok) {
        free(buf);
        return throwErr(env, "create_arraybuffer failed");
    }
    memcpy(data, buf, len);
    free(buf);
    return ab;
}

/* -- closeFile(id) --------------------------------------------------------- */
static napi_value JsCloseFile(napi_env env, napi_callback_info info) {
    int id;
    napi_value err;
    if ((err = getIntArg(env, info, 0, &id))) return err;
    if (id >= 0 && id < MAX_HANDLES) g_handles[id] = NULL;
    napi_value out;
    napi_get_boolean(env, true, &out);
    return out;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"init", NULL, JsInit, NULL, NULL, NULL, napi_default, NULL},
        {"makeRequest", NULL, JsMakeRequest, NULL, NULL, NULL, napi_default, NULL},
        {"save", NULL, JsSave, NULL, NULL, NULL, napi_default, NULL},
        {"addLicenseXml", NULL, JsAddLicenseXml, NULL, NULL, NULL, napi_default, NULL},
        {"cekList", NULL, JsCekList, NULL, NULL, NULL, napi_default, NULL},
        {"openFile", NULL, JsOpenFile, NULL, NULL, NULL, napi_default, NULL},
        {"cekFromHandle", NULL, JsCekFromHandle, NULL, NULL, NULL, napi_default, NULL},
        {"readFile", NULL, JsReadFile, NULL, NULL, NULL, napi_default, NULL},
        {"closeFile", NULL, JsCloseFile, NULL, NULL, NULL, napi_default, NULL},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

/* Module registration (see ncg_napi.h for the loader mechanics).
 *
 * Self-registration constructor: the ONLY load path on node <= 10 (verified on
 * TV node 8.12.0: a symbol-only module fails there with
 * "Module did not self-register."); also the standard path of the official
 * NAPI_MODULE macro on every node version.
 *
 * The advertised N-API version is 1: every binding here uses v1/v2 functions
 * (max: napi_create_arraybuffer, v2), and older TVs run node that predates
 * newer versions.
 */
static napi_module _ncg_module = {
    1,                 /* nm_version */
    0,                 /* nm_flags */
    "ncg_native.node", /* nm_filename */
    Init,              /* nm_register_func */
    "ncg_native",      /* nm_modname */
    NULL,              /* nm_priv */
    {0, 0, 0, 0},      /* reserved[4] */
};
__attribute__((constructor)) static void _register_ncg_native(void) {
    napi_module_register(&_ncg_module);
}

/* Symbol-based fallback, used by node 11+ if the pending-list path is not
 * taken. Same entry point. */
napi_value napi_register_module_v1(napi_env env, napi_value exports) {
    return Init(env, exports);
}
