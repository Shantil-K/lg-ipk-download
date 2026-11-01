/* ncg_napi.h -- minimal, self-maintained declaration of the Node-API C ABI
 * surface that ncg_native.c actually uses (15 functions + module registration).
 * Written from scratch; no third-party node headers.
 *
 * Everything declared here is interop fact, not copied code: symbol names,
 * parameter order, fixed enum values, and one struct layout. Facts were
 * established from (a) the dynamic symbol tables of real node binaries
 * (node 22, x86-64 and armv7l: all 15 functions exported) and (b) the official
 * Node-API documentation (nodejs.org/api/n-api.html). A deviation from the
 * real ABI breaks the module load in the TV node (wrong
 * registration symbol/signature, wrong descriptor layout, wrong enum value or
 * argument order) before any artifact ships.
 *
 * Keep this surface frozen. If the addon ever needs another napi_* function:
 * add its prototype here, confirm the symbol in a node binary's dynamic table,
 * then re-run the full verification (cross-build + load on the TV).
 */
#ifndef NCG_NAPI_H
#define NCG_NAPI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque handles: the node side owns the layout; we never dereference. */
typedef struct napi_env__* napi_env;
typedef struct napi_value__* napi_value;
typedef struct napi_callback_info__* napi_callback_info;

typedef napi_value(*napi_callback)(napi_env env, napi_callback_info info);

/* Return codes: only napi_ok (0) is ever compared, but the full order is
 * recorded so a partial list can never drift from the spec. */
typedef enum {
  napi_ok = 0,
  napi_invalid_arg,
  napi_object_expected,
  napi_string_expected,
  napi_name_expected,
  napi_function_expected,
  napi_number_expected,
  napi_boolean_expected,
  napi_array_expected,
  napi_generic_failure,
  napi_pending_exception,
  napi_cancelled,
  napi_escape_called_twice,
  napi_handle_scope_mismatch,
  napi_callback_scope_mismatch,
  napi_queue_full,
  napi_closing,
  napi_bigint_expected,
  napi_date_expected,
  napi_arraybuffer_expected,
  napi_detachable_arraybuffer_expected,
  napi_would_deadlock,
  napi_no_external_buffers_allowed,
  napi_cannot_run_js,
} napi_status;

/* JS value types (matches typeof). */
typedef enum {
  napi_undefined = 0,
  napi_null,
  napi_boolean,
  napi_number,
  napi_string,
  napi_symbol,
  napi_object,
  napi_function,
  napi_external,
  napi_bigint,
} napi_valuetype;

typedef enum {
  napi_default = 0,
  napi_writable = 1,
  napi_enumerable = 2,
  napi_configurable = 4,
} napi_property_attributes;

/* 8-field layout, in order -- napi_define_properties reads it by offset.
 * utf8name and name are alternatives (one must be NULL);
 * method/getter/setter are alternatives; value is the data-property variant. */
typedef struct {
  const char* utf8name;
  napi_value name;
  napi_callback method;
  napi_callback getter;
  napi_callback setter;
  napi_value value;
  napi_property_attributes attributes;
  void* data;
} napi_property_descriptor;

/* Pass for the length parameter of a NUL-terminated string. */
#define NAPI_AUTO_LENGTH SIZE_MAX

napi_status napi_get_undefined(napi_env env, napi_value* result);
napi_status napi_get_boolean(napi_env env, bool value, napi_value* result);
napi_status napi_typeof(napi_env env, napi_value value,
                        napi_valuetype* result);
napi_status napi_get_cb_info(napi_env env, napi_callback_info cbinfo,
                             size_t* argc, napi_value* argv,
                             napi_value* this_arg, void** data);
napi_status napi_get_value_int32(napi_env env, napi_value value,
                                 int32_t* result);
napi_status napi_get_value_string_utf8(napi_env env, napi_value value,
                                       char* buf, size_t bufsize,
                                       size_t* result);
napi_status napi_throw_error(napi_env env, const char* code,
                             const char* msg);
napi_status napi_create_object(napi_env env, napi_value* result);
napi_status napi_create_array(napi_env env, napi_value* result);
napi_status napi_create_int32(napi_env env, int32_t value,
                              napi_value* result);
napi_status napi_create_string_utf8(napi_env env, const char* str,
                                    size_t length, napi_value* result);
napi_status napi_create_arraybuffer(napi_env env, size_t byte_length,
                                    void** data, napi_value* result);
napi_status napi_set_named_property(napi_env env, napi_value object,
                                    const char* utf8name,
                                    napi_value value);
napi_status napi_set_element(napi_env env, napi_value object,
                             uint32_t index, napi_value value);
napi_status napi_define_properties(napi_env env, napi_value object,
                                   size_t property_count,
                                   const napi_property_descriptor* properties);

/* Module registration. Two entry points exist, and a module must offer both to
 * load on every TV node:
 *   (1) self-registration: a load-time constructor calls the node-exported
 *       napi_module_register() with a napi_module descriptor; the loader
 *       activates it from a pending list. This is the ONLY path on
 *       node <= 10 -- the v8.12.0 loader (src/node.cc DLOpen) knows no other
 *       mechanism, so a module without it fails with
 *       "Module did not self-register." (verified on TV node 8.12.0, W21A
 *       firmware 03.53.45). It is also how the official NAPI_MODULE macro of
 *       every node version registers, so node 12/16 use it too.
 *   (2) the napi_register_module_v1 symbol, accepted by node 11+ as a fallback.
 * The v8.12.0 loader string table contains no "napi_register_module_v1" at all;
 * all three TV nodes (8.12.0 / 12.22.2 / 16.20.2) export napi_module_register
 * in their dynamic symbol tables.
 *
 * Struct layout: frozen N-API ABI, verbatim from node v8.12.0 src/node_api.h.
 * reserved[4] is what keeps the layout stable across node versions, so this one
 * definition serves node 8 through 16+. */
typedef struct napi_module {
  int nm_version;
  unsigned int nm_flags;
  const char* nm_filename;
  napi_value (*nm_register_func)(napi_env env, napi_value exports);
  const char* nm_modname;
  void* nm_priv;
  void* reserved[4];
} napi_module;

void napi_module_register(napi_module* mod);

#endif /* NCG_NAPI_H */
