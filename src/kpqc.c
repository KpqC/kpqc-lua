#include <lua.h>
#include <lauxlib.h>

#include <stdint.h>
#include <stdlib.h>

#if defined(_WIN32)
#define KPQC_LUA_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define KPQC_LUA_EXPORT __attribute__((visibility("default")))
#else
#define KPQC_LUA_EXPORT
#endif

typedef int (*signature_keypair_fn)(uint8_t *, uint8_t *);
typedef int (*signature_sign_fn)(uint8_t *, uint64_t *, const uint8_t *,
                                 size_t, const uint8_t *, size_t,
                                 const uint8_t *);
typedef int (*signature_verify_fn)(const uint8_t *, size_t, const uint8_t *,
                                   size_t, const uint8_t *, size_t,
                                   const uint8_t *);
typedef int (*kem_keypair_fn)(uint8_t *, uint8_t *);
typedef int (*kem_encapsulate_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*kem_decapsulate_fn)(uint8_t *, const uint8_t *,
                                  const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
typedef int (*set_test_entropy_fn)(const uint8_t *, size_t);
typedef size_t (*test_entropy_remaining_fn)(void);
typedef void (*clear_test_entropy_fn)(void);
#endif

#define DECLARE_SIGNATURE(prefix)                                             \
    extern int prefix##_keypair(uint8_t *, uint8_t *);                       \
    extern int prefix##_sign(uint8_t *, uint64_t *, const uint8_t *, size_t, \
                             const uint8_t *, size_t, const uint8_t *);       \
    extern int prefix##_verify(const uint8_t *, size_t, const uint8_t *,     \
                               size_t, const uint8_t *, size_t,              \
                               const uint8_t *);

#define DECLARE_KEM(prefix)                                                    \
    extern int prefix##_keypair(uint8_t *, uint8_t *);                        \
    extern int prefix##_encapsulate(uint8_t *, uint8_t *, const uint8_t *);  \
    extern int prefix##_decapsulate(uint8_t *, const uint8_t *,              \
                                    const uint8_t *);

#if defined(KPQC_TEST_ENTROPY)
#define DECLARE_TEST_ENTROPY(prefix)                                           \
    extern int prefix##_set_test_entropy(const uint8_t *, size_t);            \
    extern size_t prefix##_test_entropy_remaining(void);                      \
    extern void prefix##_clear_test_entropy(void);
#else
#define DECLARE_TEST_ENTROPY(prefix)
#endif

#define DECLARE_SIGNATURE_ALGORITHM(prefix) \
    DECLARE_SIGNATURE(prefix)               \
    DECLARE_TEST_ENTROPY(prefix)

#define DECLARE_KEM_ALGORITHM(prefix) \
    DECLARE_KEM(prefix)               \
    DECLARE_TEST_ENTROPY(prefix)

DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer128f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer128s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer192f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer192s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer256f)
DECLARE_SIGNATURE_ALGORITHM(kpqc_aimer256s)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae2)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae3)
DECLARE_SIGNATURE_ALGORITHM(kpqc_haetae5)

DECLARE_KEM_ALGORITHM(kpqc_ntruplus768)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus864)
DECLARE_KEM_ALGORITHM(kpqc_ntruplus1152)
DECLARE_KEM_ALGORITHM(kpqc_smaugt128)
DECLARE_KEM_ALGORITHM(kpqc_smaugt192)
DECLARE_KEM_ALGORITHM(kpqc_smaugt256)
DECLARE_KEM_ALGORITHM(kpqc_timer)

#if defined(KPQC_TEST_ENTROPY)
extern void kpqc_test_aes256_ecb(uint8_t *, const uint8_t *, const uint8_t *);
#endif

typedef struct {
    const char *name;
    const char *id;
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
    signature_keypair_fn keypair;
    signature_sign_fn sign;
    signature_verify_fn verify;
#if defined(KPQC_TEST_ENTROPY)
    set_test_entropy_fn set_test_entropy;
    test_entropy_remaining_fn test_entropy_remaining;
    clear_test_entropy_fn clear_test_entropy;
#endif
} signature_algorithm;

typedef struct {
    const char *name;
    const char *id;
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    kem_keypair_fn keypair;
    kem_encapsulate_fn encapsulate;
    kem_decapsulate_fn decapsulate;
#if defined(KPQC_TEST_ENTROPY)
    set_test_entropy_fn set_test_entropy;
    test_entropy_remaining_fn test_entropy_remaining;
    clear_test_entropy_fn clear_test_entropy;
#endif
} kem_algorithm;

#if defined(KPQC_TEST_ENTROPY)
#define TEST_ENTROPY_FIELDS(prefix)                                            \
    , prefix##_set_test_entropy, prefix##_test_entropy_remaining,             \
        prefix##_clear_test_entropy
#else
#define TEST_ENTROPY_FIELDS(prefix)
#endif

#define SIGNATURE_ALGORITHM(name_value, id_value, prefix, public_size,        \
                            secret_size, signature_size)                      \
    {                                                                          \
        name_value, id_value, public_size, secret_size, signature_size,        \
            prefix##_keypair, prefix##_sign, prefix##_verify                   \
                TEST_ENTROPY_FIELDS(prefix)                                    \
    }

#define KEM_ALGORITHM(name_value, id_value, prefix, public_size, secret_size, \
                      ciphertext_size, shared_size)                            \
    {                                                                          \
        name_value, id_value, public_size, secret_size, ciphertext_size,       \
            shared_size, prefix##_keypair, prefix##_encapsulate,               \
            prefix##_decapsulate TEST_ENTROPY_FIELDS(prefix)                   \
    }

static const signature_algorithm signature_algorithms[] = {
    SIGNATURE_ALGORITHM("aimer128f", "aimer-128f", kpqc_aimer128f, 32, 48,
                        6944),
    SIGNATURE_ALGORITHM("aimer128s", "aimer-128s", kpqc_aimer128s, 32, 48,
                        4704),
    SIGNATURE_ALGORITHM("aimer192f", "aimer-192f", kpqc_aimer192f, 48, 72,
                        15408),
    SIGNATURE_ALGORITHM("aimer192s", "aimer-192s", kpqc_aimer192s, 48, 72,
                        10320),
    SIGNATURE_ALGORITHM("aimer256f", "aimer-256f", kpqc_aimer256f, 64, 96,
                        31360),
    SIGNATURE_ALGORITHM("aimer256s", "aimer-256s", kpqc_aimer256s, 64, 96,
                        20224),
    SIGNATURE_ALGORITHM("haetae2", "haetae-mode2", kpqc_haetae2, 992, 1408,
                        1474),
    SIGNATURE_ALGORITHM("haetae3", "haetae-mode3", kpqc_haetae3, 1472, 2112,
                        2349),
    SIGNATURE_ALGORITHM("haetae5", "haetae-mode5", kpqc_haetae5, 2080, 2752,
                        2948),
};

static const kem_algorithm kem_algorithms[] = {
    KEM_ALGORITHM("ntruplus768", "NTRU+768", kpqc_ntruplus768, 1152, 2336,
                  1152, 32),
    KEM_ALGORITHM("ntruplus864", "NTRU+864", kpqc_ntruplus864, 1296, 2624,
                  1296, 32),
    KEM_ALGORITHM("ntruplus1152", "NTRU+1152", kpqc_ntruplus1152, 1728, 3488,
                  1728, 32),
    KEM_ALGORITHM("smaugt128", "SMAUG-T128", kpqc_smaugt128, 672, 832, 672,
                  32),
    KEM_ALGORITHM("smaugt192", "SMAUG-T192", kpqc_smaugt192, 1088, 1312, 992,
                  32),
    KEM_ALGORITHM("smaugt256", "SMAUG-T256", kpqc_smaugt256, 1440, 1728, 1376,
                  32),
    KEM_ALGORITHM("timer", "TiMER", kpqc_timer, 672, 832, 608, 32),
};

static const uint8_t empty_bytes[1] = {0};

#define KPQC_TEMPORARY_BUFFER_METATABLE "kpqc.temporary_buffer"

typedef struct {
    size_t size;
    uint8_t *bytes;
} temporary_buffer;

static void secure_clear(void *pointer, size_t size) {
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (size-- != 0) *bytes++ = 0;
}

static void clear_temporary_buffer(temporary_buffer *buffer) {
    if (buffer->bytes == NULL) return;
    secure_clear(buffer->bytes, buffer->size);
    free(buffer->bytes);
    buffer->bytes = NULL;
    buffer->size = 0;
}

static int temporary_buffer_gc(lua_State *state) {
    temporary_buffer *buffer = (temporary_buffer *)lua_touserdata(state, 1);
    if (buffer != NULL) clear_temporary_buffer(buffer);
    return 0;
}

static void register_temporary_buffer(lua_State *state) {
    luaL_newmetatable(state, KPQC_TEMPORARY_BUFFER_METATABLE);
    lua_pushcfunction(state, temporary_buffer_gc);
    lua_setfield(state, -2, "__gc");
    lua_pop(state, 1);
}

static temporary_buffer *allocate_temporary_buffer(lua_State *state,
                                                   size_t size) {
    temporary_buffer *buffer = (temporary_buffer *)lua_newuserdata(
        state, sizeof(temporary_buffer));
    buffer->size = size;
    buffer->bytes = NULL;
    luaL_getmetatable(state, KPQC_TEMPORARY_BUFFER_METATABLE);
    lua_setmetatable(state, -2);

    buffer->bytes = (uint8_t *)malloc(size);
    if (buffer->bytes == NULL) {
        luaL_error(state, "could not allocate %lu bytes", (unsigned long)size);
    }
    return buffer;
}

static const uint8_t *check_string(lua_State *state, int index,
                                   size_t *length) {
    luaL_checktype(state, index, LUA_TSTRING);
    return (const uint8_t *)lua_tolstring(state, index, length);
}

static const uint8_t *check_bytes(lua_State *state, int index,
                                  size_t expected, const char *label) {
    size_t actual = 0;
    const uint8_t *value = check_string(state, index, &actual);
    if (actual != expected) {
        luaL_error(state, "%s must contain %lu bytes, received %lu", label,
                   (unsigned long)expected, (unsigned long)actual);
    }
    return value;
}

static const uint8_t *check_context(lua_State *state, int index,
                                    size_t *length) {
    if (lua_isnoneornil(state, index)) {
        *length = 0;
        return empty_bytes;
    }
    const uint8_t *value = check_string(state, index, length);
    if (*length > 255) luaL_error(state, "context must not exceed 255 bytes");
    return value;
}

static int operation_error(lua_State *state, const char *operation,
                           int status) {
    return luaL_error(state, "KpqC %s failed with status %d", operation,
                      status);
}

static const signature_algorithm *signature_upvalue(lua_State *state) {
    return (const signature_algorithm *)lua_touserdata(
        state, lua_upvalueindex(1));
}

static const kem_algorithm *kem_upvalue(lua_State *state) {
    return (const kem_algorithm *)lua_touserdata(state, lua_upvalueindex(1));
}

static int signature_generate_keypair(lua_State *state) {
    const signature_algorithm *algorithm = signature_upvalue(state);
    temporary_buffer *public_key =
        allocate_temporary_buffer(state, algorithm->public_key_size);
    temporary_buffer *secret_key =
        allocate_temporary_buffer(state, algorithm->secret_key_size);
    int status = algorithm->keypair(public_key->bytes, secret_key->bytes);
    if (status != 0) {
        clear_temporary_buffer(secret_key);
        clear_temporary_buffer(public_key);
        return operation_error(state, "key generation", status);
    }

    lua_createtable(state, 0, 2);
    lua_pushlstring(state, (const char *)public_key->bytes,
                    algorithm->public_key_size);
    lua_setfield(state, -2, "public_key");
    lua_pushlstring(state, (const char *)secret_key->bytes,
                    algorithm->secret_key_size);
    lua_setfield(state, -2, "secret_key");

    clear_temporary_buffer(secret_key);
    clear_temporary_buffer(public_key);
    return 1;
}
static int signature_sign(lua_State *state) {
    const signature_algorithm *algorithm = signature_upvalue(state);
    size_t message_size = 0;
    const uint8_t *message = check_string(state, 1, &message_size);
    const uint8_t *secret_key = check_bytes(
        state, 2, algorithm->secret_key_size, "secret_key");
    size_t context_size = 0;
    const uint8_t *context = check_context(state, 3, &context_size);
    temporary_buffer *signature =
        allocate_temporary_buffer(state, algorithm->signature_size);
    uint64_t actual_size = 0;

    int status = algorithm->sign(signature->bytes, &actual_size, message,
                                 message_size, context, context_size,
                                 secret_key);
    if (status != 0) {
        clear_temporary_buffer(signature);
        return operation_error(state, "signing", status);
    }
    if (actual_size != algorithm->signature_size) {
        clear_temporary_buffer(signature);
        return luaL_error(state,
                          "KpqC signing returned %llu bytes; expected %lu",
                          (unsigned long long)actual_size,
                          (unsigned long)algorithm->signature_size);
    }

    lua_pushlstring(state, (const char *)signature->bytes,
                    algorithm->signature_size);
    clear_temporary_buffer(signature);
    return 1;
}
static int signature_verify(lua_State *state) {
    const signature_algorithm *algorithm = signature_upvalue(state);
    size_t message_size = 0;
    const uint8_t *message = check_string(state, 1, &message_size);
    size_t signature_size = 0;
    const uint8_t *signature = check_string(state, 2, &signature_size);
    const uint8_t *public_key = check_bytes(
        state, 3, algorithm->public_key_size, "public_key");
    size_t context_size = 0;
    const uint8_t *context = check_context(state, 4, &context_size);

    if (signature_size != algorithm->signature_size) {
        lua_pushboolean(state, 0);
        return 1;
    }

    int status = algorithm->verify(signature, signature_size, message,
                                   message_size, context, context_size,
                                   public_key);
    lua_pushboolean(state, status == 0);
    return 1;
}

static int kem_generate_keypair(lua_State *state) {
    const kem_algorithm *algorithm = kem_upvalue(state);
    temporary_buffer *public_key =
        allocate_temporary_buffer(state, algorithm->public_key_size);
    temporary_buffer *secret_key =
        allocate_temporary_buffer(state, algorithm->secret_key_size);
    int status = algorithm->keypair(public_key->bytes, secret_key->bytes);
    if (status != 0) {
        clear_temporary_buffer(secret_key);
        clear_temporary_buffer(public_key);
        return operation_error(state, "key generation", status);
    }

    lua_createtable(state, 0, 2);
    lua_pushlstring(state, (const char *)public_key->bytes,
                    algorithm->public_key_size);
    lua_setfield(state, -2, "public_key");
    lua_pushlstring(state, (const char *)secret_key->bytes,
                    algorithm->secret_key_size);
    lua_setfield(state, -2, "secret_key");

    clear_temporary_buffer(secret_key);
    clear_temporary_buffer(public_key);
    return 1;
}

static int kem_encapsulate(lua_State *state) {
    const kem_algorithm *algorithm = kem_upvalue(state);
    const uint8_t *public_key = check_bytes(
        state, 1, algorithm->public_key_size, "public_key");
    temporary_buffer *ciphertext =
        allocate_temporary_buffer(state, algorithm->ciphertext_size);
    temporary_buffer *shared_secret =
        allocate_temporary_buffer(state, algorithm->shared_secret_size);
    int status = algorithm->encapsulate(ciphertext->bytes,
                                        shared_secret->bytes, public_key);
    if (status != 0) {
        clear_temporary_buffer(shared_secret);
        clear_temporary_buffer(ciphertext);
        return operation_error(state, "encapsulation", status);
    }

    lua_createtable(state, 0, 2);
    lua_pushlstring(state, (const char *)ciphertext->bytes,
                    algorithm->ciphertext_size);
    lua_setfield(state, -2, "ciphertext");
    lua_pushlstring(state, (const char *)shared_secret->bytes,
                    algorithm->shared_secret_size);
    lua_setfield(state, -2, "shared_secret");

    clear_temporary_buffer(shared_secret);
    clear_temporary_buffer(ciphertext);
    return 1;
}

static int kem_decapsulate(lua_State *state) {
    const kem_algorithm *algorithm = kem_upvalue(state);
    const uint8_t *ciphertext = check_bytes(
        state, 1, algorithm->ciphertext_size, "ciphertext");
    const uint8_t *secret_key = check_bytes(
        state, 2, algorithm->secret_key_size, "secret_key");
    temporary_buffer *shared_secret =
        allocate_temporary_buffer(state, algorithm->shared_secret_size);
    int status = algorithm->decapsulate(shared_secret->bytes, ciphertext,
                                        secret_key);
    if (status != 0) {
        clear_temporary_buffer(shared_secret);
        return operation_error(state, "decapsulation", status);
    }

    lua_pushlstring(state, (const char *)shared_secret->bytes,
                    algorithm->shared_secret_size);
    clear_temporary_buffer(shared_secret);
    return 1;
}

static void set_integer_field(lua_State *state, const char *name,
                              size_t value) {
    lua_pushinteger(state, (lua_Integer)value);
    lua_setfield(state, -2, name);
}

static void set_closure(lua_State *state, const char *name, lua_CFunction call,
                        const void *algorithm) {
    lua_pushlightuserdata(state, (void *)algorithm);
    lua_pushcclosure(state, call, 1);
    lua_setfield(state, -2, name);
}

#if defined(KPQC_TEST_ENTROPY)
typedef struct {
    set_test_entropy_fn set;
    test_entropy_remaining_fn remaining;
    clear_test_entropy_fn clear;
} test_entropy_functions;

static const test_entropy_functions *test_entropy_upvalue(lua_State *state) {
    return (const test_entropy_functions *)lua_touserdata(
        state, lua_upvalueindex(1));
}

static int set_test_entropy(lua_State *state) {
    const test_entropy_functions *functions = test_entropy_upvalue(state);
    size_t length = 0;
    const uint8_t *bytes = check_string(state, 1, &length);
    int status = functions->set(bytes, length);
    if (status != 0) return operation_error(state, "test entropy", status);
    return 0;
}

static int test_entropy_remaining(lua_State *state) {
    const test_entropy_functions *functions = test_entropy_upvalue(state);
    lua_pushinteger(state, (lua_Integer)functions->remaining());
    return 1;
}

static int clear_test_entropy(lua_State *state) {
    const test_entropy_functions *functions = test_entropy_upvalue(state);
    functions->clear();
    return 0;
}

static void add_test_entropy_api(lua_State *state, set_test_entropy_fn set,
                                 test_entropy_remaining_fn remaining,
                                 clear_test_entropy_fn clear) {
    test_entropy_functions *functions =
        (test_entropy_functions *)lua_newuserdata(
            state, sizeof(test_entropy_functions));
    functions->set = set;
    functions->remaining = remaining;
    functions->clear = clear;

    lua_pushvalue(state, -1);
    lua_pushcclosure(state, set_test_entropy, 1);
    lua_setfield(state, -3, "_set_test_entropy");
    lua_pushvalue(state, -1);
    lua_pushcclosure(state, test_entropy_remaining, 1);
    lua_setfield(state, -3, "_test_entropy_remaining");
    lua_pushcclosure(state, clear_test_entropy, 1);
    lua_setfield(state, -2, "_clear_test_entropy");
}

static int aes256_ecb(lua_State *state) {
    const uint8_t *key = check_bytes(state, 1, 32, "key");
    const uint8_t *input = check_bytes(state, 2, 16, "input");
    uint8_t output[16];
    kpqc_test_aes256_ecb(output, key, input);
    lua_pushlstring(state, (const char *)output, sizeof(output));
    secure_clear(output, sizeof(output));
    return 1;
}
#endif

static void create_signature_table(lua_State *state,
                                   const signature_algorithm *algorithm) {
    lua_createtable(state, 0, 8);
    lua_pushstring(state, algorithm->id);
    lua_setfield(state, -2, "id");
    lua_pushliteral(state, "signature");
    lua_setfield(state, -2, "type");

    lua_createtable(state, 0, 3);
    set_integer_field(state, "public_key", algorithm->public_key_size);
    set_integer_field(state, "secret_key", algorithm->secret_key_size);
    set_integer_field(state, "signature", algorithm->signature_size);
    lua_setfield(state, -2, "sizes");

    set_closure(state, "generate_keypair", signature_generate_keypair,
                algorithm);
    set_closure(state, "sign", signature_sign, algorithm);
    set_closure(state, "verify", signature_verify, algorithm);
#if defined(KPQC_TEST_ENTROPY)
    add_test_entropy_api(state, algorithm->set_test_entropy,
                         algorithm->test_entropy_remaining,
                         algorithm->clear_test_entropy);
#endif
}

static void create_kem_table(lua_State *state,
                             const kem_algorithm *algorithm) {
    lua_createtable(state, 0, 8);
    lua_pushstring(state, algorithm->id);
    lua_setfield(state, -2, "id");
    lua_pushliteral(state, "kem");
    lua_setfield(state, -2, "type");

    lua_createtable(state, 0, 4);
    set_integer_field(state, "public_key", algorithm->public_key_size);
    set_integer_field(state, "secret_key", algorithm->secret_key_size);
    set_integer_field(state, "ciphertext", algorithm->ciphertext_size);
    set_integer_field(state, "shared_secret", algorithm->shared_secret_size);
    lua_setfield(state, -2, "sizes");

    set_closure(state, "generate_keypair", kem_generate_keypair, algorithm);
    set_closure(state, "encapsulate", kem_encapsulate, algorithm);
    set_closure(state, "decapsulate", kem_decapsulate, algorithm);
#if defined(KPQC_TEST_ENTROPY)
    add_test_entropy_api(state, algorithm->set_test_entropy,
                         algorithm->test_entropy_remaining,
                         algorithm->clear_test_entropy);
#endif
}

KPQC_LUA_EXPORT int luaopen_kpqc(lua_State *state) {
    size_t index;
    register_temporary_buffer(state);
    lua_createtable(state, 0, 20);
    int module = lua_gettop(state);

    lua_pushliteral(state, "0.1.0");
    lua_setfield(state, module, "_VERSION");

    for (index = 0;
         index < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]);
         ++index) {
        create_signature_table(state, &signature_algorithms[index]);
        lua_setfield(state, module, signature_algorithms[index].name);
    }
    for (index = 0; index < sizeof(kem_algorithms) / sizeof(kem_algorithms[0]);
         ++index) {
        create_kem_table(state, &kem_algorithms[index]);
        lua_setfield(state, module, kem_algorithms[index].name);
    }

    lua_createtable(state,
                    (int)(sizeof(signature_algorithms) /
                          sizeof(signature_algorithms[0])),
                    0);
    for (index = 0;
         index < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]);
         ++index) {
        lua_getfield(state, module, signature_algorithms[index].name);
        lua_rawseti(state, -2, (int)index + 1);
    }
    lua_setfield(state, module, "signature_algorithms");

    lua_createtable(
        state,
        (int)(sizeof(kem_algorithms) / sizeof(kem_algorithms[0])), 0);
    for (index = 0; index < sizeof(kem_algorithms) / sizeof(kem_algorithms[0]);
         ++index) {
        lua_getfield(state, module, kem_algorithms[index].name);
        lua_rawseti(state, -2, (int)index + 1);
    }
    lua_setfield(state, module, "kem_algorithms");

#if defined(KPQC_TEST_ENTROPY)
    lua_pushcfunction(state, aes256_ecb);
    lua_setfield(state, module, "_aes256_ecb");
#endif

    return 1;
}
