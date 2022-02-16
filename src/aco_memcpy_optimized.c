// Note: dst and src must be valid address already
#if !defined(aco_memcpy_optimized) && (defined(__x86_64__) || defined(_M_X64))
    #define aco_amd64_inline_short_aligned_memcpy_test_ok(dst, src, sz)                            \
        ((((uintptr_t)(src)&0x0f) == 0) && (((uintptr_t)(dst)&0x0f) == 0) && (((sz)&0x0f) == 0x08) \
         && (((sz) >> 4) >= 0) && (((sz) >> 4) <= 8))

    #define aco_amd64_inline_short_aligned_memcpy(dst, src, sz)                                      \
        do {                                                                                         \
            __uint128_t xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;                              \
            switch ((sz) >> 4) {                                                                     \
                case 0:                                                                              \
                    break;                                                                           \
                case 1:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    break;                                                                           \
                case 2:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    break;                                                                           \
                case 3:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    break;                                                                           \
                case 4:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    xmm3 = *((__uint128_t *)(src) + 3);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                    break;                                                                           \
                case 5:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    xmm3 = *((__uint128_t *)(src) + 3);                                              \
                    xmm4 = *((__uint128_t *)(src) + 4);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                    *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                    break;                                                                           \
                case 6:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    xmm3 = *((__uint128_t *)(src) + 3);                                              \
                    xmm4 = *((__uint128_t *)(src) + 4);                                              \
                    xmm5 = *((__uint128_t *)(src) + 5);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                    *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                    *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                    break;                                                                           \
                case 7:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    xmm3 = *((__uint128_t *)(src) + 3);                                              \
                    xmm4 = *((__uint128_t *)(src) + 4);                                              \
                    xmm5 = *((__uint128_t *)(src) + 5);                                              \
                    xmm6 = *((__uint128_t *)(src) + 6);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                    *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                    *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                    *((__uint128_t *)(dst) + 6) = xmm6;                                              \
                    break;                                                                           \
                case 8:                                                                              \
                    xmm0 = *((__uint128_t *)(src) + 0);                                              \
                    xmm1 = *((__uint128_t *)(src) + 1);                                              \
                    xmm2 = *((__uint128_t *)(src) + 2);                                              \
                    xmm3 = *((__uint128_t *)(src) + 3);                                              \
                    xmm4 = *((__uint128_t *)(src) + 4);                                              \
                    xmm5 = *((__uint128_t *)(src) + 5);                                              \
                    xmm6 = *((__uint128_t *)(src) + 6);                                              \
                    xmm7 = *((__uint128_t *)(src) + 7);                                              \
                    *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                    *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                    *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                    *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                    *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                    *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                    *((__uint128_t *)(dst) + 6) = xmm6;                                              \
                    *((__uint128_t *)(dst) + 7) = xmm7;                                              \
                    break;                                                                           \
            }                                                                                        \
            *((uint64_t *)((uintptr_t)(dst) + (sz)-8)) = *((uint64_t *)((uintptr_t)(src) + (sz)-8)); \
        } while (0)

    #define aco_memcpy_optimized(dst, src, sz)                                       \
        do {                                                                         \
            if (aco_amd64_inline_short_aligned_memcpy_test_ok((dst), (src), (sz))) { \
                aco_amd64_inline_short_aligned_memcpy((dst), (src), (sz));           \
            } else {                                                                 \
                memcpy((dst), (src), (sz));                                          \
            }                                                                        \
        } while (0)
#endif
