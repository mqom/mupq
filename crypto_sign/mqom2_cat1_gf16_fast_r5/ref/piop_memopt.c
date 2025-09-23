#include "piop.h"
#if MQOM2_PARAM_WITH_STATISTICAL_BATCHING == 1
#include "xof.h"
#endif
#include "piop_cache.h"
#include "benchmark.h"
#include "expand_mq.h"

int ExpandBatchingChallenge(const uint8_t com[MQOM2_PARAM_DIGEST_SIZE], field_ext_elt Gamma[MQOM2_PARAM_ETA][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)]) {
    int ret = -1;
    uint32_t i;
    uint8_t stream[MQOM2_PARAM_ETA*BYTE_SIZE_FIELD_EXT(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    xof_context xof_ctx;

    ret = xof_init(&xof_ctx); ERR(ret, err);
    ret = xof_update(&xof_ctx, (const uint8_t*) "\x08", 1); ERR(ret, err);
    ret = xof_update(&xof_ctx, com, MQOM2_PARAM_DIGEST_SIZE); ERR(ret, err);
    ret = xof_squeeze(&xof_ctx, stream, MQOM2_PARAM_ETA*BYTE_SIZE_FIELD_EXT(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU));
    for(i=0; i<MQOM2_PARAM_ETA; i++) {
        field_ext_parse(&stream[i*BYTE_SIZE_FIELD_EXT(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)], MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU, Gamma[i]);
    }

    ret = 0;
err:
    return ret;
}

int ComputePz_xTau(const field_ext_elt x0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)], const field_base_elt x[FIELD_BASE_PACKING(MQOM2_PARAM_MQ_N)], const uint8_t mseed_eq[2 * MQOM2_PARAM_SEED_SIZE], field_ext_elt z0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)], field_ext_elt z1[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)]) {
    int ret = -1;
    uint32_t i, j, e;
    ExpandEquations_ctx EEctx;

    /* Only use rows for A_hat and b_hat to save memory */
    field_ext_elt A_hat_row[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    /* NOTE: we reuse the A_hat_row memory slot to save memory */
    field_ext_elt *b_hat_row = A_hat_row;

    field_ext_elt t0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    field_ext_elt t1[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    field_ext_elt t1_x0[MQOM2_PARAM_TAU];

    field_ext_elt z_0i, z_1i;

    /* Compute the equations expansion in a streaming way to save memory */
    ret = ExpandEquations_memopt_init(mseed_eq, &EEctx); ERR(ret, err);

    for(i = 0; i < MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU; i++) {
        for(j = 0; j < MQOM2_PARAM_MQ_N; j++){
            __BENCHMARK_START__(BS_PIOP_EXPAND_MQ);
            /* Extract row from A_hat */
            ret = ExpandEquations_memopt_update(&EEctx, A_hat_row); ERR(ret, err);
            __BENCHMARK_STOP__(BS_PIOP_EXPAND_MQ);
            /* Compute t1, common to all tau repetitions */
            __BENCHMARK_START__(BS_PIOP_COMPUTE_T1);
            t1[j] = field_ext_base_vect_mult(A_hat_row, x, j+1);
            __BENCHMARK_STOP__(BS_PIOP_COMPUTE_T1);
            /* Compute t0, different for each tau repetition */
            __BENCHMARK_START__(BS_PIOP_MAT_MUL_EXT);
            for(e = 0; e < MQOM2_PARAM_TAU; e++){
                t0[e][j] = field_ext_vect_mult(A_hat_row, x0[e], j+1); 
            }
            __BENCHMARK_STOP__(BS_PIOP_MAT_MUL_EXT);
        }
        /* Finish t1 computation with b_hat_row */
        __BENCHMARK_START__(BS_PIOP_EXPAND_MQ);
        ret = ExpandEquations_memopt_update(&EEctx, b_hat_row); ERR(ret, err);
        __BENCHMARK_STOP__(BS_PIOP_EXPAND_MQ);
        __BENCHMARK_START__(BS_PIOP_COMPUTE_T1);
        field_ext_vect_add(t1, b_hat_row, t1, MQOM2_PARAM_MQ_N);
        __BENCHMARK_STOP__(BS_PIOP_COMPUTE_T1);
        /* Compute the rest */
        __BENCHMARK_START__(BS_PIOP_COMPUTE_PZI);
        for(e = 0; e < MQOM2_PARAM_TAU; e++){
            t1_x0[e] = field_ext_vect_mult(t1, x0[e], MQOM2_PARAM_MQ_N); /* t1^T x0[e] */
        }
        for(e = 0; e < MQOM2_PARAM_TAU; e++) {
            field_ext_elt t0_x = field_ext_base_vect_mult(t0[e], x, MQOM2_PARAM_MQ_N);   /* t0^T x[e] */
            field_ext_vect_add(&t0_x, &t1_x0[e], &z_1i, 1);
            field_ext_vect_pack(z_1i, z1[e], i);
        }
        for(e = 0; e < MQOM2_PARAM_TAU; e++) {
            z_0i = field_ext_vect_mult(t0[e], x0[e], MQOM2_PARAM_MQ_N);
            field_ext_vect_pack(z_0i, z0[e], i);
        }
        __BENCHMARK_STOP__(BS_PIOP_COMPUTE_PZI);
    }

    ret = 0;
err:
    return ret;
}

int ComputePAlpha_memopt(const uint8_t com[MQOM2_PARAM_DIGEST_SIZE], const field_ext_elt x0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)], const field_ext_elt u0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)], const field_ext_elt u1[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)], const field_base_elt x[FIELD_BASE_PACKING(MQOM2_PARAM_MQ_N)], const uint8_t mseed_eq[2 * MQOM2_PARAM_SEED_SIZE], field_ext_elt alpha0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)], field_ext_elt alpha1[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)])
{
    int ret = -1;
    uint32_t e;
 
    /* Initialize the PIOP cache for t1 */
    __BENCHMARK_START__(BS_PIOP_EXPAND_BATCHING_MAT);
#if MQOM2_PARAM_WITH_STATISTICAL_BATCHING == 1
    uint32_t i;
    field_ext_elt Gamma[MQOM2_PARAM_ETA][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    ret = ExpandBatchingChallenge(com, Gamma); ERR(ret, err);
#else
    (void) com;
#endif
    __BENCHMARK_STOP__(BS_PIOP_EXPAND_BATCHING_MAT);

    field_ext_elt z0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)], z1[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    ret = ComputePz_xTau(x0, x, mseed_eq, z0, z1); ERR(ret, err);
    for(e = 0; e < MQOM2_PARAM_TAU; e++) {
        __BENCHMARK_START__(BS_PIOP_BATCH_AND_MASK);
#if MQOM2_PARAM_WITH_STATISTICAL_BATCHING == 1
        for(i=0; i<MQOM2_PARAM_ETA; i++) {
            field_ext_vect_pack(
                field_ext_vect_mult(Gamma[i], z0[e], MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU),
                alpha0[e], i
            );
        }
        for(i=0; i<MQOM2_PARAM_ETA; i++) {
            field_ext_vect_pack(
                field_ext_vect_mult(Gamma[i], z1[e], MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU),
                alpha1[e], i
            );
        }
        field_ext_vect_add(alpha0[e], u0[e], alpha0[e], MQOM2_PARAM_ETA);
        field_ext_vect_add(alpha1[e], u1[e], alpha1[e], MQOM2_PARAM_ETA);
#else
        field_ext_vect_add(z0[e], u0[e], alpha0[e], MQOM2_PARAM_ETA);
        field_ext_vect_add(z1[e], u1[e], alpha1[e], MQOM2_PARAM_ETA);
#endif
        __BENCHMARK_STOP__(BS_PIOP_BATCH_AND_MASK);
    }

    ret = 0;
err:
    return ret;
}

/***************************************************************/
/***************************************************************/

int ComputePzEval_xTau(const field_ext_elt r[MQOM2_PARAM_TAU], const field_ext_elt v_x[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)], const uint8_t mseed_eq[2 * MQOM2_PARAM_SEED_SIZE], const field_ext_elt y[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)], field_ext_elt v_z[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)]) {
    int ret = -1;
    uint32_t i, j, e;
    ExpandEquations_ctx EEctx;

    /* Only use rows for A_hat and b_hat to save memory */
    field_ext_elt A_hat_row[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    /* NOTE: we reuse the A_hat_row memory slot to save memory */
    field_ext_elt *b_hat_row = A_hat_row;

    field_ext_elt v_t[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    field_ext_elt tmp[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)];
    field_ext_elt y_r2[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    field_ext_elt v_zi;

    /* Compute the equations expansion in a streaming way to save memory */
    ret = ExpandEquations_memopt_init(mseed_eq, &EEctx); ERR(ret, err);

    for(i = 0; i < MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU; i++) {
        /* Perform operations row by row for A_hat */
        for(j = 0; j < MQOM2_PARAM_MQ_N; j++){
            ret = ExpandEquations_memopt_update(&EEctx, A_hat_row); ERR(ret, err);
            for(e = 0; e < MQOM2_PARAM_TAU; e++) {
                v_t[e][j] = field_ext_vect_mult(A_hat_row, v_x[e], j+1);
            }
        }
        /* Generate and add b_hat row */
        ret = ExpandEquations_memopt_update(&EEctx, b_hat_row); ERR(ret, err);
        for(e = 0; e < MQOM2_PARAM_TAU; e++) {
            field_ext_constant_vect_mult(r[e], b_hat_row, tmp, MQOM2_PARAM_MQ_N);
            field_ext_vect_add(v_t[e], tmp, v_t[e], MQOM2_PARAM_MQ_N);
            /* Compute v_{z,i} = P_{z,i}(r) = v_t^T v_x - y_i r^2 */
            v_zi = field_ext_vect_mult(v_t[e], v_x[e], MQOM2_PARAM_MQ_N);
            field_ext_vect_pack(v_zi, v_z[e], i);
        }
    }
    for(e = 0; e < MQOM2_PARAM_TAU; e++) {
        field_ext_elt r2 = field_ext_mult(r[e], r[e]);
        field_ext_constant_vect_mult(r2, y, y_r2, MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU);
        field_ext_vect_add(v_z[e], y_r2, v_z[e], MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU);
    }

    ret = 0;
err:
    return ret;
}



int RecomputePAlpha_memopt(const uint8_t com[MQOM2_PARAM_DIGEST_SIZE], const field_ext_elt alpha1[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)], const uint16_t i_star[MQOM2_PARAM_TAU], const field_ext_elt x_eval[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_N)], const field_ext_elt u_eval[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)], const uint8_t mseed_eq[2 * MQOM2_PARAM_SEED_SIZE], const field_ext_elt y[FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)], field_ext_elt alpha0[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_ETA)])
{
    int ret = -1;
    uint32_t e;

#if MQOM2_PARAM_WITH_STATISTICAL_BATCHING == 1
    uint32_t i;
    field_ext_elt Gamma[MQOM2_PARAM_ETA][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    ret = ExpandBatchingChallenge(com, Gamma); ERR(ret, err);
#else
    (void) com;
#endif

    field_ext_elt v_z[MQOM2_PARAM_TAU][FIELD_EXT_PACKING(MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU)];
    field_ext_elt v_alpha[FIELD_EXT_PACKING(MQOM2_PARAM_ETA)];
    field_ext_elt r[MQOM2_PARAM_TAU];
    for(e = 0; e < MQOM2_PARAM_TAU; e++)
        r[e] = get_evaluation_point(i_star[e]);
    ret = ComputePzEval_xTau(r, x_eval, mseed_eq, y, v_z); ERR(ret, err);
    for(e = 0; e < MQOM2_PARAM_TAU; e++) {
#if MQOM2_PARAM_WITH_STATISTICAL_BATCHING == 1
        for(i=0; i<MQOM2_PARAM_ETA; i++) {
            field_ext_vect_pack(
                field_ext_vect_mult(Gamma[i], v_z[e], MQOM2_PARAM_MQ_M/MQOM2_PARAM_MU),
                v_alpha, i
            );
        }
        field_ext_vect_add(v_alpha, u_eval[e], v_alpha, MQOM2_PARAM_ETA);
        field_ext_constant_vect_mult(r[e], alpha1[e], alpha0[e], MQOM2_PARAM_ETA);
        field_ext_vect_add(v_alpha, alpha0[e], alpha0[e], MQOM2_PARAM_ETA);
#else
        field_ext_vect_add(v_z[e], u_eval[e], v_alpha, MQOM2_PARAM_ETA);
        field_ext_constant_vect_mult(r[e], alpha1[e], alpha0[e], MQOM2_PARAM_ETA);
        field_ext_vect_add(v_alpha, alpha0[e], alpha0[e], MQOM2_PARAM_ETA);
#endif
    }

    ret = 0;
err:
    return ret;
}
