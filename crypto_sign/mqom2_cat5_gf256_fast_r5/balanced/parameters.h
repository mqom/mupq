#ifndef __PARAMETERS_H__
#define __PARAMETERS_H__

#define MQOM2_PARAM_SECURITY 256
#define MQOM2_PARAM_BASE_FIELD 8
#define MQOM2_PARAM_TRADEOFF 0
#define MQOM2_PARAM_NBROUNDS 5

/* Fields conf: ref implementation */
#define FIELDS_REF
/* Rijndael conf: bitslice (actually underlying MUPQ implementation for cat1 with the MQOM2_FOR_MUPQ toggle) */
#define RIJNDAEL_BITSLICE
/* Options activated for memory optimization */
#define MEMORY_EFFICIENT_BLC
#define PIOP_BITSLICE
#define FIELDS_BITSLICE_COMPOSITE
#define FIELDS_BITSLICE_PUBLIC_JUMP
#define GGMTREE_NB_ENC_CTX_IN_MEMORY 0
#define GGMTREE_NB_SIMULTANEOUS_LEAVES_LOG 5
#define BLC_NB_LEAF_SEEDS_IN_PARALLEL 32
#define BLC_SEEDCOMMIT_CACHE
#define BLC_SEEDEXPAND_CACHE
#define NO_EXPANDMQ_PRG_CACHE
#define MEMORY_EFFICIENT_KEYGEN
/* Specifically target MUPQ */
#define MQOM2_FOR_MUPQ

/* Do not mess with sections as the PQM4 framework uses them */
#define NO_EMBEDDED_SRAM_SECTION

#endif /* __PARAMETERS_H__ */
