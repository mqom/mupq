#ifndef __PARAMETERS_H__
#define __PARAMETERS_H__

#define MQOM2_PARAM_SECURITY 192
#define MQOM2_PARAM_BASE_FIELD 8
#define MQOM2_PARAM_TRADEOFF 0
#define MQOM2_PARAM_NBROUNDS 3

/* Fields conf: ref implementation */
#define FIELDS_REF
/* Rijndael conf: bitslice (actually underlying MUPQ implementation for cat1 with the MQOM2_FOR_MUPQ toggle) */
#define RIJNDAEL_BITSLICE
/* Options activated for memory optimization */
#define MEMORY_EFFICIENT_BLC
#define MEMORY_EFFICIENT_PIOP
#define MEMORY_EFFICIENT_KEYGEN
#define USE_ENC_X8
#define USE_XOF_X4

/* Specifically target MUPQ */
#define MQOM2_FOR_MUPQ

/* Do not mess with sections as the PQM4 framework uses them */
#define NO_EMBEDDED_SRAM_SECTION

#endif /* __PARAMETERS_H__ */
