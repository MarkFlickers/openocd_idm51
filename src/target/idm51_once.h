#ifndef idm51_ONCE_H
#define idm51_ONCE_H

#include <jtag/jtag.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//extern idm51_status_t idm51_state;

/** */
int idm51_write_dr_u64(struct target *target, uint64_t *dr_in, uint64_t dr_out, int dr_len, int execute);

/** core read resource */
int idm51_read_core_resource(struct target *target, uint64_t cmd, uint32_t *data);
/** core write resource */
int idm51_write_core_resource(struct target *target, uint64_t cmd, uint64_t type, uint32_t adr, uint8_t * data);

/** core read memory */
int idm51_read_memory_core(struct target *target, uint64_t mem_type, uint32_t address, uint8_t *buffer);
/** core write memory */
int idm51_write_memory_core(struct target *target, uint64_t mem_type, uint32_t address, const uint8_t *buffer);
/** core read status */
int idm51_read_status(struct target *target, uint32_t *data);

#endif /* idm51_ONCE_H */
