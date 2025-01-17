#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jim.h>

#include "target.h"
#include "target_type.h"
#include "register.h"
#include "idm51.h"
#include "idm51_once.h"

//idm51_status_t idm51_state;

/** */
static inline int idm51_write_dr(struct target *target, uint8_t * dr_in, uint8_t * dr_out, int dr_len, int execute, int fullsize)
{
	//если нужно переводим все остальные tap в bypass
	int reconfig = 0;
	for (struct jtag_tap *tap = jtag_tap_next_enabled(NULL); tap != NULL; tap = jtag_tap_next_enabled(tap))
	{
		if (tap->bypass)
		{
			if(tap == target->tap)
			{
				reconfig = 1;
				break;
			}
		}
		else
		{
			if(tap != target->tap)
			{
				reconfig = 1;
				break;
			}
		}
	}

	if(reconfig) idm51_jtag_sendinstr(target, 0, DEBUG_INIT, 1);

	struct scan_field field;

	//LOG_INFO("dr_out %lX", *((uint64_t*)dr_out));
	field.num_bits = dr_len;
	field.out_value = dr_out;
	field.in_value = dr_in;

	jtag_add_dr_scan(target->tap,1,&field,TAP_IDLE);

	jtag_execute_queue();
	//if(dr_in) LOG_INFO("dr_in %lX", *((uint64_t*)dr_in));

	return ERROR_OK;
}

int idm51_write_dr_u64(struct target *target, uint64_t * dr_in, uint64_t dr_out, int dr_len, int execute)
{
	return idm51_write_dr(target, (uint8_t *) dr_in, (uint8_t *) &dr_out, dr_len, execute, 0);
}

/* IR and DR functions */
static inline int idm51_write_ir(struct target *target, uint8_t * ir_in, uint8_t * ir_out, int ir_len, int execute)
{
	//jtag_add_plain_ir_scan(tap->ir_length, ir_out, ir_in, TAP_IDLE);

	struct scan_field field;

	field.num_bits = ir_len;
	field.out_value = ir_out;
	field.in_value = ir_in;

	jtag_add_ir_scan_noverify(target->tap,&field,TAP_IDLE);

	if(execute) jtag_execute_queue();

	return ERROR_OK;
}

static inline int idm51_write_ir_u8(struct target *target, uint8_t * ir_in, uint8_t ir_out, int ir_len, int execute)
{
	return idm51_write_ir(target, ir_in, &ir_out, ir_len, execute);
}

int idm51_jtag_sendinstr(struct target *target, uint8_t * ir_in, uint8_t ir_out, int execute)
{
	return idm51_write_ir_u8(target, ir_in, ir_out, target->tap->ir_length, execute);
}

int idm51_write_core_resource(struct target *target, uint64_t cmd, uint64_t type, uint32_t adr, uint8_t * data)
{
	int err = ERROR_OK;
	uint64_t out_data = 0xbad0ull;
	uint64_t in_data = 0;

	if(data)
		in_data = *data;

	err = idm51_write_dr_u64(target, &out_data, (cmd<<28)|(type<<24)|((adr&0xFFFF)<<8)|in_data , DR_IDM51_SIZE, 1);
	if (err != ERROR_OK)
		return err;

	return err;
}

int idm51_read_core_resource(struct target *target, uint64_t cmd, uint32_t * data)
{
	int err = ERROR_OK;
	uint64_t out_data = 0xbad0ull;

	//????????????????????????
	err = idm51_write_dr_u64(target, &out_data, (cmd<<28) , DR_IDM51_SIZE, 0);
	if (err != ERROR_OK)
		return err;

	//LOG_INFO("rr1----data %llX",(long long unsigned int) (((cmd<<34)|(type<<32)|(reg<<26))<<1)|0x1);
	//LOG_INFO("rr1----out_dr %lX", out_data);

	err = idm51_write_dr_u64(target, &out_data, NOP, DR_IDM51_SIZE, 1);
	if (err != ERROR_OK)
		return err;

	//LOG_INFO("rr2----out_dr %lX", out_data);

	//out_data = out_data >> 1;
	*data = (uint32_t)out_data;

	//LOG_INFO("rreg %d:%08X", (int)reg, (uint32_t)out_data);

	return err;
}

int idm51_read_status(struct target *target, uint32_t * data)
{
	int err = idm51_read_core_resource(target, READST, data);
	//struct idm51_common *idm51 = target_to_idm51(target);
	//uint32_t temp_data = *data;

	// if((temp_data >> 15) & 1) target -> state = TARGET_HALTED;
	// if((temp_data >> 14) & 1) target -> state = TARGET_RESET;
	// idm51->is_load_done = (temp_data >> 13) & 1;
	// idm51->is_load_enabled = (temp_data >> 12) & 1;

	// for(int i = 0; i < 8; i++)
	// {
	// 	idm51->breakpoints[i].is_bp_used = (temp_data >> i) & 1;
	// }
	


	return err;
}

int idm51_read_memory_core(struct target *target, uint64_t mem_type, uint32_t address, uint8_t *buffer)
{
	int err = ERROR_OK;
	uint64_t out_data = 0xbad0ull;

	struct idm51_common *idm51 = target_to_idm51(target);
	// if(idm51->core_hangup == 1)
	// {
	// 	*buffer = 0;
	// 	return err;
	// }

	err = idm51_write_dr_u64(target, &out_data, (READDATA<<28)|(mem_type<<24)|((address&0xFFFF)<<8), DR_IDM51_SIZE, 1);
	if (err != ERROR_OK)
		return err;

	LOG_DEBUG("mr1----data %llX", (long long unsigned int)((READDATA<<28)|(mem_type<<24)|((address&0xFFFF)<<8)));
	LOG_DEBUG("mr1----out_dr %lX", out_data);

	err = idm51_write_dr_u64(target, &out_data, (NOP<<28), DR_IDM51_SIZE, 1);
	if (err != ERROR_OK)
		return err;

	LOG_DEBUG("mr2----out_dr %lX", out_data);

	//out_data = out_data >> 1;
	*buffer = (uint8_t)out_data;


	LOG_DEBUG("rmem %08X:%08X", address, *buffer);

	return err;
}

int idm51_write_memory_core(struct target *target, uint64_t mem_type, uint32_t address, const uint8_t *buffer)
{
	int err = ERROR_OK;
	uint64_t out_data = 0xbad0ull;
	uint64_t in_data = *buffer;

	struct idm51_common *idm51 = target_to_idm51(target);
	// if(idm51->core_hangup == 1)// инфа о зависание ядра берется из спец массива
	// 	return err;

	LOG_DEBUG("wmem %08X:%08X", address, *buffer);

	err = idm51_write_dr_u64(target, &out_data,  (WRITEDATA<<28)|(mem_type<<24)|((address&0xFFFF)<<8)|(in_data & 0xFF), DR_IDM51_SIZE, 1);
	if (err != ERROR_OK)
		return err;

	LOG_DEBUG("mw1----data %llX", (long long unsigned int)((WRITEDATA<<28)|(mem_type<<24)|((address&0xFFFF)<<8)|(in_data & 0xFF)));
	LOG_DEBUG("mw1----out_dr %lX", out_data);

	return err;
}

