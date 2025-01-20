
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jim.h>

#include "target.h"
#include "breakpoints.h"
#include "target_type.h"
#include "algorithm.h"
#include "register.h"
#include "idm51.h"
#include "idm51_once.h"

static const struct
{
	unsigned id;
	const char *name;
	unsigned bits;
	uint32_t eame;
} idm51_regs[] = {
	{PC_REGNUM, "pc", 16, 0x00000000}
	/* {E_R0_REGNUM,  "r0",  32, 0x00000000},
	{E_R1_REGNUM,  "r1",  32, 0x00000001},
	{E_R2_REGNUM,  "r2",  32, 0x00000002},
	{E_R3_REGNUM,  "r3",  32, 0x00000003},
	{E_R4_REGNUM,  "r4",  32, 0x00000004},
	{E_R5_REGNUM,  "r5",  32, 0x00000005},
	{E_R6_REGNUM,  "r6",  32, 0x00000006},
	{E_R7_REGNUM,  "r7",  32, 0x00000007},
	{E_R8_REGNUM,  "r8",  32, 0x00000008},
	{E_R9_REGNUM,  "r9",  32, 0x00000009},
	{E_R10_REGNUM, "r10", 32, 0x0000000a},
	{E_R11_REGNUM, "r11", 32, 0x0000000b},
	{E_R12_REGNUM, "r12", 32, 0x0000000c},
	{E_R13_REGNUM, "r13", 32, 0x0000000d},
	{E_R14_REGNUM, "r14", 32, 0x0000000e},
	{E_R15_REGNUM, "r15", 32, 0x0000000f},
	{E_R16_REGNUM, "r16", 32, 0x00000010},
	{E_R17_REGNUM, "r17", 32, 0x00000011},
	{E_R18_REGNUM, "r18", 32, 0x00000012},
	{E_R19_REGNUM, "r19", 32, 0x00000013},
	{E_R20_REGNUM, "r20", 32, 0x00000014},
	{E_R21_REGNUM, "r21", 32, 0x00000015},
	{E_R22_REGNUM, "r22", 32, 0x00000016},
	{E_R23_REGNUM, "r23", 32, 0x00000017},
	{E_R24_REGNUM, "r24", 32, 0x00000018},
	{E_R25_REGNUM, "r25", 32, 0x00000019},
	{E_R26_REGNUM, "r26", 32, 0x0000001a},
	{E_R27_REGNUM, "r27", 32, 0x0000001b},
	{E_R28_REGNUM, "r28", 32, 0x0000001c},
	{E_R29_REGNUM, "r29", 32, 0x0000001d},
	{E_R30_REGNUM, "r30", 32, 0x0000001e},
	{E_R31_REGNUM, "r31", 32, 0x0000001f},
	{E_S0_REGNUM,  "s0",  32, 0x00000020},
	{E_S1_REGNUM,  "s1",  32, 0x00000021},
	{E_S2_REGNUM,  "s2",  32, 0x00000022},
	{E_S3_REGNUM,  "s3",  32, 0x00000023},
	{E_S4_REGNUM,  "s4",  32, 0x00000024},
	{E_S5_REGNUM,  "s5",  32, 0x00000025},
	{E_S6_REGNUM,  "s6",  32, 0x00000026},
	{E_S7_REGNUM,  "s7",  32, 0x00000027},
	{E_S8_REGNUM,  "s8",  32, 0x00000028},
	{E_S9_REGNUM,  "s9",  32, 0x00000029},
	{E_S10_REGNUM, "s10", 32, 0x0000002a},
	{E_S11_REGNUM, "s11", 32, 0x0000002b},
	{E_S12_REGNUM, "s12", 32, 0x0000002c},
	{E_S13_REGNUM, "s13", 32, 0x0000002d}, */

	//{E_FINAL,   "", 32, 0xffffffff}
};

int idm51_print_status(struct target *target);

static int idm51_read_register(struct target *target, int num, int force);
static int idm51_write_register(struct target *target, int num, int force);

static int idm51_debug_read_register(struct target *target, unsigned num, uint32_t *data);
// static int idm51_debug_write_register(struct target *target, unsigned num, uint32_t data);

static int idm51_read_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, uint8_t *buffer);

int idm51_print_status(struct target *target)
{
	char Core_Status_String[256] = "status:";
	char Trigg_String[256] = "active triggers:";
	// uint8_t first = 1;

	uint32_t status_reg;
	int err = ERROR_OK;

	struct idm51_common *idm51 = target_to_idm51(target);
	err = idm51_read_status(target, &status_reg);

	if (err != ERROR_OK)
		return err;

	if ((status_reg >> 15) & 1)
		snprintf(Core_Status_String, sizeof(Core_Status_String), "%s %s", Core_Status_String, "Halted");
	else
		snprintf(Core_Status_String, sizeof(Core_Status_String), "%s %s", Core_Status_String, "Running");
	if ((status_reg >> 14) & 1)
		snprintf(Core_Status_String, sizeof(Core_Status_String), "%s, %s", Core_Status_String, "In Reset");
	if (idm51->is_load_enabled)
		snprintf(Core_Status_String, sizeof(Core_Status_String), "%s, %s", Core_Status_String, "SPI Load Enabled");
	if (idm51->is_load_done)
		snprintf(Core_Status_String, sizeof(Core_Status_String), "%s, %s", Core_Status_String, "Load Done");

	for (int i = 0; i < 8; i++)
	{
		// if(idm51->breakpoints[i].is_bp_used)
		if (status_reg & (1 << i))
		{
			snprintf(Trigg_String, sizeof(Trigg_String), "%s %d,", Trigg_String, i);
		}
	}
	if (status_reg & BP_ARE_USED)
		Trigg_String[strlen(Trigg_String) - 1] = '\0';

	LOG_INFO("%s", Core_Status_String);
	LOG_INFO("%s", Trigg_String);

	return err;
}

static int idm51_get_gdb_reg_list(struct target *target,
								  struct reg **reg_list[],
								  int *reg_list_size,
								  enum target_register_class reg_class)
{
	int i;
	struct idm51_common *idm51 = target_to_idm51(target);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	*reg_list_size = idm51->idm51_num_regs;
	*reg_list = malloc(sizeof(struct reg *) * (idm51->idm51_num_regs));

	if (!*reg_list)
		return ERROR_COMMAND_SYNTAX_ERROR;

	for (i = 0; i < idm51->idm51_num_regs; i++)
		(*reg_list)[i] = &idm51->core_cache->reg_list[i];

	return ERROR_OK;
}

static int idm51_read_core_reg(struct target *target, int num)
{
	uint32_t reg_value;
	struct idm51_common *idm51 = target_to_idm51(target);

	if ((num < 0) || (num >= (MAX_REGS)))
		return ERROR_COMMAND_SYNTAX_ERROR;

	reg_value = idm51->core_regs[num];
	buf_set_u32(idm51->core_cache->reg_list[num].value, 0, 32, reg_value);
	idm51->core_cache->reg_list[num].valid = 1;
	idm51->core_cache->reg_list[num].dirty = 0;

	return ERROR_OK;
}

static int idm51_write_core_reg(struct target *target, int num)
{
	uint32_t reg_value;
	struct idm51_common *idm51 = target_to_idm51(target);

	if ((num < 0) || (num >= (MAX_REGS)))
		return ERROR_COMMAND_SYNTAX_ERROR;

	reg_value = buf_get_u32(idm51->core_cache->reg_list[num].value, 0, 32);
	idm51->core_regs[num] = reg_value;
	idm51->core_cache->reg_list[num].valid = 1;
	idm51->core_cache->reg_list[num].dirty = 0;

	return ERROR_OK;
}

static int idm51_get_core_reg(struct reg *reg)
{
	struct idm51_core_reg *idm51_reg = reg->arch_info;
	struct target *target = idm51_reg->target;
	struct idm51_common *idm51 = target_to_idm51(target);

	LOG_DEBUG("%s", __func__);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	return idm51->read_core_reg(target, idm51_reg->num);
}

static int idm51_set_core_reg(struct reg *reg, uint8_t *buf)
{
	LOG_DEBUG("%s", __func__);

	struct idm51_core_reg *idm51_reg = reg->arch_info;
	struct target *target = idm51_reg->target;
	uint32_t value = buf_get_u32(buf, 0, 32);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	buf_set_u32(reg->value, 0, reg->size, value);
	reg->dirty = 1;
	reg->valid = 1;

	return ERROR_OK;
}

static const struct reg_arch_type idm51_reg_type = {
	.get = idm51_get_core_reg,
	.set = idm51_set_core_reg,
};

static void idm51_build_reg_cache(struct target *target)
{
	struct idm51_common *idm51 = target_to_idm51(target);

	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(MAX_REGS, sizeof(struct reg));
	struct idm51_core_reg *arch_info = malloc(
		sizeof(struct idm51_core_reg) * (MAX_REGS));
	int i;

	/* Build the process context cache */
	/* Max numregs configuration */
	cache->name = "idm51 registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = idm51->idm51_num_regs;
	(*cache_p) = cache;
	idm51->core_cache = cache;

	for (i = 0; i < MAX_REGS; i++)
	{
		arch_info[i].num = idm51_regs[i].id;
		arch_info[i].name = idm51_regs[i].name;
		arch_info[i].size = idm51_regs[i].bits;
		arch_info[i].eame = idm51_regs[i].eame;
		arch_info[i].target = target;
		arch_info[i].idm51_common = idm51;

		reg_list[i].name = idm51_regs[i].name;
		reg_list[i].size = idm51_regs[i].bits; // 32
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
		reg_list[i].exist = 1;
		reg_list[i].type = &idm51_reg_type;
		reg_list[i].arch_info = &arch_info[i];
	}
}

static int idm51_reg_read(struct target *target, uint32_t eame, uint32_t *data)
{
	// PC
	int err = ERROR_OK;
	if (eame == idm51_regs[PC_REGNUM].eame)
	{
		struct idm51_common *idm51 = target_to_idm51(target);
		err = idm51_read_core_resource(target, READPRCNT, data);
		if (err != ERROR_OK)
		{
			*data = NO_ADDRESS;
			idm51->triggered_pc = NO_ADDRESS;
		}
		else
			idm51->triggered_pc = *data - 1;
		// if(	idm51->triggered_pc != NONE_ADR)
		// 	*data = idm51->triggered_pc;
		// else
		// 	err = idm51_read_core_resource(target, READPRCNT, data);
	}
	else
	{
		*data = 0;
	}

	return err;
}

static int idm51_reg_write(struct target *target, uint32_t eame, uint32_t data)
{
	return ERROR_OK;
}

static int idm51_read_register(struct target *target, int num, int force)
{
	int err = ERROR_OK;
	uint32_t data = 0;
	struct idm51_common *idm51 = target_to_idm51(target);
	struct idm51_core_reg *arch_info;

	if (force)
		idm51->core_cache->reg_list[num].valid = false;

	if (!idm51->core_cache->reg_list[num].valid)
	{
		arch_info = idm51->core_cache->reg_list[num].arch_info;

		err = idm51_reg_read(target, arch_info->eame, &data);
		if (err == ERROR_OK)
		{
			idm51->core_regs[num] = data;
			idm51->read_core_reg(target, num);
		}

		// switch (arch_info->num)
		// {
		// 	default:
		// 		err = idm51_reg_read(target, arch_info->eame, &data);
		// 		if (err == ERROR_OK)
		// 		{
		// 			idm51->core_regs[num] = data;
		// 			idm51->read_core_reg(target, num);
		// 		}
		// 		break;
		// }
	}

	return err;
}

static int idm51_write_register(struct target *target, int num, int force)
{
	int err = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);
	struct idm51_core_reg *arch_info;

	if (force)
		idm51->core_cache->reg_list[num].dirty = 1;

	if (idm51->core_cache->reg_list[num].dirty)
	{
		arch_info = idm51->core_cache->reg_list[num].arch_info;

		idm51->write_core_reg(target, num);
		err = idm51_reg_write(target, arch_info->eame, idm51->core_regs[num]);
	}

	return err;
}

static int idm51_debug_read_register(struct target *target, unsigned num, uint32_t *data)
{
	int err = ERROR_OK, i;

	for (i = 0;; i++)
	{
		if (idm51_regs[i].id == num)
			break;
		if (idm51_regs[i].id == FINAL)
			break;
	}

	if ((idm51_regs[i].id == FINAL))
	{
		LOG_ERROR("Error, no reg %d in idm51_regs[]", num);
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	err = idm51_reg_read(target, idm51_regs[i].eame, data);

	return err;
}

// static int idm51_debug_write_register(struct target *target, unsigned num, uint32_t data)
//{
//	int err = ERROR_OK,i;
//
//	for (i = 0; ; i++)
//	{
//		if (idm51_regs[i].id == num) break ;
//		if (idm51_regs[i].id == E_FINAL) break ;
//	}
//
//	if((idm51_regs[i].id == E_FINAL))
//	{
//		LOG_ERROR("Error, no reg %d in idm51_regs[]", num);
//		return ERROR_COMMAND_SYNTAX_ERROR;
//	}
//
//	err = idm51_reg_write(target, idm51_regs[i].eame, data);
//
//	return err;
// }

static int idm51_save_context(struct target *target)
{
	int err = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);

	for (int i = 0; i < idm51->idm51_num_regs; i++)
	{
		err = idm51_read_register(target, i, true);
		if (err != ERROR_OK)
			break;
	}

	return err;
}

static int idm51_restore_context(struct target *target, int force)
{
	int i, err = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);

	idm51->triggered_pc = NONE_ADR;

	for (i = 0; i < idm51->idm51_num_regs; i++)
	{
		err = idm51_write_register(target, i, force);
		if (err != ERROR_OK)
			break;
	}

	return err;
}

static int idm51_init_arch_info(struct target *target, struct idm51_common *idm51)
{
	target->arch_info = idm51;

	idm51->jtag_info.tap = target->tap;
	idm51->idm51_num_regs = IDM51_NUM_REGS;

	idm51->imemstart = MEM_IMEMX_ADDR;
	idm51->imemend = MEM_IMEMX_ADDR + MEM_IMEMX_SIZE - 1;
	idm51->dmemxstart = MEM_DMEMX_ADDR;
	idm51->dmemxend = MEM_DMEMX_ADDR + MEM_DMEMX_SIZE - 1;
	idm51->dmemstart = MEM_DMEM_ADDR;
	idm51->dmemend = MEM_DMEM_ADDR + MEM_DMEM_SIZE - 1;

	idm51->bp_scanned = false;
	idm51->breakpoints = NULL;

	idm51->ext_flash.is_identified = false;
	idm51->ext_flash.manufacturer_id = 0;
	idm51->ext_flash.manufacturer = "?unknown?";
	idm51->ext_flash.part_num = calloc(20, sizeof(char));

	idm51->ext_flash.mem_type = 0;
	idm51->ext_flash.capactiy = 0;

	idm51->ext_flash.status_reg = 0xFF;

	idm51->ext_flash.bytes_erased = 0;

	// idm51->spi_load_en = true;
	idm51->is_load_done = false;
	idm51->is_load_enabled = false;

	idm51->read_core_reg = idm51_read_core_reg;
	idm51->write_core_reg = idm51_write_core_reg;

	return ERROR_OK;
}

static int idm51_configure_break_unit(struct target *target)
{
	struct idm51_common *idm51 = target_to_idm51(target);

	if (idm51->bp_scanned)
		return ERROR_OK;

	idm51->num_hw_bpoints = BPOINTS_AMOUNT;
	idm51->num_hw_wpoints = BPOINTS_AMOUNT - INSTRUCTION_BPOINTS_AMOUNT;
	idm51->num_hw_bpoints_avail = idm51->num_hw_bpoints;
	idm51->num_hw_wpoints_avail = idm51->num_hw_wpoints;

	idm51->breakpoints = calloc(idm51->num_hw_bpoints, sizeof(struct idm51_comparator));

	for (int i = 0; i < BPOINTS_AMOUNT; i++)
	{
		idm51->breakpoints[i].bp_number = i;
	}

	idm51->bp_scanned = true;
	idm51->triggered_pc = NONE_ADR;

	return ERROR_OK;
}

static int idm51_target_create(struct target *target, Jim_Interp *interp)
{
	LOG_INFO("target->coreid - %X", target->coreid);

	struct idm51_common *idm51 = calloc(1, sizeof(struct idm51_common));

	if (!idm51)
		return ERROR_COMMAND_SYNTAX_ERROR;

	idm51_init_arch_info(target, idm51);
	idm51_configure_break_unit(target);

	// memset(idm51->idm51_breakpoints.Is_BP_Active, 0, BPOINTS_AMOUNT * sizeof(idm51->idm51_breakpoints.Is_BP_Active[0]));
	// memset(idm51->idm51_breakpoints.BP_Address, 0, BPOINTS_AMOUNT * sizeof(idm51->idm51_breakpoints.BP_Address[0]));

	// idm51->bp_activ_map = 0;
	// idm51->bp_pc_num = 6;
	// idm51->triggered_pc = NONE_ADR;

	// idm51->DEBUG_REQUEST = false;
	// idm51->spi_load_en = true;

	return ERROR_OK;
}

static int idm51_examine_debug_reason(struct target *target)
{
	int err = ERROR_OK;
	uint32_t status_reg = 0;
	uint32_t current_pc = NONE_ADR;
	struct idm51_common *idm51 = target_to_idm51(target);

	//*_data = 0;
	err = idm51_debug_read_register(target, PC_REGNUM, &current_pc);
	if (err != ERROR_OK)
		return err;
	idm51->triggered_pc = current_pc - 1; // Locate last executed instruction

	err = idm51_read_status(target, &status_reg);
	// if (err != ERROR_OK)
	//	return err;

	if ((target->debug_reason != DBG_REASON_DBGRQ) && (target->debug_reason != DBG_REASON_SINGLESTEP))
	{
		if (err != ERROR_OK)
			return err;

		if (status_reg & STATE_IN_RESET)
			/* halted on reset */
			target->debug_reason = DBG_REASON_UNDEFINED;

		else if (status_reg & BP_ARE_USED)
		{
			/* we have halted on a breakpoint */
			for (int i = 0; i < INSTRUCTION_BPOINTS_AMOUNT; i++)
			{
				if (idm51->breakpoints[i].bp_value == idm51->triggered_pc)
				{
					target->debug_reason = DBG_REASON_BREAKPOINT;
					break;
				}
			}
		}
		else
			target->debug_reason = DBG_REASON_UNDEFINED;
	}

	return ERROR_OK;

	// for(unsigned int i = 0; i < INSTRUCTION_BPOINTS_AMOUNT; i++)
	// {
	// 	if(idm51->breakpoints[i].is_bp_used)
	// 	{
	// 		if(idm51->triggered_pc == idm51->breakpoints[i].bp_value){
	// 			*_data = 1;
	// 			target->debug_reason = DBG_REASON_BREAKPOINT;
	// 			break;
	// 		}
	// 	}
	// }

	// for(unsigned int i = 0; i < idm51->bp_pc_num; i++)
	// {
	// 	if(((idm51->bp_activ_map & data) & (1<<i)) != 0)
	// 	{
	// 		idm51->triggered_pc = idm51->bp_adr[i];
	// 		*_data = 1;
	// 		break;
	// 	}
	// }

	// return err;
}

static int idm51_core_reset(struct target *target, uint64_t _sig)
{
	int err = ERROR_OK;

	if (_sig == 0)
	{
		err = idm51_write_core_resource(target, RST_OFF, 0, 0, NULL);
		if (err != ERROR_OK)
			return err;
	}
	else
	{
		err = idm51_write_core_resource(target, RST_ON, 0, 0, NULL);
		if (err != ERROR_OK)
			return err;
	}

	LOG_INFO("%s", "Core Reset task");
	err = idm51_print_status(target);

	return err;
}

static int idm51_core_step(struct target *target)
{
	int err = ERROR_OK;

	err = idm51_write_core_resource(target, STEP, 0, 0, NULL);
	if (err != ERROR_OK)
		return err;

	LOG_INFO("%s", "Core Step task");
	// err = idm51_print_status(target);

	return err;
}

static int idm51_core_halt(struct target *target)
{
	int err = ERROR_OK;

	err = idm51_write_core_resource(target, HALT, 0, 0, NULL);
	if (err != ERROR_OK)
		return err;

	LOG_INFO("%s", "Core Halt task");
	err = idm51_print_status(target);

	return err;
}

static int idm51_core_resume(struct target *target)
{
	int err = ERROR_OK;

	err = idm51_write_core_resource(target, RUN, 0, 0, NULL);
	if (err != ERROR_OK)
		return err;

	uint32_t out_reg;
	err = idm51_read_status(target, &out_reg);
	LOG_INFO("%s", "Core Resume task");
	err = idm51_print_status(target);

	return err;
}

static int idm51_debug_entry(struct target *target)
{
	int err = ERROR_OK;
	// int midres = STATE_RUN;
	// uint32_t data = 0, data1 = 0;
	//	uint64_t out_data;
	// LOG_DEBUG("%s", __func__);

	struct idm51_common *idm51 = target_to_idm51(target);

	idm51_save_context(target);

	idm51_examine_debug_reason(target);

	LOG_DEBUG("entered debug state at PC #%" PRIx32 ", target->state: %s",
			  buf_get_u32(idm51->core_cache->reg_list[IDM51_PC].value, 0, 32),
			  target_state_name(target));

	return ERROR_OK;
	// err = idm51_core_halt(target);
	// if (err != ERROR_OK)
	// 	return err;

	// err = idm51_read_status(target, &data);
	// if (err != ERROR_OK)
	// 	return err;

	// LOG_INFO("DBI_STAT %08x(%d)",data, target->coreid);

	// if HALT
	// 	if ((data & Status_MC_in_debug_mode) == Status_MC_in_debug_mode) //Status_MC_in_debug_mode_out
	// 	{
	// 		//LOG_INFO("%s","halt" );
	// 		midres = midres | STATE_HALT;
	// 	}
	// 	else
	// 	{
	// 		LOG_INFO("%s","hangup");
	// 		// не вышли в режим отладки
	// 		midres = midres | STATE_HANGUP;

	// 		//idm51->core_hangup = 1;

	// //		err = idm51_read_memory_core(target, DATA_MEM, 0x2000, &data);

	// 		*res = midres;
	// 		return err;
	// 	}

	// 	//idm51->core_hangup = 0;

	// 	//if breakpoint
	// 	err = idm51_examine_debug_reason(target, &data);
	// 	if (err != ERROR_OK)
	// 		return err;

	// 	/* if (data & 0x1)
	// 	{
	// 		idm51_debug_read_register(target, PC_REGNUM, &data1);
	// 		LOG_INFO("breakpoint - %04X", data1);

	// 		uint32_t out_reg;
	// 		err = idm51_read_status(target, &out_reg);
	// 		//LOG_INFO("bpstatr----out_dr %X", out_reg);

	// 		// halt core
	// 		err = idm51_core_halt(target);
	// 		if (err != ERROR_OK)
	// 			return err;

	// 		midres = midres | STATE_BREAKPOINT;
	// 	}*/

	// 	*res = midres;
	// 	return err;
}

// static int idm51_is_target_stop_by_event(struct target *target) // Ещё одна бездарная функция
// {
// 	uint32_t data = 0;
// //	uint64_t out_data;
// 	struct idm51_common *idm51 = target_to_idm51(target);
// 	struct idm51_tap_common *idm51_tap = target_to_idm51_tap(target);
// 	//LOG_INFO("%s(%d)", __func__, target->coreid);

// 	if(target == NULL) return 0;

// 	idm51_read_status(target, &data);
// 	if ((data & Status_MC_in_debug_mode) == Status_MC_in_debug_mode) //Status_MC_in_debug_mode_out
// 	{
// 		//idm51->core_hangup = 0;

// 		//if breakpoint
// 		idm51_examine_debug_reason(target, &data);
// 		if (data & 0x1)
// 		{
// 			return idm51_tap->core_smp_num;
// 		}

// 		//run
// 		return 0;
// 	}

// 	//run
// 	return 0;
// }

// static int idm51_test_debugstate(struct target *target, int *res, bool _step)	//  Ещё одна бездарная функция
// {
// 	int err = ERROR_FAIL;
// 	uint32_t status_reg = 0;
// 	struct idm51_common *idm51 = target_to_idm51(target);
// 	struct idm51_tap_common *idm51_tap = target_to_idm51_tap(target);

// 	err = idm51_read_status(target, &status_reg);

// 	if((target->state == TARGET_HALTED) && (!_step))
// 	{
// 		*res = 	STATE_HALT;
// 		return ERROR_OK;
// 	}

// 	// if(idm51->DEBUG_REQUEST || _step || (target->state == TARGET_RESET))
// 	// {
// 	// 	idm51->DEBUG_REQUEST = false;
// 	// }
// 	//else
// 	{
// 		int stop_count = 0;

// 		stop_count =  idm51_is_target_stop_by_event(target);//CRISCS

// 		//LOG_INFO("stop_count = %d(by_event)",stop_count);

// 		if(stop_count < idm51_tap->core_smp_num)//если не сложидись условия для глобального останова
// 		{
// 			*res = STATE_RUN;
// 			return ERROR_OK;
// 		}
// 	}

// 	//identify stop reason
// 	err = idm51_debug_entry(target,res);//CRISCS
// 	if (err != ERROR_OK)
// 		return err;

// 	return err;
// }

static int idm51_init_target(struct command_context *cmd_ctx, struct target *target)
{
	int err = ERROR_OK;
	LOG_INFO("%s", __func__);

	// struct idm51_common *idm51 = target_to_idm51(target);

	// idm51->core_hangup = 0;

	// idm51->idm51_num_regs = IDM51_NUM_REGS;

	// memset(idm51->idm51_breakpoints.Is_BP_Active, 0, BPOINTS_AMOUNT * sizeof(idm51->idm51_breakpoints.Is_BP_Active[0]));
	// memset(idm51->idm51_breakpoints.BP_Address, 0, BPOINTS_AMOUNT * sizeof(idm51->idm51_breakpoints.BP_Address[0]));

	// idm51->bp_activ_map = 0;
	// idm51->bp_pc_num = 6;
	// idm51->triggered_pc = NONE_ADR;

	// idm51->DEBUG_REQUEST = false;
	// idm51->spi_load_en = true;

	idm51_build_reg_cache(target);

	return err;
}

static int idm51_examine(struct target *target)
{
	// uint64_t out_data = 0xbad0ull;
	// uint32_t out_reg = 0xbad0;

	LOG_INFO("%s", __func__);

	struct idm51_common *idm51 = target_to_idm51(target);
	// LOG_INFO("target %X target->coreid - %X",target->target_number, target->coreid);

	//	uint32_t chip;

	if (target->tap->has_idcode == false)
	{
		LOG_ERROR("no IDCODE present on device");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	if (!target_was_examined(target))
	{
		target_set_examined(target);

		if (target->tap->idcode == TAPID_IDM51)
		{
			// idm51
			if (target->tap->priv == NULL)
			{
				struct idm51_tap_common *idm51_tap = calloc(1, sizeof(struct idm51_tap_common));
				idm51_tap->core_smp_num = 1;

				target->tap->priv = idm51_tap;
			}
			else
			{
				LOG_ERROR("Too many targets for IDM51 tap");
				return ERROR_COMMAND_SYNTAX_ERROR;
			}
		}
		else
		{
			LOG_ERROR("Not valid tap IDCODE");
			return ERROR_COMMAND_SYNTAX_ERROR;
		}

		// idm51->DEBUG_REQUEST = true;
		idm51->idm51_num_regs = IDM51_NUM_REGS;

		uint8_t ir_in = 0;
		int err = idm51_jtag_sendinstr(target, &ir_in, DEBUG_INIT, 1);
		if (err != ERROR_OK)
			return err;

		// LOG_INFO("examine halt");

		LOG_INFO("%s", "Core Examine task");
		err = idm51_print_status(target);

		// halt
		err = idm51_core_halt(target);
		if (err != ERROR_OK)
			return err;
	}

	return ERROR_OK;
}

static int idm51_arch_state(struct target *target)
{
	struct idm51_common *idm51 = target_to_idm51(target);

	LOG_USER("target halted due to %s, pc: 0x%8.8" PRIx32 "",
			 debug_reason_name(target),
			 buf_get_u32(idm51->core_cache->reg_list[IDM51_PC].value, 0, 32));

	// LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

// static int idm51_debug_init(struct target *target)	// Ещё одна бездарная функция
// {
// 	int err;
// 	//LOG_INFO("%s", __func__);

// 	err = idm51_save_context(target);
// 	if (err != ERROR_OK)
// 		return err;

// 	return ERROR_OK;
// }

static int idm51_poll(struct target *target)
{
	// LOG_DEBUG("%s", __func__);
	// LOG_INFO("idm51_poll target->coreid - %X", target->coreid);
	// LOG_INFO("%s", __func__);

	int err;
	// int result = 0;
	uint32_t status_reg = 0;

	struct idm51_common *idm51 = target_to_idm51(target);

	err = idm51_read_status(target, &status_reg);
	if (err != ERROR_OK)
	{
		LOG_DEBUG("idm51_read_status failed. Err = %d", err);
		return err;
	}
	// if debug state -------------
	// err = idm51_test_debugstate(target,&result,false);
	// if (err != ERROR_OK)
	//	return err;

	// LOG_INFO("result - %d (%d)", result, target->coreid);

	if (status_reg & STATE_HALTED)
	{
		if (target->state != TARGET_HALTED)
		{
			if (target->state == TARGET_UNKNOWN)
				LOG_DEBUG("idm51 already halted during server startup");

			err = idm51_debug_entry(target);
			if (err != ERROR_OK)
			{
				LOG_DEBUG("idm51_debug_entry failed. Err = %d", err);
				return err;
			}

			if (target->state == TARGET_DEBUG_RUNNING)
			{
				target->state = TARGET_HALTED;
				target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
			}
			else
			{
				target->state = TARGET_HALTED;
				target_call_event_callbacks(target, TARGET_EVENT_HALTED);
			}
		}
	}
	else
		target->state = TARGET_RUNNING;

	return ERROR_OK;
}
// 	if (result != STATE_RUN)
// 	{
// 		if (target->state != TARGET_HALTED)
// 		{

// 			target->state = TARGET_HALTED;

// 			register_cache_invalidate(idm51->core_cache);
// 			err = idm51_debug_init(target);
// 			if (err != ERROR_OK)
// 				return err;

// 			// if breakpoint ----------------
// 			if (result & STATE_BREAKPOINT)
// 			{
// 				target->debug_reason = DBG_REASON_BREAKPOINT;
// 			}
// 			else
// 			{
// 				target->debug_reason = DBG_REASON_DBGRQ;
// 			}

// 			target_call_event_callbacks(target, TARGET_EVENT_HALTED);

// 			LOG_INFO("poll halted: PC: 0x%08X (%d)", idm51->core_regs[PC_REGNUM], target->coreid);

// 			err = idm51_print_status(target);
// 		}
// 	}

// 	return ERROR_OK;
// }

static int idm51_halt(struct target *target)
{
	int err;

	LOG_DEBUG("%s", __func__);

	if (target->state == TARGET_HALTED)
	{
		LOG_DEBUG("target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("target was in unknown state when halt was requested");

	// стоп на всех
	err = idm51_core_halt(target);
	if (err != ERROR_OK)
		return err;

	struct idm51_common *idm51 = target_to_idm51(target);
	// idm51->DEBUG_REQUEST = true;
	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int idm51_resume(struct target *target,
						int current,
						target_addr_t address,
						int handle_breakpoints,
						int debug_execution)
{
	int err;
	struct idm51_common *idm51 = target_to_idm51(target);
	struct breakpoint *breakpoint = NULL;
	uint32_t resume_pc;

	LOG_DEBUG("%s %08X %08X", __func__, current, (unsigned)address);

	if (target->state != TARGET_HALTED)
	{
		LOG_TARGET_ERROR(target, "not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* current = 1: continue on current pc,
	   otherwise continue at <address> */
	if (!current)
	{
		buf_set_u32(idm51->core_cache->reg_list[IDM51_PC].value,
					0, 32, address);
		idm51->core_cache->reg_list[IDM51_PC].dirty = true;
		idm51->core_cache->reg_list[IDM51_PC].valid = true;
	}

	if (!current)
		resume_pc = address;
	else
		resume_pc = buf_get_u32(
			idm51->core_cache->reg_list[IDM51_PC].value,
			0, 32);

	err = idm51_restore_context(target, 0);
	if (err != ERROR_OK)
		return err;

	LOG_INFO("resume ");

	err = idm51_core_resume(target);
	if (err != ERROR_OK)
		return err;

	target->debug_reason = DBG_REASON_NOTHALTED;

	register_cache_invalidate(idm51->core_cache);

	/* the front-end may request us not to handle breakpoints */
	// if (handle_breakpoints) {
	// 	/* Single step past breakpoint at current address */
	// 	breakpoint = breakpoint_find(target, resume_pc);
	// 	if (breakpoint) {
	// 		LOG_DEBUG("unset breakpoint at " TARGET_ADDR_FMT,
	// 				breakpoint->address);
	// 		idm51_unset_breakpoint(target, breakpoint);
	// 		idm51_single_step_core(target);
	// 		idm51_set_breakpoint(target, breakpoint);
	// 	}
	// }
	// idm51->DEBUG_REQUEST = false;

	if (!debug_execution)
	{
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("target resumed at 0x%" PRIx32 "", resume_pc);
	}
	else
	{
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("target debug resumed at 0x%" PRIx32 "", resume_pc);
	}

	return ERROR_OK;
}

// static int idm51_step_ex(struct target *target,
// 	int current,
// 	uint32_t address,
// 	int handle_breakpoints,
// 	int steps)
// {
// 	int err;
// 	int result;
// 	struct idm51_common *idm51 = target_to_idm51(target);

// 	if (target->state != TARGET_HALTED) {
// 		LOG_DEBUG("target was not halted");
// 		return ERROR_OK;
// 	}

// 	LOG_DEBUG("%s %08X %08X", __func__, current, (unsigned) address);

// 	err = idm51_restore_context(target, 0);
// 	if (err != ERROR_OK)
// 		return err;
// 	register_cache_invalidate(idm51->core_cache);

// 	//LOG_INFO("synchronous step on all matrix cores(%d)",target->coreid);

// 	err = idm51_core_step(target);
// 	if (err != ERROR_OK)
// 		return err;

// 	jtag_sleep(300);

// 	LOG_INFO("step");

// 	// err = idm51_core_halt(target);
// 	// if (err != ERROR_OK)
// 	// 	return err;

// 	// err = idm51_test_debugstate(target,&result,true);
// 	// if (err != ERROR_OK)
// 	// 	return err;

// 	// err = idm51_debug_init(target);
// 	// if (err != ERROR_OK)
// 	// 	return err;

// 	return ERROR_OK;
// }

static int idm51_step(struct target *target,
					  int current,
					  target_addr_t address,
					  int handle_breakpoints)
{
	LOG_DEBUG("%s", __func__);

	int err;
	struct idm51_common *idm51 = target_to_idm51(target);
	struct breakpoint *breakpoint = NULL;

	if (target->state != TARGET_HALTED)
	{
		LOG_TARGET_ERROR(target, "not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// LOG_DEBUG("%s %08X %08X", __func__, current, (unsigned) address);

	err = idm51_restore_context(target, 0);
	if (err != ERROR_OK)
		return err;

	target->debug_reason = DBG_REASON_SINGLESTEP;

	target_call_event_callbacks(target, TARGET_EVENT_STEP_START);

	// LOG_INFO("synchronous step on all matrix cores(%d)",target->coreid);

	err = idm51_core_step(target);
	if (err != ERROR_OK)
		return err;

	// jtag_sleep(300);

	// LOG_INFO("step");

	// err = idm51_core_halt(target);
	// if (err != ERROR_OK)
	// 	return err;

	// err = idm51_test_debugstate(target,&result,true);
	// if (err != ERROR_OK)
	// 	return err;

	// err = idm51_debug_init(target);
	// if (err != ERROR_OK)
	// 	return err;

	// err = idm51_step_ex(target, current, address, handle_breakpoints, 0);
	// if (err != ERROR_OK)
	// 	return err;

	/* the front-end may request us not to handle breakpoints */
	// if (handle_breakpoints) {
	// 	breakpoint = breakpoint_find(target,
	// 			buf_get_u32(idm51->core_cache->reg_list[IDM51_PC].value, 0, 32));
	// 	if (breakpoint)
	// 		idm51_remove_breakpoint(target, breakpoint);
	// }

	register_cache_invalidate(idm51->core_cache);

	// LOG_INFO("step halted: PC: 0x%X", idm51->core_regs[PC_REGNUM]);
	LOG_USER("target stepped, pc: 0x%4.4" PRIx32 "",
			 buf_get_u32(idm51->core_cache->reg_list[IDM51_PC].value, 0, 32));
	LOG_DEBUG("target stepped ");
	idm51_debug_entry(target);

	target_call_event_callbacks(target, TARGET_EVENT_STEP_END);
	// uint32_t out_reg = 0;
	// err = idm51_read_status(target, READ_STATUS, DBI_STAT, &out_reg);
	// LOG_INFO("step stat----out_dr %X", out_reg);

	// read_ports(target);

	// if (breakpoint)
	// 	idm51_add_breakpoint(target, breakpoint);

	// target_call_event_callbacks(target, TARGET_EVENT_HALTED);

	return err;
}

static int idm51_assert_reset(struct target *target)
{
	int err = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);
	uint8_t spi_load_en = ((uint8_t)(idm51->is_load_enabled)) & 1;

	LOG_INFO("%s", __func__);

	// стоп на всех
	err = idm51_core_halt(target);
	if (err != ERROR_OK)
		return err;

	// RESETON
	LOG_INFO("%s", "Assert Reset task");
	err = idm51_write_core_resource(target, RST_ON, 0, 0, &spi_load_en);
	if (err != ERROR_OK)
		return err;

	// jtag_sleep(100);

	idm51->triggered_pc = NONE_ADR;
	/* registers are now invalid */
	register_cache_invalidate(idm51->core_cache);

	target->state = TARGET_RESET;
	target->debug_reason = DBG_REASON_NOTHALTED;
	// target->debug_reason = DBG_REASON_NOTHALTED;

	if (target->reset_halt)
	{
		err = target_halt(target);
		if (err != ERROR_OK)
			return err;
	}

	return ERROR_OK;
}

static int idm51_deassert_reset(struct target *target)
{
	int err;
	// LOG_INFO("%s", __func__);
	LOG_INFO("%s", "Deassert Reset task");
	err = idm51_write_core_resource(target, RST_OFF, 0, 0, NULL);
	if (err != ERROR_OK)
		return err;

	/* The cpu should now be stalled. If halt was requested
	   let poll detect the stall */
	if (target->reset_halt)
		return ERROR_OK;

	/* Instead of going through saving context, polling and
	   then resuming target again just clear stall and proceed. */
	target->state = TARGET_RUNNING;
	return idm51_core_resume(target);

	// err = idm51_poll(target);
	// if (err != ERROR_OK)
	// 	return err;
}

int idm51_read_memory_byte(struct target *target, target_addr_t address, uint8_t *buffer)
{
	int err = ERROR_OK;

	if (address < MEM_DMEMX_ADDR)
	{
		err = idm51_read_memory_core(target, MEM_IMEMX, (uint32_t)address, buffer);
		if (err != ERROR_OK)
			return err;
	}
	else if ((MEM_DMEMX_ADDR <= address) && (address < MEM_DMEM_ADDR))
	{
		err = idm51_read_memory_core(target, MEM_DMEMX, (uint32_t)(address - MEM_DMEMX_ADDR), buffer);
		if (err != ERROR_OK)
			return err;
	}
	else if ((MEM_DMEM_ADDR <= address))
	{
		err = idm51_read_memory_core(target, MEM_DMEM, (uint32_t)(address - MEM_DMEM_ADDR), buffer);
		if (err != ERROR_OK)
			return err;
	}

	return err;
}

static int idm51_read_memory(struct target *target,
							 target_addr_t address,
							 uint32_t size,
							 uint32_t count,
							 uint8_t *buffer)
{
	int err;

	// LOG_INFO("rm(%d) %x %d start", target->coreid, address, (size * count));

	for (unsigned int i = 0; i < (size * count); i++)
	{
		err = idm51_read_memory_byte(target, address, buffer);
		if (err != ERROR_OK)
			return err;

		address = address + 1;
		buffer = buffer + 1;
	}

	return ERROR_OK;
}

static int idm51_read_memory_default(struct target *target,
									 target_addr_t address,
									 uint32_t size,
									 uint32_t count,
									 uint8_t *buffer)
{

	return idm51_read_memory(target, address, size, count, buffer);
}

int idm51_write_memory_byte(struct target *target, uint32_t address, const uint8_t *buffer)
{
	int err = ERROR_OK;

	if (address < MEM_DMEMX_ADDR)
	{
		err = idm51_write_memory_core(target, MEM_IMEMX, (uint32_t)address, buffer);
		if (err != ERROR_OK)
			return err;
	}
	else if ((MEM_DMEMX_ADDR <= address) && (address < MEM_DMEM_ADDR))
	{
		err = idm51_write_memory_core(target, MEM_DMEMX, (uint32_t)(address - MEM_DMEMX_ADDR), buffer);
		if (err != ERROR_OK)
			return err;
	}
	else if ((MEM_DMEM_ADDR <= address))
	{
		err = idm51_write_memory_core(target, MEM_DMEM, (uint32_t)(address - MEM_DMEM_ADDR), buffer);
		if (err != ERROR_OK)
			return err;
	}

	return err;
}

static int idm51_write_memory(struct target *target,
							  target_addr_t address,
							  uint32_t size,
							  uint32_t count,
							  const uint8_t *buffer)
{
	int err;

	// LOG_INFO("wm(%d) %x %d ", target->coreid, address, (size * count));

	for (unsigned int i = 0; i < (size * count); i++)
	{
		err = idm51_write_memory_byte(target, address, buffer);
		if (err != ERROR_OK)
			return err;

		address = address + 1;
		buffer = buffer + 1;
	}

	return ERROR_OK;
}

static int idm51_write_memory_default(struct target *target,
									  target_addr_t address,
									  uint32_t size,
									  uint32_t count,
									  const uint8_t *buffer)
{
	return idm51_write_memory(target, address, size, count, buffer);
}

static int idm51_add_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct idm51_common *idm51 = target_to_idm51(target);
	int retval = ERROR_OK;

	LOG_INFO("add BPID: %d, Address: %#08llx, Type: %d",
			 breakpoint->unique_id,
			 breakpoint->address,
			 breakpoint->type);

	// if(idm51->core_hangup == 1)
	// 	return ERROR_TARGET_NOT_HALTED;

	if (target->state != TARGET_HALTED)
	{
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((breakpoint->type == BKPT_HARD) || (breakpoint->type == BKPT_SOFT))
	{
		/* did we already set this breakpoint? */
		if (breakpoint->is_set)
			return ERROR_OK;

		if (breakpoint->address < MEM_DMEMX_ADDR)
		{
			for (unsigned int i = 0; i < INSTRUCTION_BPOINTS_AMOUNT; i++)
			{
				if ((idm51->breakpoints[i].is_bp_used) == 0)
				{
					idm51->breakpoints[i].is_bp_used = 1;
					idm51->breakpoints[i].bp_value = breakpoint->address;

					retval = idm51_write_core_resource(target, TRIGON, i, breakpoint->address, NULL);
					if (retval != ERROR_OK)
						return retval;

					*(breakpoint->orig_instr) = i;
					breakpoint->is_set = 1;
					return retval;
				}
			}

			LOG_ERROR("Unable to set  breakpoint at address %#08llx" PRIx32
					  " - only %d comparator available ",
					  breakpoint->address, INSTRUCTION_BPOINTS_AMOUNT);
			return ERROR_OK;
		}
	}

	return retval;
}

static int idm51_remove_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	int retval = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);

	LOG_INFO("rem BPID: %d, Address: %#08llx",
			 breakpoint->unique_id,
			 breakpoint->address);

	// if(idm51->core_hangup == 1)
	// 	return ERROR_TARGET_NOT_HALTED;

	if (!breakpoint->is_set)
	{
		LOG_WARNING("breakpoint not set");
		return ERROR_OK;
	}

	if ((breakpoint->type == BKPT_HARD) || (breakpoint->type == BKPT_SOFT))
	{
		if (breakpoint->address < MEM_DMEMX_ADDR)
		{
			// idm51->bp_activ_map = idm51->bp_activ_map &(~(1<<*(breakpoint->orig_instr)));
			idm51->breakpoints[*(breakpoint->orig_instr)].is_bp_used = 0;
			retval = idm51_write_core_resource(target, TRIGOFF, *(breakpoint->orig_instr), breakpoint->address, NULL);
			if (retval != ERROR_OK)
				return retval;

			breakpoint->is_set = 0;
		}
	}

	return retval;
}

static int idm51_spi_communication(struct target *target, const uint8_t *send_buf, const uint8_t send_buf_sz, uint8_t *receive_buf)
{
	int retval = ERROR_OK;
	int err = ERROR_OK;
	uint8_t data = 0;
	// struct idm51_common *idm51 = target_to_idm51(target);

	data = 0x38;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data); // Slave deactivated
	if (err != ERROR_OK)
		return err;

	data = 0x18;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data); // SPI OFF
	if (err != ERROR_OK)
		return err;

	data = 0x1C;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data); // SPI ON
	if (err != ERROR_OK)
		return err;

	data = 0x28;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data); // Slave activated
	if (err != ERROR_OK)
		return err;

	for (int i = 0; i < send_buf_sz; i++)
	{
		data = send_buf[i];
		err = idm51_write_memory_byte(target, SPI_DATA_REG, &data);
		if (err != ERROR_OK)
			return err;

		err = idm51_read_memory_byte(target, SPI_REG_status_1, &data); // How many bytes are in FIFO?
		if (err != ERROR_OK)
			return err;
		if (data)
		{
			err = idm51_read_memory_byte(target, SPI_REG_status_1, &(receive_buf[i])); // Read byte from FIFO
			if (err != ERROR_OK)
				return err;
		}
	}

	data = 0x38;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data); // Slave deactivated
	if (err != ERROR_OK)
		return err;

	data = 0x18;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data); // SPI OFF
	if (err != ERROR_OK)
		return err;

	return retval;
}

static int idm51_identify_flash(struct target *target)
{
	char mem_type_letter = 0;
	uint16_t capacity_code = 0;
	uint8_t data = 0;
	uint8_t rec_data[16] = {0};

	int err;
	int retval = ERROR_OK;
	struct idm51_common *idm51 = target_to_idm51(target);

	if (target->state != TARGET_HALTED)
	{
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	data = 0x02;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_1, &data); // Freq = 5 MHz
	if (err != ERROR_OK)
		return err;
	// data = 0x1C;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data);		// Start SPI to reset it
	// jtag_sleep(30);														// Let to at least one SPI CLK to pass
	// data = 0x18;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data);		// Reset SPI
	// if (err != ERROR_OK)
	// 	return err;

	data = 0x38;
	err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data); // SS0, Motorola, Master, CPHA=CPOL=0, Programmable Slave Select, Slave deactivated
	if (err != ERROR_OK)
		return err;
	data = 0xFF;
	err = idm51_write_memory_byte(target, SPI_REG_mask_1, &data); // No interrupts
	if (err != ERROR_OK)
		return err;
	data = 0xF0;
	err = idm51_write_memory_byte(target, SPI_REG_status_1, &data); // Clear status
	if (err != ERROR_OK)
		return err;

	{
		uint8_t send_data[16] = {0x9F, 0x00, 0x00, 0x00};
		idm51_spi_communication(target, send_data, 4, rec_data);
	}
	// data = 0x9F;
	// err = idm51_write_memory_byte(target, SPI_DATA_REG, &data);			// Load JEDEC ID instruction
	// if (err != ERROR_OK)
	// 	return err;
	// data = 0x00;
	// err = idm51_write_memory_byte(target, SPI_DATA_REG, &data);			// Dummy bytes
	// if (err != ERROR_OK)
	// 	return err;
	// err = idm51_write_memory_byte(target, SPI_DATA_REG, &data);			// Dummy bytes
	// if (err != ERROR_OK)
	// 		return err;
	// err = idm51_write_memory_byte(target, SPI_DATA_REG, &data);			// Dummy bytes
	// if (err != ERROR_OK)
	// 	return err;
	// data = 0x28;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data);		// Slave activated
	// if (err != ERROR_OK)
	// 	return err;
	// data = 0x1C;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data);		// SPI ON
	// if (err != ERROR_OK)
	// 	return err;

	// jtag_sleep(1000);

	// data = 0x38;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_2, &data);		// Slave deactivated
	// if (err != ERROR_OK)
	// 	return err;

	// err = idm51_read_memory_byte(target, SPI_REG_status_1, &data);		// How many bytes are in FIFO?
	// if (err != ERROR_OK)
	// 	return err;
	// int i = 0;
	// while(data)
	// {
	// 	if (data && (i < 16))
	// 	{
	// 		err = idm51_read_memory_byte(target, SPI_DATA_REG, &(rec_data[i]));	// Read Flash parameters
	// 		if (err != ERROR_OK)
	// 			return err;
	// 		i++;
	// 		err = idm51_read_memory_byte(target, SPI_REG_status_1, &data);
	// 		if (err != ERROR_OK)
	// 			return err;
	// 	}
	// 	else break;
	// }
	// data = 0x18;
	// err = idm51_write_memory_byte(target, SPI_REG_CFG_3, &data);		// SPI OFF
	// if (err != ERROR_OK)
	// 	return err;

	idm51->ext_flash.manufacturer_id = rec_data[1]; // Read Flash parameters
	idm51->ext_flash.mem_type = rec_data[2];
	idm51->ext_flash.capactiy = 1 << rec_data[3];

	if (idm51->ext_flash.manufacturer_id == 0xEF) // Winbond detected
	{
		idm51->ext_flash.is_identified = true;
		idm51->ext_flash.manufacturer = "Winbond";
		switch (idm51->ext_flash.mem_type)
		{
		case 0x30:
			mem_type_letter = 'X';
			break;
		case 0x40:
		case 0x70:
			mem_type_letter = 'Q';
			break;
		case 0x61:
			mem_type_letter = 'M';
			break;
		case 0xAA:
			mem_type_letter = 'H';
			break;
		default:
			mem_type_letter = '?';
			break;
		}

		switch (rec_data[3])
		{
		case 0x10:
			capacity_code = 05;
			break;
		case 0x11:
			capacity_code = 10;
			break;
		case 0x12:
			capacity_code = 20;
			break;
		case 0x13:
			capacity_code = 40;
			break;
		case 0x14:
			capacity_code = 80;
			break;
		case 0x15:
			capacity_code = 16;
			break;
		case 0x16:
			capacity_code = 32;
			break;
		case 0x17:
			capacity_code = 64;
			break;
		case 0x18:
			capacity_code = 128;
			break;
		case 0x19:
			capacity_code = 256;
			break;
		case 0x20:
			capacity_code = 512;
			break;
		case 0x21:
			capacity_code = 01;
			break;
		case 0x22:
			capacity_code = 02;
			break;
		default:
			capacity_code = 00;
			break;
		}

		snprintf(idm51->ext_flash.part_num, 20, "%c25%c%02d..", idm51->ext_flash.manufacturer[0], mem_type_letter, capacity_code);

		//======================== Read Status Register ============================================================
		{
			uint8_t send_data[16] = {0x05, 0x00};
			idm51_spi_communication(target, send_data, 2, rec_data);
		}
		idm51->ext_flash.status_reg = rec_data[1];
		//======================== Read Status Register =========================================================
	}
	else
		idm51->ext_flash.part_num = "unknown";

	return retval;
}

// static int idm51_winbond_flash_communicate(struct target *target, uint8_t *command)
// {
// 	int retval = ERROR_OK;

// 	{
// 		uint8_t send_data[16] = {0x05, 0x00};
// 		retval = idm51_spi_communication(target, send_data, 2, rec_data);	// Send Read Status Register command
// 		if (retval != ERROR_OK)
// 			return retval;
// 		idm51->ext_flash.status_reg = rec_data[1];
// 		if(idm51->ext_flash.status_reg & (1 << 0))							// If Busy - leave
// 		{
// 			LOG_ERROR("Cannot flash - Flash is Busy");
// 			return ERROR_FAIL;
// 		}
// 	}

// 	return retval;
// }

static int idm51_winbond_flash_erase(struct target *target, uint32_t erase_size)
{
	uint32_t curr_address = 0;
	uint32_t sectors_4k = 0;
	uint32_t blocks_32k = 0;
	uint32_t blocks_64k = 0;
	uint32_t to_be_erased = 0;
	uint8_t rec_data[16] = {0};

	struct idm51_common *idm51 = target_to_idm51(target);
	int retval = ERROR_OK;

	{
		uint8_t send_data[16] = {0x05, 0x00};
		retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
		if (retval != ERROR_OK)
			return retval;
		idm51->ext_flash.status_reg = rec_data[1];
		if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
		{
			LOG_ERROR("Cannot flash - Flash is Busy");
			return ERROR_FAIL;
		}
	}

	if ((idm51->ext_flash.capactiy / 1024) < erase_size)
	{
		LOG_ERROR("Failed to erase - flash capacity (%d KB) is less than you want to erase (%d KB)", idm51->ext_flash.capactiy / 1024, erase_size);
		to_be_erased = 0;
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}
	else if ((idm51->ext_flash.capactiy / 1024) == erase_size) // Full chip erase
	{
		{
			uint8_t send_data[16] = {0x06};
			retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
			if (retval != ERROR_OK)
				return retval;
		}

		{
			uint8_t send_data[16] = {0x05, 0x00};
			retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
			if (retval != ERROR_OK)
				return retval;
			idm51->ext_flash.status_reg = rec_data[1];
			if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
			{
				LOG_ERROR("Cannot flash - Flash is Busy");
				return ERROR_FAIL;
			}
			if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
			{
				LOG_ERROR("Cannot flash - Communication error");
				return ERROR_FAIL;
			}
		}

		{
			uint8_t send_data[16] = {0x60};
			idm51_spi_communication(target, send_data, 1, rec_data); // Send Full chip erase command
		}

		LOG_INFO("Successfully erased %d KB", (idm51->ext_flash.capactiy / 1024));
		to_be_erased = idm51->ext_flash.capactiy;
	}
	else
	{
		sectors_4k = erase_size / 4;
		if (erase_size % 4)
			sectors_4k++;
		to_be_erased = sectors_4k * 4 * 1024; // in Bytes
		blocks_64k = sectors_4k / 16;
		sectors_4k -= blocks_64k * 16;
		blocks_32k = sectors_4k / 8;
		sectors_4k -= blocks_32k * 8;

		while (blocks_64k)
		{
			{
				uint8_t send_data[16] = {0x06};
				retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
			}

			{
				uint8_t send_data[16] = {0xD8, (curr_address >> 16) & 0xFF, (curr_address >> 8) & 0xFF, (curr_address >> 0) & 0xFF};
				retval = idm51_spi_communication(target, send_data, 4, rec_data); // Send 64K Block Erase command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
				if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
				{
					LOG_ERROR("Cannot flash - Communication error");
					return ERROR_FAIL;
				}
			}

			curr_address += (64 * 1024);
			blocks_64k--;
		}

		while (blocks_32k)
		{
			{
				uint8_t send_data[16] = {0x06};
				retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
			}

			{
				uint8_t send_data[16] = {0x52, (curr_address >> 16) & 0xFF, (curr_address >> 8) & 0xFF, (curr_address >> 0) & 0xFF};
				retval = idm51_spi_communication(target, send_data, 4, rec_data); // Send 32K Block Erase command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
				if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
				{
					LOG_ERROR("Cannot flash - Communication error");
					return ERROR_FAIL;
				}
			}

			curr_address += (32 * 1024);
			blocks_32k--;
		}

		while (sectors_4k)
		{
			{
				uint8_t send_data[16] = {0x06};
				retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
			}

			{
				uint8_t send_data[16] = {0x20, (curr_address >> 16) & 0xFF, (curr_address >> 8) & 0xFF, (curr_address >> 0) & 0xFF};
				retval = idm51_spi_communication(target, send_data, 4, rec_data); // Send Sector Erase command
				if (retval != ERROR_OK)
					return retval;
			}

			{
				uint8_t send_data[16] = {0x05, 0x00};
				retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
				if (retval != ERROR_OK)
					return retval;
				idm51->ext_flash.status_reg = rec_data[1];
				if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
				{
					LOG_ERROR("Cannot flash - Flash is Busy");
					return ERROR_FAIL;
				}
				if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
				{
					LOG_ERROR("Cannot flash - Communication error");
					return ERROR_FAIL;
				}
			}

			curr_address += (4 * 1024);
			sectors_4k--;
		}

		LOG_INFO("Successfully erased %d KB", to_be_erased / 1024);
	}

	idm51->ext_flash.bytes_erased = to_be_erased;

	return retval;
}

static int idm51_winbond_flash_program(struct target *target, uint16_t size, FILE *firmware)
{
	int retval = ERROR_OK;
	uint16_t curr_address = 0;
	uint8_t rec_data[260] = {0};

	struct idm51_common *idm51 = target_to_idm51(target);

	{
		uint8_t send_data[16] = {0x05, 0x00};
		retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
		if (retval != ERROR_OK)
			return retval;
		idm51->ext_flash.status_reg = rec_data[1];
		if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
		{
			LOG_ERROR("Cannot flash - Flash is Busy");
			return ERROR_FAIL;
		}
	}

	{
		uint8_t send_data[16] = {0x06};
		retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
		if (retval != ERROR_OK)
			return retval;
	}

	{
		uint8_t send_data[16] = {0x05, 0x00};
		retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
		if (retval != ERROR_OK)
			return retval;
		idm51->ext_flash.status_reg = rec_data[1];
		if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
		{
			LOG_ERROR("Cannot flash - Flash is Busy");
			return ERROR_FAIL;
		}
		if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
		{
			LOG_ERROR("Cannot flash - Communication error");
			return ERROR_FAIL;
		}
	}

	{
		uint8_t send_data[16] = {0x02, 0x00, 0x00, 0x00, (size >> 0) & 0xFF, (size >> 8) & 0xFF};
		retval = idm51_spi_communication(target, send_data, 6, rec_data); // Send Page Programm command with first two bytes - firmware size
		if (retval != ERROR_OK)
			return retval;
		curr_address += 2;
	}

	while (curr_address < size)
	{
		{
			uint8_t send_data[16] = {0x05, 0x00};
			retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
			if (retval != ERROR_OK)
				return retval;
			idm51->ext_flash.status_reg = rec_data[1];
			if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
			{
				LOG_ERROR("Cannot flash - Flash is Busy");
				return ERROR_FAIL;
			}
		}

		{
			uint8_t send_data[16] = {0x06};
			retval = idm51_spi_communication(target, send_data, 1, rec_data); // Send Write Enable command
			if (retval != ERROR_OK)
				return retval;
		}

		{
			uint8_t send_data[16] = {0x05, 0x00};
			retval = idm51_spi_communication(target, send_data, 2, rec_data); // Send Read Status Register command
			if (retval != ERROR_OK)
				return retval;
			idm51->ext_flash.status_reg = rec_data[1];
			if (idm51->ext_flash.status_reg & (1 << 0)) // If Busy - leave
			{
				LOG_ERROR("Cannot flash - Flash is Busy");
				return ERROR_FAIL;
			}
			if ((idm51->ext_flash.status_reg & (1 << 1)) == 0) // If Write Enable Latch was not set - leave
			{
				LOG_ERROR("Cannot flash - Communication error");
				return ERROR_FAIL;
			}
		}

		{
			uint16_t i = 0;
			uint8_t send_data[260] = {
				0x02,
				(curr_address >> 16) & 0xFF,
				(curr_address >> 8) & 0xFF,
				(curr_address >> 0) & 0xFF};
			for (i = 0; i < 256; i++)
			{
				int s = 0;
				if ((s = getc(firmware)) != EOF)
				{
					send_data[4 + i] = s & 0xFF;
				}
				else
				{
					break;
				}
			}
			retval = idm51_spi_communication(target, send_data, i + 4, rec_data); // Send Page Programm command with first two bytes - firmware size
			if (retval != ERROR_OK)
				return retval;
			curr_address += i;
		}
	}

	return retval;
}

COMMAND_HANDLER(idm51_reset)
{
	int err = ERROR_OK;
	// bool enable_spi_load = 0;

	struct target *target = get_current_target(CMD_CTX);
	struct idm51_common *idm51 = target_to_idm51(target);

	if (CMD_ARGC > 0)
	{
		if (strcmp("enable_spi_load", CMD_ARGV[0]) == 0)
			idm51->is_load_enabled = true;
		else
			idm51->is_load_enabled = false;
	}

	err = idm51_assert_reset(target);
	if (err != ERROR_OK)
		return err;

	err = idm51_print_status(target);

	err = idm51_deassert_reset(target);
	if (err != ERROR_OK)
		return err;

	err = idm51_print_status(target);

	return err;
}

COMMAND_HANDLER(idm51_fill_zero)
{
	int err = ERROR_OK;
	uint32_t i = 0;

	uint32_t adr = 0;
	uint32_t size = 0;

	uint8_t dan = 0;

	struct target *target = get_current_target(CMD_CTX);

	if (CMD_ARGC > 0)
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], adr);
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (CMD_ARGC > 1)
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], size);
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	for (i = 0; i < size; i++)
	{
		err = idm51_write_memory_byte(target, adr + i, &dan);
		if (err != ERROR_OK)
			return err;
	}

	return err;
}

COMMAND_HANDLER(idm51_program)
{
	int err = ERROR_OK;
	char fw_filename[255] = {'\0'};
	FILE *firmware = NULL;
	target_addr_t adr = 0;
	int s = 0;

	struct target *target = get_current_target(CMD_CTX);

	if (CMD_ARGC > 0)
		strcpy(fw_filename, CMD_ARGV[0]);
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	firmware = fopen(fw_filename, "r+b");
	if (firmware == NULL)
		return ERROR_COMMAND_ARGUMENT_INVALID;

	while (((s = getc(firmware)) != EOF) && (adr < 0x10000))
	{
		char b = s & 0xFF;
		err = idm51_write_memory_byte(target, adr, (byte *)&b);
		if (err != ERROR_OK)
		{
			fclose(firmware);
			return err;
		}
		adr++;
	}

	fclose(firmware);

	err = idm51_assert_reset(target);
	if (err != ERROR_OK)
		return err;

	err = idm51_deassert_reset(target);
	if (err != ERROR_OK)
		return err;

	return err;
}

COMMAND_HANDLER(idm51_flash_erase)
{
	int erase_length = 0;
	int err = ERROR_OK;

	if (CMD_ARGC > 0)
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], erase_length);
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct target *target = get_current_target(CMD_CTX);
	struct idm51_common *idm51 = target_to_idm51(target);

	err = idm51_identify_flash(target);
	if (err != ERROR_OK)
		return err;
	if (idm51->ext_flash.is_identified == 0)
	{
		LOG_ERROR("Failed to identify flash");
		return ERROR_FAIL;
	}
	else
	{
		LOG_INFO("Flash identified: %s %s", idm51->ext_flash.manufacturer, idm51->ext_flash.part_num);
		LOG_INFO("Flash capacity: %.1f Mb = %d KB", (float)(idm51->ext_flash.capactiy) * 8 / 1024 / 1024, idm51->ext_flash.capactiy / 1024);
	}

	err = idm51_winbond_flash_erase(target, erase_length);
	if (err != ERROR_OK)
		return err;

	return err;
}

COMMAND_HANDLER(idm51_flash_program)
{
	int err = ERROR_OK;
	char fw_filename[255] = {'\0'};
	FILE *firmware = NULL;
	uint32_t fw_size = 0;
	static uint8_t user_warned = 0;

	if (CMD_ARGC > 0)
		strcpy(fw_filename, CMD_ARGV[0]);
	else
		return ERROR_COMMAND_SYNTAX_ERROR;

	firmware = fopen(fw_filename, "r+b");
	if (firmware == NULL)
		return ERROR_COMMAND_ARGUMENT_INVALID;

	fseek(firmware, 0, SEEK_END);
	fw_size = ftell(firmware) + 2; // Space required in flash = firmware size + firmware size value (2 bytes)
	fseek(firmware, 0, SEEK_SET);

	struct target *target = get_current_target(CMD_CTX);
	struct idm51_common *idm51 = target_to_idm51(target);

	if (idm51->ext_flash.is_identified == 0)
	{
		err = idm51_identify_flash(target);
		if (err != ERROR_OK)
			return err;
		if (idm51->ext_flash.is_identified == 0)
		{
			LOG_ERROR("Failed to identify flash");
			return ERROR_FAIL;
		}
		else
		{
			LOG_INFO("Flash identified: %s %s", idm51->ext_flash.manufacturer, idm51->ext_flash.part_num);
			LOG_INFO("Flash capacity: %.1f Mb = %d KB", (float)(idm51->ext_flash.capactiy) * 8 / 1024 / 1024, idm51->ext_flash.capactiy / 1024);
		}

		err = idm51_winbond_flash_erase(target, fw_size);
		if (err != ERROR_OK)
			return err;
	}
	else if (idm51->ext_flash.bytes_erased < fw_size)
	{
		if (user_warned == 0)
		{
			LOG_INFO("Erased space in flash is not enough for specified firmware. Run this command again to perform erase and programming");
			user_warned = 1;
			return err;
		}
		else
		{
			user_warned = 0;
			err = idm51_winbond_flash_erase(target, fw_size);
			if (err != ERROR_OK)
				return err;
		}
	}
	else
	{
		user_warned = 0;
	}

	idm51_winbond_flash_program(target, fw_size, firmware);

	return err;
}

static const struct command_registration idm51_command_handlers[] = {
	{
		.name = "idm51_reset",
		.handler = idm51_reset,
		.mode = COMMAND_EXEC,
		.help = "reset target. Specify \"enable_spi_load\" to enable firmware load from external spi-flash",
		.usage = "idm51_reset [enable_spi_load]",
	},
	{
		.name = "idm51_fill_zero",
		.handler = idm51_fill_zero,
		.mode = COMMAND_EXEC,
		.help = "idm51_fill_zero <adr> <size>",
		.usage = "<adr> <size>",
	},
	{
		.name = "idm51_program",
		.handler = idm51_program,
		.mode = COMMAND_EXEC,
		.help = "idm51_program <bin file>",
		.usage = "<bin file>",
	},
	{
		.name = "idm51_flash_erase",
		.handler = idm51_flash_erase,
		.mode = COMMAND_EXEC,
		.help = "This command scans for SPI flash connected to CS0, and erases it if compatible. Size is specified in Kilobytes",
		.usage = "<size in KB>",
	},
	{
		.name = "idm51_flash_program",
		.handler = idm51_flash_program,
		.mode = COMMAND_EXEC,
		.help = "This command writes specified bin file to SPI flash connected to CS0 if compatible. Will perform flash erase first if is wasn't done before.",
		.usage = "<bin file>",
	},

	COMMAND_REGISTRATION_DONE};

/** Holds methods for idm51 targets. */
struct target_type idm51_target = {
	.name = "idm51",

	.poll = idm51_poll,
	.arch_state = idm51_arch_state,

	.get_gdb_reg_list = idm51_get_gdb_reg_list,

	.halt = idm51_halt,
	.resume = idm51_resume,
	.step = idm51_step,

	.assert_reset = idm51_assert_reset,
	.deassert_reset = idm51_deassert_reset,

	.read_memory = idm51_read_memory_default,
	.write_memory = idm51_write_memory_default,

	.add_breakpoint = idm51_add_breakpoint,
	.remove_breakpoint = idm51_remove_breakpoint,

	.commands = idm51_command_handlers,
	.target_create = idm51_target_create,
	.init_target = idm51_init_target,
	.examine = idm51_examine,
};
