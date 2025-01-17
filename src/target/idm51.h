#ifndef idm51_H
#define idm51_H

#include <jtag/jtag.h>
#include <target/idm51_once.h>

#define TAPID_IDM51 0x0051a01f

#define IDM51_PC 0

#define EXTEST 0x00
#define DEBUG_INIT 0x1C

#define DR_IDM51_SIZE 32

#define NOP        0x0ull
#define RST_ON     0x1ull
#define RST_OFF    0x2ull
#define RUN        0x3ull
#define HALT       0x4ull
#define STEP       0x5ull
#define READDATA   0x6ull
#define WRITEDATA  0x7ull
	#define MEM_IMEMX   0x0ull
	#define MEM_DMEMX   0x1ull
	#define MEM_DMEM    0x2ull
		#define MEM_IMEMX_ADDR  0x00000
      #define MEM_IMEMX_SIZE  0x10000
		#define MEM_DMEMX_ADDR  0x10000
      #define MEM_DMEMX_SIZE  0x10000
		#define MEM_DMEM_ADDR   0x20000
      #define MEM_DMEM_SIZE   0x00080
#define READST     0x8ull
#define READPRCNT  0x9ull
#define TRIGON     0xAull
#define TRIGOFF    0xBull

#define PERIPH_ADDR       (MEM_DMEMX_ADDR + 0xE000)
  #define SPI_ADDR          (PERIPH_ADDR + 0x0020)
    #define SPI_REG_CFG_1     (SPI_ADDR + 0x0)
    #define SPI_REG_CFG_2     (SPI_ADDR + 0x1)
    #define SPI_REG_CFG_3     (SPI_ADDR + 0x2)
    #define SPI_REG_FF_lvl    (SPI_ADDR + 0x3)
    #define SPI_REG_mask_1    (SPI_ADDR + 0x4)
    #define SPI_REG_status_1  (SPI_ADDR + 0x5)
    #define SPI_DATA_REG      (SPI_ADDR + 0x6)



//#define STATE_RUN 		 0x0
//#define STATE_HALT 		 0x1
//#define STATE_BREAKPOINT 0x2
//#define STATE_HANGUP	 0x8

#define STATE_HALTED 0x8000ULL
#define STATE_IN_RESET 0x4000ULL
#define STATE_LOAD_DONE 0x2000ULL
#define STATE_LOAD_EN 0x1000ULL
#define BP_ARE_USED 0x00FFULL


#define BPOINTS_AMOUNT 8
#define INSTRUCTION_BPOINTS_AMOUNT 6

#define NONE_ADR       0xFFFFFFFF
#define Status_MC_in_debug_mode        0x8000


enum idm51_regnum
{
  PC_REGNUM = 0,
  // E_R1_REGNUM,  E_R2_REGNUM,  E_R3_REGNUM,
  // E_R4_REGNUM,  E_R5_REGNUM,  E_R6_REGNUM,  E_R7_REGNUM,
  // E_R8_REGNUM,  E_R9_REGNUM,  E_R10_REGNUM, E_R11_REGNUM,
  // E_R12_REGNUM, E_R13_REGNUM, E_R14_REGNUM, E_R15_REGNUM,
  // E_R16_REGNUM, E_R17_REGNUM, E_R18_REGNUM, E_R19_REGNUM,
  // E_R20_REGNUM, E_R21_REGNUM, E_R22_REGNUM, E_R23_REGNUM,
  // E_R24_REGNUM, E_R25_REGNUM, E_R26_REGNUM, E_R27_REGNUM,
  // E_R28_REGNUM, E_R29_REGNUM, E_R30_REGNUM, E_R31_REGNUM,
  // E_S0_REGNUM, /*S0 PC*/
  // E_S1_REGNUM,/*S1 PSW*/
  // E_S2_REGNUM,/*S2 SBA*/
  // E_S3_REGNUM, /*S3 SL*/
  // E_S4_REGNUM,/*S4 SPH - hardware stack pointer*/
  // E_S5_REGNUM,/*S5 FPH - hardware frame pointer*/
  	  	  	  // /*   CRISC1        MRISC */
  // E_S6_REGNUM,/*S6 LAST_ADDR   LAST_ADDR  (CRISC0 - PCL)*/
  // E_S7_REGNUM,/*S7 NMI_PC      MEM_STAT*/
  // E_S8_REGNUM,/*S8 MEM_STAT    FPU_CTRL*/
  // E_S9_REGNUM,/*S9 FPU_CTRL    FPU_STAT*/
  // E_S10_REGNUM,/*S10 FPU_STAT*/
  // E_S11_REGNUM,/*S11 */
  // E_S12_REGNUM,/*S12 */
  // E_S13_REGNUM,/*S13 */

  // E_PC_REGNUM         = E_S0_REGNUM, /* Program counter.  */
  // E_SP_REGNUM         = E_S4_REGNUM, /* Stack pointer.  */
  // E_FN_RETURN_REGNUM  = E_R19_REGNUM,  /* Function return value register.  */
  // E_1ST_ARGREG        = E_R19_REGNUM,  /* 1st  function arg register.  */
  // E_LAST_ARGREG       = E_R24_REGNUM, /* Last function arg register.  */

  // E_IDM51_NUM_REGS   = E_S13_REGNUM + 1,
  // E_MAX_REGS		  = E_IDM51_NUM_REGS,

  // E_FINAL = 0x1000
  IDM51_NUM_REGS,
  MAX_REGS = IDM51_NUM_REGS,
  FINAL = 0x1000
};


struct mcu_jtag {
	struct jtag_tap *tap;
};

struct idm51_status{
  bool is_halted;
  bool is_in_reset;
  bool is_load_done;
  bool is_load_enabled;
};

struct idm51_comparator{
  uint8_t bp_number;    // 0-5 - instruction bpoints; 6 - Dmemx wpoint; 7 - Dmem wpoint
  bool is_bp_used;
  uint32_t bp_value;
};

// struct idm51_spi {
// 	uint8_t spi_REG_CFG_1;
// 	uint8_t spi_REG_CFG_2;
// 	uint8_t spi_REG_CFG_3;
// 	uint8_t spi_REG_FF_lvl;
// 	uint8_t spi_REG_mask_1;
// 	uint8_t spi_REG_status_1;
// 	uint8_t spi_DATA_REG;
// };

struct spi_flash
{
  uint8_t is_identified;                  // Flash identified flag
  uint8_t manufacturer_id;
  char *manufacturer;                     // Name of flash manufacturer
  uint8_t mem_type;
  uint32_t capactiy;                      // Flash capacity in Bytes
  char *part_num;
  uint8_t status_reg;
};

struct idm51_common {
	struct mcu_jtag jtag_info;
	struct reg_cache *core_cache;
	uint32_t core_regs[MAX_REGS];
	
	struct idm51_comparator* breakpoints;
  bool bp_scanned;
  uint32_t triggered_pc;                  // Last executed instruction number
  uint8_t num_hw_bpoints;
  uint8_t num_hw_bpoints_avail;
  uint8_t num_hw_wpoints;
  uint8_t num_hw_wpoints_avail;

  uint32_t imemstart; 
  uint32_t imemend; 
  uint32_t dmemstart; 
  uint32_t dmemend; 
  uint32_t dmemxstart; 
  uint32_t dmemxend; 


	/* register cache to processor synchronization */
	int (*read_core_reg) (struct target *target, int num);
	int (*write_core_reg) (struct target *target, int num);

	//int core_hangup;

  struct spi_flash ext_flash;

	//struct idm51_spi spi_flash;
	//unsigned int bp_activ_map;
	//uint32_t bp_adr[16];
	//unsigned int bp_pc_num;

	//bool DEBUG_REQUEST;
	//bool spi_load_en;
  bool is_load_done;
  bool is_load_enabled;

	int idm51_num_regs;
};


struct idm51_tap_common {
	int core_smp_num;
};

struct idm51_core_reg {
	uint32_t num;
	const char *name;
	uint32_t size;
	uint32_t eame;
	struct target *target;
	struct idm51_common *idm51_common;
};

static inline struct idm51_common *target_to_idm51(struct target *target)
{
	return target->arch_info;
}

static inline struct idm51_tap_common *target_to_idm51_tap(struct target *target)
{
	return target->tap->priv;
}

int idm51_jtag_sendinstr(struct target *target, uint8_t * ir_in, uint8_t ir_out, int execute);

struct target *get_target_by_num(int num);

#endif /* idm51_H */

