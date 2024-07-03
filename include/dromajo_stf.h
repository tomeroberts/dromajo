//
// STF gen protos.
//
#pragma once

#include "machine.h"
#include "riscv_cpu.h"
#include "stf-inc/stf_record_types.hpp"
#include "stf-inc/stf_writer.hpp"
#include "trace_macros.h"

extern stf::STFWriter stf_writer;
extern void           stf_record_state(RISCVMachine* m, int hartid, uint64_t last_pc);
extern void           stf_trace_element(RISCVMachine* m, int hartid, int priv, uint64_t last_pc, uint32_t insn, bool insn_executed);
extern bool           stf_trace_trigger(RISCVMachine* m, int hartid, uint32_t insn);
extern void           stf_trace_open(RISCVMachine* m, int hartid, uint64_t PC);
extern void           stf_trace_close(RISCVMachine* m, uint64_t PC);
