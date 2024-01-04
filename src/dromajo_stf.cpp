/*
 * STF gen trigger detection
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "dromajo.h"

#ifdef REGRESS_COSIM
#include "dromajo_cosim.h"
#endif

#include "dromajo_stf.h"
stf::STFWriter stf_writer;

void stf_record_state(RISCVMachine * m, int hartid)
{
    RISCVCPUState * cpu = m->cpu_state[hartid];

    // Record integer registers
    for(int rn = 0; rn < 32; ++rn) {
        stf_writer << stf::InstRegRecord(rn,
                                         stf::Registers::STF_REG_TYPE::INTEGER,
                                         stf::Registers::STF_REG_OPERAND_TYPE::REG_STATE,
                                         riscv_get_reg(cpu, rn));
    }

#if FLEN > 0
    // Record floating point registers
    for(int rn = 0; rn < 32; ++rn) {
        stf_writer << stf::InstRegRecord(rn,
                                         stf::Registers::STF_REG_TYPE::FLOATING_POINT,
                                         stf::Registers::STF_REG_OPERAND_TYPE::REG_STATE,
                                         riscv_get_fpreg(cpu, rn));
    }
#endif

    // TODO: CSRs
}

void stf_trace_element(RISCVMachine * m, int hartid, int priv, uint64_t last_pc, uint32_t insn)
{
    if(m->common.stf_entering_traceable_region) {
        m->common.stf_entering_traceable_region = false;
        stf_record_state(m, hartid);
        return;
    }

    RISCVCPUState *cpu = m->cpu_state[hartid];

    if(m->common.stf_in_traceable_region && (cpu->pending_exception == -1) && (m->common.stf_prog_asid == ((cpu->satp >> 4) & 0xFFFF))) {
        ++(m->common.stf_count);
        const uint32_t inst_width = ((insn & 0x3) == 0x3) ? 4 : 2;
        bool skip_record = false;

        // See if the instruction changed control flow or a
        // possible not-taken branch conditional
        if(cpu->info != ctf_nop) {
            stf_writer << stf::InstPCTargetRecord(virt_machine_get_pc(m, 0));
        }
        else {
            // Not sure what's going on, but there's a
            // possibility that the current instruction will
            // cause a page fault or a timer interrupt or
            // process switch so the next instruction might
            // not be on the program's path
            if(cpu->pc != last_pc + inst_width) {
                skip_record = true;
            }
        }
        // Record the instruction trace record
        if(false == skip_record) {
            // Source registers
            for(auto int_reg_src : cpu->stf_read_regs) {
                stf_writer << stf::InstRegRecord(int_reg_src,
                                                 stf::Registers::STF_REG_TYPE::INTEGER,
                                                 stf::Registers::STF_REG_OPERAND_TYPE::REG_SOURCE,
                                                 riscv_get_reg(cpu, int_reg_src));
            }
#if FLEN > 0
            for(auto fp_reg_src : cpu->stf_read_fp_regs) {
                stf_writer << stf::InstRegRecord(fp_reg_src,
                                                 stf::Registers::STF_REG_TYPE::FLOATING_POINT,
                                                 stf::Registers::STF_REG_OPERAND_TYPE::REG_SOURCE,
                                                 riscv_get_reg(cpu, fp_reg_src));
            }
#endif
            // Destination registers
            for(auto int_reg_dst : cpu->stf_write_regs) {
                stf_writer << stf::InstRegRecord(int_reg_dst,
                                                 stf::Registers::STF_REG_TYPE::INTEGER,
                                                 stf::Registers::STF_REG_OPERAND_TYPE::REG_DEST,
                                                 riscv_get_reg(cpu, int_reg_dst));
            }
#if FLEN > 0
            for(auto fp_reg_dst : cpu->stf_write_fp_regs) {
                stf_writer << stf::InstRegRecord(fp_reg_dst,
                                                 stf::Registers::STF_REG_TYPE::FLOATING_POINT,
                                                 stf::Registers::STF_REG_OPERAND_TYPE::REG_DEST,
                                                 riscv_get_fpreg(cpu, fp_reg_dst));
            }
#endif
            // Memory reads
            for(auto mem_read : cpu->stf_mem_reads) {
                stf_writer << stf::InstMemAccessRecord(mem_read.vaddr,
                                                       mem_read.size,
                                                       0,
                                                       stf::INST_MEM_ACCESS::READ);
                stf_writer << stf::InstMemContentRecord(mem_read.value);
            }
            // Memory writes
            for(auto mem_write : cpu->stf_mem_writes) {
                stf_writer << stf::InstMemAccessRecord(mem_write.vaddr,
                                                       mem_write.size,
                                                       0,
                                                       stf::INST_MEM_ACCESS::WRITE);
                stf_writer << stf::InstMemContentRecord(mem_write.value); // empty content for now
            }
            // Opcode (instruction)
            if(inst_width == 4) {
               stf_writer << stf::InstOpcode32Record(insn);
            }
            else {
               stf_writer << stf::InstOpcode16Record(insn & 0xFFFF);
            }
        }
    }

    // Reset
    riscv_stf_reset(cpu);
}

bool stf_trace_trigger(RISCVMachine * m, int hartid, uint32_t insn)
{
    uint64_t pc = virt_machine_get_pc(m, hartid);

    // Determine if we're in a traceable region of the workload. All conditions
    // must be met (true) to begin/continue tracing.
    // TODO: Non-contiguous traces

    // Has the boot rom finished executing?
    if(m->common.stf_boot_rom_complete == false) {
        m->common.stf_boot_rom_complete = pc == m->ram_base_addr;
        if(m->common.stf_boot_rom_complete) {
        }
    }
    bool in_traceable_region = m->common.stf_boot_rom_complete;

    // If tracepoints are enabled, open the trace and start tracing when the
    // start tracepoint is detected
    if(m->common.stf_tracepoints_enabled) {
        if(insn == START_TRACE_OPC) {
            m->common.stf_in_tracepoint_region = true;
        }
        else if(insn == STOP_TRACE_OPC) {
            m->common.stf_in_tracepoint_region = false;
        }
    }
    in_traceable_region &= m->common.stf_in_tracepoint_region;

    // Are we in a traceable privilege mode?
    in_traceable_region &= \
        m->common.stf_highest_priv_mode <= riscv_get_priv_level(m->cpu_state[hartid]);

    // If we're entering the traceable region, the next instruction executed
    // will be traced. The current instruction will not be traced.
    m->common.stf_entering_traceable_region = \
        in_traceable_region && (m->common.stf_in_traceable_region == false);

    // If entering the traceable region for the first time, open the trace.
    if((m->common.stf_trace_open == false) && m->common.stf_entering_traceable_region) {
        stf_trace_open(m, hartid, pc);
    }

    m->common.stf_in_traceable_region = in_traceable_region;
    return m->common.stf_trace_open;
}

void stf_trace_open(RISCVMachine * m, int hartid, target_ulong pc)
{
    m->common.stf_trace_open = true;
    fprintf(dromajo_stderr, ">>> DROMAJO: Tracing Started at 0x%llx\n", pc);

    RISCVCPUState * s = m->cpu_state[hartid];
    m->common.stf_prog_asid = (s->satp >> 4) & 0xFFFF;

    if((bool)stf_writer == false) {
        stf_writer.open(m->common.stf_trace);
        stf_writer.addTraceInfo(stf::TraceInfoRecord(
                   stf::STF_GEN::STF_GEN_DROMAJO, 1, 1, 0,"Trace from Dromajo"));
        stf_writer.setISA(stf::ISA::RISCV);
        stf_writer.setHeaderIEM(stf::INST_IEM::STF_INST_IEM_RV64);
        stf_writer.setTraceFeature(stf::TRACE_FEATURES::STF_CONTAIN_RV64);
        stf_writer.setTraceFeature(stf::TRACE_FEATURES::STF_CONTAIN_PHYSICAL_ADDRESS);
        stf_writer.setHeaderPC(pc);
        stf_writer.finalizeHeader();
    }
}

void stf_trace_close(RISCVMachine * m, target_ulong pc)
{
    m->common.stf_trace_open = false;
    fprintf(dromajo_stderr, ">>> DROMAJO: Tracing Stopped at 0x%llx\n", pc);
    fprintf(dromajo_stderr, ">>> DROMAJO: Traced %llu insts\n", m->common.stf_count);
    stf_writer.close();
}

