/*
 * FIXME:
 *
 * Copyright (C) 2023, FIXME
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
//#include "../../trace_macros.h"
//#include "stf-inc/stf_writer.hpp"
//#include "stf-inc/stf_record_types.hpp"

stf::STFWriter stf_writer;
//uint64_t count_on = 0;
//uint64_t count_off = 0;

//#include <limits>
//#include <string>

//uint32_t LEVEL = 5;
//void stf_dbg(std::string s,uint32_t l=0)
//{
//  if(l < LEVEL) fprintf(dromajo_stderr,"DBG HERE %s\n",s.c_str());
//}

//void stf_trace_element(RISCVMachine *m,int hartid,int priv,uint64_t last_pc,uint32_t insn)
//{
//    if(m->common.stf_tracing_enabled) {
//
//        RISCVCPUState *cpu = m->cpu_state[hartid];
// 
//        if(m->common.stf_no_priv_check
//           || ((priv == 0)
//               && (cpu->pending_exception == -1)
//               && (m->common.stf_prog_asid == ((cpu->satp >> 4) & 0xFFFF))))
//        {
//
//            ++m->common.stf_count;
//            const uint32_t inst_width = ((insn & 0x3) == 0x3) ? 4 : 2;
//            bool skip_record = false;
//  
//            // See if the instruction changed control flow or a
//            // possible not-taken branch conditional
//            if(cpu->info != ctf_nop) {
//                stf_writer << stf::InstPCTargetRecord(virt_machine_get_pc(m, 0));
//            }
//            else {
//                // Not sure what's going on, but there's a
//                // possibility that the current instruction will
//                // cause a page fault or a timer interrupt or
//                // process switch so the next instruction might
//                // not be on the program's path
//                if(cpu->pc != last_pc + inst_width) {
//                    skip_record = true;
//                }
//            }
//
//            // Record the instruction trace record
//            if(false == skip_record)
//            {
//                // If the last instruction were a load/store,
//                // record the last vaddr, size, and if it were a
//                // read or write.
//
//                if(cpu->last_data_vaddr
//                    != std::numeric_limits<decltype(cpu->last_data_vaddr)>::max())
//                {
//                    stf_writer << stf::InstMemAccessRecord(cpu->last_data_vaddr,
//                                                           cpu->last_data_size,
//                                                           0,
//                                                           (cpu->last_data_type == 0) ?
//                                                           stf::INST_MEM_ACCESS::READ :
//                                                           stf::INST_MEM_ACCESS::WRITE);
//                    stf_writer << stf::InstMemContentRecord(0); // empty content for now
//                }
//   
//                if(inst_width == 4) {
//                   stf_writer << stf::InstOpcode32Record(insn);
//                }
//                else {
//                   stf_writer << stf::InstOpcode16Record(insn & 0xFFFF);
//                }
//            }
//        }
//    }
//}

bool stf_trace_trigger(RISCVCPUState *s,target_ulong PC,uint32_t insn) 
{
    int hartid = s->mhartid;
    RISCVCPUState *cpu = s->machine->cpu_state[hartid];

    s->machine->common.stf_is_start_opc = insn == START_TRACE_OPC;
    s->machine->common.stf_is_stop_opc  = insn == STOP_TRACE_OPC;

    if(s->machine->common.stf_is_start_opc) {

        s->machine->common.stf_tracing_enabled = true;
        fprintf(dromajo_stderr, ">>> DROMAJO: Tracing Started at 0x%lx\n", PC);

        s->machine->common.stf_prog_asid = (cpu->satp >> 4) & 0xFFFF;

        if((bool)stf_writer == false) {
            stf_writer.open(s->machine->common.stf_trace);
            stf_writer.addTraceInfo(stf::TraceInfoRecord(
                       stf::STF_GEN::STF_GEN_DROMAJO, 1, 1, 0,"Trace from Dromajo"));
            stf_writer.setISA(stf::ISA::RISCV);
            stf_writer.setHeaderIEM(stf::INST_IEM::STF_INST_IEM_RV64);
            stf_writer.setTraceFeature(stf::TRACE_FEATURES::STF_CONTAIN_RV64);
            stf_writer.setTraceFeature(stf::TRACE_FEATURES::STF_CONTAIN_PHYSICAL_ADDRESS);
            stf_writer.setHeaderPC(PC);
            stf_writer.finalizeHeader();
        }
        return true;

    } else if(s->machine->common.stf_is_stop_opc) {

        s->machine->common.stf_tracing_enabled = false;
        fprintf(dromajo_stderr, ">>> DROMAJO: Tracing Stopped at 0x%lx\n", PC);
        fprintf(dromajo_stderr, ">>> DROMAJO: Traced %ld insts\n",
                             s->machine->common.stf_count);
        stf_writer.close();
        return false;
    }

    return s->machine->common.stf_tracing_enabled;
}
