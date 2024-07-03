/*
 * Top-level driver
 *
 * Copyright (C) 2018,2019, Esperanto Technologies Inc.
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>

#include "LiveCacheCore.h"
#include "cutils.h"
#include "iomem.h"
#include "riscv_machine.h"
#include "virtio.h"

//#define REGRESS_COSIM 1
#ifdef REGRESS_COSIM
#include "dromajo_cosim.h"
#endif

#include "dromajo_stf.h"
#include <limits>

#ifdef SIMPOINT_BB
FILE *simpoint_bb_file = nullptr;
int   simpoint_roi     = 0;  // start without ROI enabled

static int simpoint_step(RISCVMachine *m, int hartid, int *n_cycles) {
    assert(hartid == 0);  // Only single core for simpoint creation

    static uint64_t ninst = 0;  // ninst in BB
    static uint64_t sp_inst = 0;
    ninst += *n_cycles;
    sp_inst += *n_cycles;

    if (simpoint_bb_file == 0) {  // Creating checkpoints mode

        assert(!m->common.simpoints.empty());

        if (m->common.simpoint_trace && m->common.stf_in_traceable_region && (sp_inst >= SIMPOINT_SIZE)) {
            m->common.stf_in_traceable_region = false;
            fprintf(dromajo_stderr, "Simpoint: %d ended\n", m->common.simpoints[m->common.simpoint_next-1].id);
            stf_trace_close(m, m->cpu_state[0]->last_pc);
            free((char*)m->common.stf_trace);
            m->common.stf_trace = NULL;
            m->common.stf_count = 0;
            *n_cycles = 10000;
            if (m->common.simpoint_next == m->common.simpoints.size()) {
                return 0;  // notify to terminate nicely
            }
        }

        auto &sp = m->common.simpoints[m->common.simpoint_next];
        if (ninst > sp.start) {
            fprintf(dromajo_stderr, "Simpoint: %d Reached\n", sp.id);
            if (m->common.simpoint_trace) {
                char str[100];
                sprintf(str, "sp%d.zstf", sp.id);
                // Start tracing
                sp_inst = 0;
                m->common.stf_in_traceable_region = true;
                m->common.stf_trace = strdup(str);
                stf_trace_open(m, 0, m->cpu_state[0]->last_pc);
                *n_cycles = 1;
            } else {
                char str[100];
                sprintf(str, "sp%d", sp.id);
                virt_machine_serialize(m, str);
            }

            m->common.simpoint_next++;
        }
        return 1;
    }

    // Creating bb trace mode
    assert(m->common.simpoints.empty());

    static uint64_t                          next_bbv_dump = UINT64_MAX;
    static std::unordered_map<uint64_t, int> pc2id;
    static int                               next_id = 1;
    if (m->common.maxinsns <= next_bbv_dump) {
        if (m->common.maxinsns > SIMPOINT_SIZE)
            next_bbv_dump = m->common.maxinsns - SIMPOINT_SIZE;
        else
            next_bbv_dump = 0;

        if (m->common.bbv.size()) {
            fprintf(simpoint_bb_file, "T");
            for (const auto ent : m->common.bbv) {
                auto it = pc2id.find(ent.first);
                int  id = 0;
                if (it == pc2id.end()) {
                    id = next_id;
                    pc2id[ent.first] = next_id;
                    next_id++;
                } else {
                    id = it->second;
                }

                fprintf(simpoint_bb_file, ":%d:%d ", id, ent.second);
            }
            fprintf(simpoint_bb_file, "\n");
            fflush(simpoint_bb_file);
            m->common.bbv.clear();
        }
    }

    return 1;
}
#endif

static int iterate_core(RISCVMachine *m, int hartid, int n_cycles) {
    m->common.maxinsns -= n_cycles;

    if (m->common.maxinsns <= 0)
        /* Succeed after N instructions without failure. */
        return 0;

    RISCVCPUState *cpu = m->cpu_state[hartid];

    /* Instruction that raises exceptions should be marked as such in
     * the trace of retired instructions.
     */
    uint64_t last_pc  = virt_machine_get_pc(m, hartid);
    int      priv     = riscv_get_priv_level(cpu);
    uint32_t insn_raw = -1;
    bool     do_trace = false;
    int      insn_executed;

    (void)riscv_read_insn(cpu, &insn_raw, last_pc);
    if (m->common.trace < (unsigned)n_cycles) {
        n_cycles = 1;
        do_trace = true;
    } else
        m->common.trace -= n_cycles;

    int keep_going = virt_machine_run(m, hartid, n_cycles, &insn_executed);

    if(m->common.stf_trace) {
        // Returns true if current instruction should be traced
        if(stf_trace_trigger(m, hartid, insn_raw)) {
            stf_trace_element(m, hartid, priv, last_pc, insn_raw, insn_executed > 0);
        }
    }

    if (!do_trace) {
        return keep_going;
    }

    fprintf(dromajo_stderr,
            "%d %d 0x%016" PRIx64 " (0x%08x)",
            hartid,
            priv,
            last_pc,
            (insn_raw & 3) == 3 ? insn_raw : (uint16_t)insn_raw);

    int iregno = riscv_get_most_recently_written_reg(cpu);
    int fregno = riscv_get_most_recently_written_fp_reg(cpu);

    if (cpu->pending_exception != -1)
        fprintf(dromajo_stderr,
                " exception %d, tval %016" PRIx64,
                cpu->pending_exception,
                riscv_get_priv_level(cpu) == PRV_M ? cpu->mtval : cpu->stval);
    else if (iregno > 0)
        fprintf(dromajo_stderr, " x%2d 0x%016" PRIx64, iregno, virt_machine_get_reg(m, hartid, iregno));
    else if (fregno >= 0)
        fprintf(dromajo_stderr, " f%2d 0x%016" PRIx64, fregno, virt_machine_get_fpreg(m, hartid, fregno));
    else
        for (int i = 31; i >= 0; i--)
            if (cpu->most_recently_written_vregs[i]) {
                fprintf(dromajo_stderr, " v%2d 0x", i);
                for (int j = VLEN / 8 - 1; j >= 0; j--) {
                    fprintf(dromajo_stderr, "%02" PRIx8, cpu->v_reg[i][j]);
                }
            }

    putc('\n', dromajo_stderr);

    return keep_going;
}

static double    execution_start_ts;
static uint64_t *execution_progress_meassure;

static void sigintr_handler(int dummy) {
    double t = get_current_time_in_seconds();
    fprintf(dromajo_stderr,
            "Simulation speed: %5.2f MIPS (single-core)\n",
            1e-6 * *execution_progress_meassure / (t - execution_start_ts));
    exit(1);
}

int main(int argc, char **argv) {
#ifdef REGRESS_COSIM
    dromajo_cosim_state_t *costate = 0;
    costate                        = dromajo_cosim_init(argc, argv);

    if (!costate)
        return 1;

    while (!dromajo_cosim_step(costate, 0, 0, 0, 0, 0, false))
        ;
    dromajo_cosim_fini(costate);
#else
    RISCVMachine *m = virt_machine_main(argc, argv);

#ifdef SIMPOINT_BB
    if (m->common.simpoints.empty()) {
        m->common.bbv_ninst = 0;
        simpoint_bb_file = fopen("dromajo_simpoint.bb", "w");
        if (simpoint_bb_file == nullptr) {
            fprintf(dromajo_stderr, "\nerror: could not open dromajo_simpoint.bb for dumping trace\n");
            exit(-3);
        }
    }
#endif

    if (!m)
        return 1;

    int n_cycles                = 10000;
    execution_start_ts          = get_current_time_in_seconds();
    execution_progress_meassure = &m->cpu_state[0]->minstret;
    signal(SIGINT, sigintr_handler);

    /* STF Trace Generation */
    if(m->common.stf_trace) {
        // Throttle back n_cycles
        n_cycles = 1;

	/* If STF tracing is configured to trace the entire workload (i.e. no tracepoints,
	 * no privilege mode checks) then the trace can be opened before execution starts.
	 */
	const int hartid = 0;
	const uint32_t insn_raw = 0x0;
        stf_trace_trigger(m, hartid, insn_raw);
    }

    int keep_going;
    do {
        keep_going = 0;
        for (int i = 0; i < m->ncpus; ++i) keep_going |= iterate_core(m, i, n_cycles);
#ifdef SIMPOINT_BB
        if (simpoint_roi) {
            if (!simpoint_step(m, 0, &n_cycles))
                break;
        }
#endif
    } while (keep_going);

#ifdef SIMPOINT_BB
    if (m->common.simpoints.empty()) {
        fclose(simpoint_bb_file);
    }
#endif
    double t = get_current_time_in_seconds();

    for (int i = 0; i < m->ncpus; ++i) {
        int benchmark_exit_code = riscv_benchmark_exit_code(m->cpu_state[i]);
        if (benchmark_exit_code != 0) {
            fprintf(dromajo_stderr, "\nBenchmark exited with code: %i \n", benchmark_exit_code);
            return 1;
        }
    }

    /* STF Trace Generaetion
     * Close the trace at the end of simulation (assume core 0 for now)
     */
    if(m->common.stf_trace_open) {
        stf_trace_close(m, m->cpu_state[0]->last_pc);
    }

    fprintf(dromajo_stderr,
            "Simulation speed: %5.2f MIPS (single-core)\n",
            1e-6 * *execution_progress_meassure / (t - execution_start_ts));

    fprintf(dromajo_stderr, "\nPower off.\n");

    virt_machine_end(m);
#endif

#ifdef LIVECACHE
#if 0
    // LiveCache Dump
    uint64_t addr_size;
    uint64_t *addr = m->llc->traverse(addr_size);

    for (uint64_t i = 0u; i < addr_size; ++i) {
        printf("addr:%llx %s\n", (unsigned long long)addr[i], (addr[i] & 1) ? "ST" : "LD");
    }
#endif
    delete m->llc;
#endif

    return 0;
}
