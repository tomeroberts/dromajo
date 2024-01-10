.PHONY: default clean run unpack pack check
SHELL=/bin/bash

DRO=../../build/dromajo

#change comment to not use stf_no_priv_check

OPT='--stf_no_priv_check'
#export OPT

bm_elfs = illegal bmi_mm.bare bmi_towers.bare

default: unpack run check

run:
	@echo "Generating traces"
	mkdir -p traces
	for i in $(bm_elfs); do \
		$(DRO) $(OPT) --stf_trace traces/$$i.stf  elf/$$i.riscv; \
	done

check:
	@echo "Checking traces"
	@for i in $(bm_elfs); do \
		diff traces/$$i.stf golden/$$i.stf; \
	done;
	@echo "Checks complete"

unpack:
	cd elf;    tar xf *.bz2
	cd golden; tar xf *.bz2

pack:
	cd elf; tar jcvf elf.bz2 *.riscv
	cd golden; tar jcvf golden.bz2 *.stf
	$(MAKE) clean

clean:
	-rm -f traces/*.stf elf/*.riscv golden/*.stf
