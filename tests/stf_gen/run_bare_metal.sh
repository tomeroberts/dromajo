#! /bin/bash

# TODO: Test without no parameters
# TODO: Test --stf_priv_modes parameter

# Enabled tracepoint detection for testing
export OPT='--stf_tracepoint'

export DRO=../../build/dromajo

echo "clean previous traces"
mkdir -p traces
rm -f traces/*

echo "create/extract elf's"
cd elf
rm -f *.riscv
tar xf *.bz2

cd ..

echo "create the bare metal traces"
for i in illegal bmi_mm.bare bmi_towers.bare; do
  $DRO $OPT --stf_trace traces/$i.zstf  elf/$i.riscv
done

diffs=0

echo "compare to the golden traces"
for i in illegal bmi_mm.bare bmi_towers.bare; do
  diff traces/$i.zstf  golden/$i.zstf
  diffs=$(expr $diffs + $?)
done

echo "number of diffs = $diffs"
exit $diffs
