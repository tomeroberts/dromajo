#! /bin/bash

#change comment to not use stf_no_priv_check
export OPT='--stf_no_priv_check'
#export OPT

export DRO=../../build/dromajo

echo "clean previous traces"
mkdir -p traces
rm -f traces/*

echo "create/extract elf's"
cd elf
rm -f *.riscv
tar xf *.bz2

# clean /extract reference stf's
cd ../golden
rm -f golden/*.stf
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
