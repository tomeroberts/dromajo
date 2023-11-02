# Summary

Simple verification of uncompressed stf trace generation with known good traces.

Assumes dromajo has been built and present in ../../build

# Bare metal checks
Creates stf's from bare metal elfs and compares uncompressed traces to golden references

If your dromajo does not support --stf_no_priv_check modify the
run_bare_metal.sh 

# Usage for bare metal checks
```
bash run_bare_metal.sh
```
