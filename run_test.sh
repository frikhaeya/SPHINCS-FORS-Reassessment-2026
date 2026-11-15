#!/bin/sh
# Run a named reproduction step from this checkout, creating private local outputs.
set -eu
case "${1:-}" in
  3|4|5|6|7|8|9|10|11) step="$1" ;;
  *) echo "Usage: sh run_test.sh 3|4|5|6|7|8|9|10|11" >&2; exit 2;;
esac
case "$step" in
  3) f=step3_smoke_test.py;; 4) f=step4_public_fors_check.py;;
  5) f=step5_public_leakage_audit.py;; 6) f=step6_hidden_fors_probe.py;;
  7) f=step7_analyze_hidden_fors_leakage.py;; 8) f=step8_audit_fors_address_grouping.py;;
  9) f=step9_prf_partial_seed_test.py;; 10) f=step10_repeat_prf_partial_seed_test.py;;
  11) f=step11_vary_prefix_addresses.py;;
esac
exec python3 "scripts/$f"
