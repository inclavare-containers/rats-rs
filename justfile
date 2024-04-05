default:
  just --list

run-in-occlum *args:
  cargo build --example spdm
  scripts/run_exe_in_occlum.sh target/debug/examples/spdm {{args}}

run-in-host *args:
  cargo build --example spdm
  target/debug/examples/spdm {{args}}
