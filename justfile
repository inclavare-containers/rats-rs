default:
  just --list

run-in-occlum *args:
  cargo build --example spdm
  scripts/run_exe_in_occlum.sh target/debug/examples/spdm {{args}}

run-in-host *args:
  cargo build --example spdm
  target/debug/examples/spdm {{args}}

run-test-in-occlum *args:
  cargo test --no-run
  test_bin=`cargo test --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && echo "unittests executable path: $test_bin" && scripts/run_exe_in_occlum.sh $test_bin {{args}}

run-test-in-host *args:
  cargo test {{args}}
