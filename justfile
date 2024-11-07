set shell := ["bash", "-uc"]

default:
  just --list

prepare-repo-spdm:
  git submodule update --init --recursive
  cd deps/spdm-rs && sh_script/pre-build.sh


install-c-api:
  cmake -Hc-api -Bbuild
  make -Cbuild install

install-c-api-coco:
  cmake -Hc-api -Bbuild -DCOCO_ONLY=ON
  make -Cbuild install

run-in-occlum *args:
  cargo build --bin spdm
  scripts/run_exe_in_occlum.sh target/debug/spdm {{args}}

run-in-host *args:
  cargo build --bin spdm
  target/debug/spdm {{args}}

run-test-in-occlum *args:
  cargo test --package rats-rs --no-run
  test_bin=`cargo test --package rats-rs --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && echo "unittests executable path: $test_bin" && scripts/run_exe_in_occlum.sh $test_bin {{args}}

run-test-in-host *args:
  cargo test --package rats-rs {{args}}

code-coverage *args:
  rm -rf ./target-sbcc
  RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-rs --target-dir ./target-sbcc --no-run
  set -x && test_bin=`RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-rs --target-dir ./target-sbcc --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && \
    echo "unittests executable path: $test_bin" && \
    rm -rf ./target-sbcc/coverage/ && mkdir -p ./target-sbcc/coverage/ && \
    LLVM_PROFILE_FILE='./target-sbcc/coverage/cargo-test-host-%p-%m.profraw' $test_bin {{args}} && \
    LLVM_PROFILE_FILE='/coverage/cargo-test-occlum-%p-%m.profraw' COVERAGE_DIR=`realpath ./target-sbcc/coverage/` scripts/run_exe_in_occlum.sh $test_bin {{args}} && \
    echo "Collect coverage info for $test_bin from: " && ls -la ./target-sbcc/coverage/*.profraw && \
      $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata merge -sparse ./target-sbcc/coverage/*.profraw -o ./target-sbcc/coverage/default.profdata && \
    echo "Generate coverage details html at ./target-sbcc/coverage/www" && mkdir -p ./target-sbcc/coverage/www && \
      $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show -Xdemangler=rustfilt $test_bin -instr-profile=./target-sbcc/coverage/default.profdata --sources . --ignore-filename-regex='deps/*' --show-branches=count --format=html -output-dir=./target-sbcc/coverage/www && \
    echo "Generate coverage report" && \
      $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov report -Xdemangler=rustfilt $test_bin -instr-profile=./target-sbcc/coverage/default.profdata --sources . --ignore-filename-regex='deps/*'
