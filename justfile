set shell := ["bash", "-uc"]

default:
  just --list

prepare-repo-spdm:
  git submodule update --init --recursive
  cd deps/spdm-rs && sh_script/pre-build.sh

build:
  cargo build --package rats-rs
  cd rats-transport/ && cargo build --package rats-transport

build-c-api:
  cmake -Hc-api -Bbuild
  make -Cbuild all

build-example-spdm:
  cd rats-transport/ && cargo build --bin spdm

build-example-cert-app:
  cd examples/cert-app && rm -rf build && cmake -H. -Bbuild && make -Cbuild all

install-c-api:
  cmake -Hc-api -Bbuild
  make -Cbuild install

install-c-api-coco:
  cmake -Hc-api -Bbuild -DCOCO_ONLY=ON
  make -Cbuild install

run-in-occlum *args:
  cd rats-transport/ && cargo build --bin spdm
  scripts/run_exe_in_occlum.sh rats-transport/target/debug/spdm {{args}}

run-in-host *args:
  cd rats-transport/ && cargo build --bin spdm
  rats-transport/target/debug/spdm {{args}}

run-test-in-occlum *args:
  # for rats-cert
  cargo test --package rats-cert --no-run
  test_bin=`cargo test --package rats-cert --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && echo "unittests executable path: $test_bin" && scripts/run_exe_in_occlum.sh $test_bin {{args}}

  # for rats-transport
  cd rats-transport/ && cargo test --package rats-transport --no-run
  cd rats-transport/ && test_bin=`cargo test --package rats-transport --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && echo "unittests executable path: $test_bin" && cd .. && scripts/run_exe_in_occlum.sh rats-transport/$test_bin {{args}}

run-test-in-host *args:
  # for rats-cert
  cargo test --package rats-cert {{args}}
  # for rats-transport
  cd rats-transport/ && cargo test --package rats-transport {{args}}

code-coverage *args:
  # for rats-cert
  rm -rf ./target-sbcc
  RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-cert --target-dir ./target-sbcc --no-run
  set -x && test_bin=`RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-cert --target-dir ./target-sbcc --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && \
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

  # for rats-transport
  cd rats-transport/ && rm -rf ./target-sbcc
  cd rats-transport/ && RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-transport --target-dir ./target-sbcc --no-run
  cd rats-transport/ && set -x && test_bin=`RUSTFLAGS="-C instrument-coverage -Zcoverage-options=branch" cargo test --package rats-transport --target-dir ./target-sbcc --no-run 2>&1 | sed -n 's/.*Executable unittests [^(]* (\([^)]\+\).*/\1/p'` && \
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
