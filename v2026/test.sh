#!/usr/bin/env zsh

proxy_dir=${0:A:h}
workspace_root=${URNETWORK_ROOT:-${WARP_HOME:-${proxy_dir:h}}}
network_test_gate="$workspace_root/tests/network-intensive-suite-lock.sh"
if [[ ! -x "$network_test_gate" ]]; then
    echo "proxy test suite gate is missing or not executable: $network_test_gate" >&2
    exit 127
fi
if [[ "${URNETWORK_NETWORK_TEST_LOCK_HELD:-}" != 1 ]]; then
    exec "$network_test_gate" run-all run-all-proxy -- "$proxy_dir/test.sh" "$@"
fi
if ! "$network_test_gate" --verify-held run-all; then
    echo "proxy test suite inherited an invalid network-intensive lock" >&2
    exit 70
fi
cd "$proxy_dir" || exit $?

# A failed output filter is the causal pipeline status. Reporting only an
# upstream SIGPIPE would incorrectly attribute the failure to the test process.
test_pipeline_status() {
    local test_status="$1"
    local filter_status="$2"
    if [[ "$filter_status" != 0 ]]; then
        echo "test output filter failed with status $filter_status (upstream test status $test_status)" >&2
        return "$filter_status"
    fi
    return "$test_status"
}

for d in `find . -iname '*_test.go' | xargs -n 1 dirname | sort | uniq | paste -sd ' ' -`; do
    # if [[ $1 == "" || $1 == `basename $d` ]]; then
        pushd $d
        # highlight source files in this dir
        match="/$(basename $(pwd))/\\S*\.go\|^\\S*_test.go"
        GORACE="log_path=profile/race.out halt_on_error=1" go test -timeout 0 -v -race -cpuprofile profile/cpu -memprofile profile/memory "$@" | grep --binary-files=text --line-buffered --color=always -e "^" -e "$match"
        # -trace profile/trace -coverprofile profile/cover 
        pipeline_status=("${pipestatus[@]}")
        test_pipeline_status "${pipeline_status[1]}" "${pipeline_status[2]}" || exit $?
        popd
    # fi
done
# stdbuf -i0 -o0 -e0 

# to turn on logging e.g.
# go test -args -v 2 -logtostderr true

# go tool trace profile/trace
# PPROF_BINARY_PATH=. go tool pprof profile/cpu

# store default.pgo
# https://go.dev/doc/pgo
