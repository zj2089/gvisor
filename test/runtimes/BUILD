load("//test/runtimes:defs.bzl", "runtime_test")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["runner.go"],
    visibility = ["//test/runtimes:__pkg__"],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)

runtime_test(
    name = "go1.12",
    exclude_file = "test/runtimes/exclude/go1.12.csv",
    lang = "go",
    shard_count = 5,
)

runtime_test(
    name = "java11",
    exclude_file = "test/runtimes/exclude/java11.csv",
    lang = "java",
    shard_count = 5,
)

runtime_test(
    name = "nodejs12.4.0",
    exclude_file = "test/runtimes/exclude/nodejs12.4.0.csv",
    lang = "nodejs",
    shard_count = 5,
)

runtime_test(
    name = "php7.3.6",
    exclude_file = "test/runtimes/exclude/php7.3.6.csv",
    lang = "php",
    shard_count = 5,
)

runtime_test(
    name = "python3.7.3",
    exclude_file = "test/runtimes/exclude/python3.7.3.csv",
    lang = "python",
    shard_count = 5,
)
