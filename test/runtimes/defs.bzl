"""Defines a rule for runtime test targets."""

load("//tools:defs.bzl", "go_test")

def runtime_test(name, lang, exclude_file, **kwargs):
    go_test(
        name = name,
        srcs = ["runner.go"],
        args = [
            "--lang",
            lang,
            "--image",
            name,  # Resolved as images/runtimes/%s.
            "--exclude_file",
            exclude_file,
        ],
        data = [
            "//test/runtimes/proctor",
        ] + native.glob(["exclude/**"]),
        defines_main = 1,
        tags = [
            "local",
            "manual",
        ],
        deps = [
            "//pkg/log",
            "//pkg/test/dockerutil",
            "//pkg/test/testutil",
        ],
        **kwargs
    )
