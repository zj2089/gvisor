# VM Images & Tests

All commands in this directory require the `gcloud` project to be set.

For example: `gcloud config set project gvisor-kokoro-testing`.

Images can be generated by using the `vm_image` rule. This rule will generate a
binary target that builds an image in an idempotent way, and can be referenced
from other rules.

For example:

```
vm_image(
    name = "ubuntu",
    project = "ubuntu-1604-lts",
    family = "ubuntu-os-cloud",
    scripts = [
        "script.sh",
        "other.sh",
    ],
)
```

These images can be built manually by executing the target. The output on
`stdout` will be the image id (in the current project).

For example:

```
$ bazel build :ubuntu
```

Images are always named per the hash of all the hermetic input scripts. This
allows images to be memoized quickly and easily.

The `vm_test` rule can be used to execute a command remotely. This is still
under development however, and will likely change over time.

For example:

```
vm_test(
    name = "mycommand",
    image = ":ubuntu",
    targets = [":test"],
)
```
