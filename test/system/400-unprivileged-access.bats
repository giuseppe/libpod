#!/usr/bin/env bats   -*- bats -*-
#
# Tests #2730 - regular users are not able to read/write container storage
#

load helpers

@test "podman container storage is not accessible by unprivileged users" {
    skip_if_rootless "test meaningless without suid"

    run_podman run --name c_uidmap   --uidmap 0:10000:10000 $IMAGE true
    run_podman run --name c_uidmap_v --uidmap 0:10000:10000 -v foo:/foo $IMAGE true

    run_podman run --name c_mount $IMAGE \
               sh -c "echo hi > /myfile;mkdir -p /mydir/mysubdir; chmod 777 /myfile /mydir /mydir/mysubdir"

    run_podman mount c_mount
    mount_path=$output

    # Do all the work from within a test script. Since we'll be invoking it
    # as a user, the parent directory must be world-readable.
    test_script=$PODMAN_TMPDIR/fail-if-writable
    cat >$test_script <<"EOF"
#!/bin/sh

path="$1"

die() {
    echo "#/vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"  >&2
    echo "#| FAIL: $*"                                           >&2
    echo "#\\^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" >&2

    exit 1
}

parent=$(dirname "$path")
if chmod +w $parent; then
    die "Able to chmod $parent"
fi
if chmod +w "$path"; then
    die "Able to chmod $path"
fi

if [ -d "$path" ]; then
    if ls "$path" >/dev/null; then
        die "Able to run 'ls $path' without error"
    fi
    if echo hi >"$path"/test; then
        die "Able to write to file under $path"
    fi
else
    # Plain file
    if cat "$path" >/dev/null; then
        die "Able to read $path"
    fi
    if echo hi >"$path"; then
        die "Able to write to $path"
    fi
fi

exit 0
EOF
    chmod 755 $PODMAN_TMPDIR $test_script

    # get podman image and container storage directories
    run_podman info --format '{{.store.GraphRoot}}'
    GRAPH_ROOT="$output"
    run_podman info --format '{{.store.RunRoot}}'
    RUN_ROOT="$output"

    # The main test: find all world-writable files or directories underneath
    # container storage, run the test script as a nonroot user, and try to
    # access each path.
    find $GRAPH_ROOT $RUN_ROOT \! -type l -perm -o+w -print | while read i; do
        dprint " o+w: $i"

        # use chroot because su fails if uid/gid don't exist or have no shell
        # For development: test all this by removing the "--userspec x:x"
        chroot --userspec 1000:1000 / $test_script "$i"
    done

    # Done. Clean up.
    rm -f $test_script

    run_podman umount c_mount
    run_podman rm c_mount

    # FIXME: without pr2730, this consistently fails with:
    #  Error: error removing userns root "/run/libpod/containers-root/b654794be6262c8d7f8f4e32b1afbf5734818e45abd6f331311b7e4accf01643": remove /run/libpod/containers-root/b654794be6262c8d7f8f4e32b1afbf5734818e45abd6f331311b7e4accf01643/shm: device or resource busy
    # FIXME: with this pr, it works. Is that a deliberate fix in 2730?
    run_podman rm c_uidmap c_uidmap_v
}

# vim: filetype=sh
