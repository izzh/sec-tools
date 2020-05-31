#!/bin/bash

function determin_docker_runtime()
{
    # echo "1. cat /proc/1/cgroup | grep '/docker/'"
    cgroup_info=$(cat /proc/1/cgroup | grep '/docker/' | grep -v grep | head -1)
    if [ -n "$cgroup_info" ]; then
        echo "(/proc/1/cgroup)========>find docker tag:$cgroup_info"
    fi
    # echo "2. cat /proc/1/cgroup | grep '/docker/'"
    cpuset_info=$(cat /proc/1/cpuset | grep '/docker/' | grep -v grep | head -1)
    if [ -n "$cpuset_info" ]; then
        echo "(/proc/1/cpuset)========>find docker tag:$cpuset_info"
    fi
    # echo "3. cat /proc/1/sched | head -1"
    sched_info=$(cat /proc/1/sched | head -1)
    x=$(echo $sched_info | grep '1, #threads: 1' | grep -v grep)
    if [ -z "$x" ]; then
        echo "(/proc/1/sched )========>find differ pid:$sched_info"
    fi
    # echo "4. [ -f /.dockerenv ]"
    if [ -f "/.dockerenv" ]; then
        echo "([ -f /.dockerenv ])====>/.dockerenv exist."
    fi
}

determin_docker_runtime