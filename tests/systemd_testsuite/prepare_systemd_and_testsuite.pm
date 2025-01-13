# SUSE's openQA tests
#
# Copyright 2020 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Prepare systemd and testsuite.
#
# This module works as a 'loader' for the actual systemd-testsuite testcases.
# - Clone systemd repo from GitHub and checkout the tag matching the installed systemd version
# - For each test in the upstream testsuite, filter out those mentioned in the variable SYSTEMD_EXCLUDE
# - For all others, schedule a new openQA testmodule: i.e. loadtest(runner.pm) passing a different name every time
# - When this module ends, the single tests of the systemd testsuite are being executed by openQA as independent test modules.
#
# Maintainer: qe-core@suse.com, Thomas Blume <tblume@suse.com>

use Mojo::Base qw(systemd_testsuite_test);
use testapi;
use serial_terminal 'select_serial_terminal';
use utils;
use version_utils qw(is_sle);
use registration qw(add_suseconnect_product get_addon_fullname is_phub_ready);

sub run {
    my $test_opts = {
        NO_BUILD => get_var('SYSTEMD_NO_BUILD', 1),
        TEST_PREFER_NSPAWN => get_var('SYSTEMD_NSPAWN', 1),
        UNIFIED_CGROUP_HIERARCHY => get_var('SYSTEMD_UNIFIED_CGROUP', 'yes')
    };
    my @pkgs = qw(
      lz4
      busybox
      qemu
      dhcp-client
      python3
      plymouth
      binutils
      netcat-openbsd
      cryptsetup
      less
      device-mapper
      strace
      e2fsprogs
      hostname
      net-tools-deprecated
      git
    );

    select_serial_terminal();
    # Package requires PackageHub is available
    return if (!is_phub_ready() && is_sle);

    if (is_sle) {
        add_suseconnect_product(get_addon_fullname('legacy'));
        add_suseconnect_product(get_addon_fullname('desktop'));
        add_suseconnect_product(get_addon_fullname('sdk'));
        add_suseconnect_product(get_addon_fullname('phub'));
        add_suseconnect_product(get_addon_fullname('python3'));
    }

    # Install dependencies
    zypper_call('ref');
    zypper_call("in @pkgs");

    # Determine systemd version and fetch appropriate tag
    my $systemd_version = script_output("rpm -qa systemd | head -n 1 | sed -r 's/systemd-([0-9]+).*/\\1/'");
    my $systemd_tag = "v" . $systemd_version;

    # Clone systemd repository and checkout the respective tag
    assert_script_run "cd /tmp && git clone --depth 1 https://github.com/systemd/systemd.git";
    assert_script_run "cd /tmp/systemd && git fetch --depth=1 origin tag $systemd_tag && git checkout tags/$systemd_tag";

    # Navigate to test case directory and extract all available test cases

    my @schedule = ();
    my $exclude = get_var('SYSTEMD_EXCLUDE');
    my $include = get_var('SYSTEMD_INCLUDE');

    if ($include) {
        record_info("SYSTEMD_INCLUDE defined, populating schedule based on it");
        @schedule = split(',', $include);
    } else {
        record_info('ls -l', script_output(qq(ls -l /tmp/systemd/test/units/)));
        record_info('find', script_output(qq(find /tmp/systemd/test/units/ -maxdepth 1 -regex '.*/testsuite-[0-9]+\\.sh\$' -o -regex '.*/TEST-[0-9]+\\.sh\$')));
        my @tests = split(/\n/, script_output(qq(find /tmp/systemd/test/units/ -maxdepth 1 -regex '.*/testsuite-[0-9]+\\.sh\$' -o -regex '.*/TEST-[0-9]+\\.sh\$')));
        foreach my $test (@tests) {
            if (defined($exclude) && $test =~ m/$exclude/) {
                next;
            }
            push @schedule, $test;
        }
    }

    record_info('Scheduled Tests', join(', ', @schedule));

    # Execute generic openQA's systemd runner for each test case directory found
    foreach my $test (@schedule) {
        record_info("Test: $test", script_output("/bin/bash $test", timeout => 1800, type_command => 1, proceed_on_failure => 1));
    }
}

sub test_flags {
    return {milestone => 1, fatal => 1};
}

1;
