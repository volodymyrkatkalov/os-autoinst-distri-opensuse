# SUSE's openQA tests
#
# Copyright 2019 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: library functions for setting up the tests and uploading logs in error case.
# Maintainer: Thomas Blume <tblume@suse.com>


package systemd_testsuite_test;
use base "opensusebasetest";

use strict;
use warnings;
use known_bugs;
use testapi;
use Utils::Backends;
use Utils::Architectures;
use power_action_utils 'power_action';
use utils 'zypper_call';
use version_utils qw(is_opensuse is_sle is_tumbleweed);
use bootloader_setup qw(change_grub_config grub_mkconfig);
use Utils::Logging qw(save_and_upload_log tar_and_upload_log);

sub testsuiteinstall {
    my ($self) = @_;

    select_console 'root-console';

    if (is_sle('15+') && !main_common::is_updates_tests) {
        # add devel tools repo for SLE15 to install strace
        my $devel_repo = get_required_var('REPO_SLE_MODULE_DEVELOPMENT_TOOLS');
        zypper_call "ar -c $utils::OPENQA_FTP_URL/" . $devel_repo . " devel-repo";
    }

    zypper_call 'in strace';

    # Determine systemd version from installed package
    my $systemd_version = script_output("rpm -qa systemd | head -n 1 | sed -E 's/systemd-([0-9]+)\..*/\1/'");

    # Clone the systemd repository and checkout the specific tag
    assert_script_run "rm -rf /tmp/systemd && mkdir -p /tmp/systemd";
    assert_script_run "git clone https://github.com/systemd/systemd.git /tmp/systemd";
    assert_script_run "cd /tmp/systemd && git checkout v$systemd_version";
}

sub testsuiteprepare {
    my ($self, $testname, $option) = @_;
    #cleanup and prepare next test
    assert_script_run "find / -maxdepth 1 -type f -print0 | xargs -0 /bin/rm -f";
    assert_script_run 'find /etc/systemd/system/ -name "schedule.conf" -prune -o \( \! -name *~ -type f -print0 \) | xargs -0 /bin/rm -f';
    assert_script_run "find /etc/systemd/system/ -name 'end.service' -delete";
    assert_script_run "rm -rf /var/tmp/systemd-test*";
    assert_script_run "clear";
    assert_script_run "cd /tmp/systemd/test/units";
    assert_script_run "./run-tests.sh $testname --setup 2>&1 | tee /tmp/testsuite.log", 300;

    if ($option eq 'nspawn') {
        my $testservicepath = script_output "sed -n '/testservice=/s/root/nspawn-root/p' logs/$testname-setup.log";
        assert_script_run "ls -l \$\{testservicepath#testservice=\}";
    }
    else {
        #tests and versions that don't need a reboot
        return if ($testname eq 'TEST-18-FAILUREACTION' || $testname eq 'TEST-21-SYSUSERS' || is_sle('>15-SP2') || is_tumbleweed);

        assert_script_run 'ls -l /etc/systemd/system/testsuite.service';
        #virtual machines do a vm reset instead of reboot
        if (!is_qemu || ($option eq 'needreboot')) {
            wait_screen_change { enter_cmd "shutdown -r now" };
            if (is_s390x) {
                $self->wait_boot(bootloader_time => 180);
            }
            else {
                $self->handle_uefi_boot_disk_workaround if (is_aarch64);
                wait_serial('Welcome to', 300) || die "System did not boot in 300 seconds.";
            }
            wait_still_screen 10;
            assert_screen('linux-login', 30);
            reset_consoles;
            select_console('root-console');
        }
    }

    script_run "clear";
}

sub post_fail_hook {
    my ($self) = @_;
    #upload logs from given testname
    tar_and_upload_log('/tmp/systemd/test/units/logs', '/tmp/systemd_testsuite-logs.tar.bz2');
    tar_and_upload_log('/var/log/journal /run/log/journal', 'binary-journal-log.tar.bz2');
    save_and_upload_log('journalctl --no-pager -axb -o short-precise', 'journal.txt');
    upload_logs('/shutdown-log.txt', failok => 1);
}


1;
