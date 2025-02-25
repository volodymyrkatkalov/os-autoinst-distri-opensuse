# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP

# Package: selinux-diag
# Summary: This test validates SELinux status and denial logging
# on a virtual machine in a supported cloud provider's
# infrastructure. It checks if SELinux is enabled and, if so,
# collects and uploads any denial logs for analysis.
#
# This test only contains minimal functionality that needs to be
# extended in future.
#
# Maintainer: qa-c team <qa-c@suse.de>

use Mojo::Base 'publiccloud::basetest';
use Test::Assert qw(assert_equals assert_not_equals);
use testapi;

sub is_selinux_enabled {
    my ($instance) = @_;

    # Get the kernel command line
    my $cmdline = script_output('cat /proc/cmdline');
    record_info('Cmdline', "Kernel cmdline: " . ($cmdline || 'not readable'));

    # Check if SELinux is explicitly disabled
    my $selinux_disabled = $cmdline && $cmdline =~ /selinux=0/;
    record_info('SELinux Disabled Check', "SELinux disabled (selinux=0): " . ($selinux_disabled ? 'yes' : 'no'));

    # Check if security=selinux is explicitly set
    my $security_selinux = $cmdline && $cmdline =~ /security=selinux/;
    record_info('Security Check', "security=selinux found: " . ($security_selinux ? 'yes' : 'no'));

    # Check if /sys/kernel/security/selinux directory exists
    my $selinux_dir_exists = script_run('stat /sys/kernel/security/selinux') == 0;
    record_info('SELinux Dir Check', "/sys/kernel/security/selinux exists: " . ($selinux_dir_exists ? 'yes' : 'no'));

    # SELinux is enabled if it's not disabled AND either the dir exists OR security=selinux is set
    my $is_enabled = !$selinux_disabled && ($selinux_dir_exists || $security_selinux);
    record_info('Result', "SELinux enabled: " . ($is_enabled ? 'yes' : 'no'));

    return $is_enabled;
}

sub upload_selinux_denials {
    my ($instance) = @_;

    # Try ausearch first if available, fall back to dmesg
    my $denials = script_output('command -v ausearch >/dev/null 2>&1 && sudo ausearch -m avc,user_avc,selinux_err,user_selinux_err -ts today --raw || dmesg | grep -i "selinux.*denied"');
    if ($denials && $denials !~ /^\s*$/) {    # Check if we got non-empty output
        my $log_file = "/tmp/selinux_denials_" . time() . ".log";
        assert_script_run("echo '$denials' > $log_file");
        upload_logs($log_file);
        return 1;
    }
    return 0;
}

sub run {
    my ($self, $args) = @_;
    my $instance = $args->{my_instance};
    my $provider = $args->{my_provider};

    upload_selinux_denials($instance) if is_selinux_enabled($instance);
}

sub test_flags {
    return {fatal => 1, publiccloud_multi_module => 1};
}

1;