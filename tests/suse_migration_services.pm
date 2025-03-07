# SUSE's openQA tests
#
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Test suse_migration_services
#
# Maintainer: QE C <qe-c@suse.de>
#
use base 'consoletest';
use strict;
use warnings;
use testapi;
use utils;
use registration;
use Config::Tiny;
use Test::Assert ':all';
use power_action_utils 'power_action';
use serial_terminal 'select_serial_terminal';
use Data::Dumper;

my $suse_migration_services_repo = get_var("SUSE_MIGRATION_SERVICES_REPO", "https://download.opensuse.org/repositories/home:/marcus.schaefer:/dms/SLE_12_SP5");
my $upgrade_expected_version = get_var("UPGRADE_EXPECTED_VERSION", "15-SP5");

sub extract_os_release {
    select_serial_terminal;

    my $os_release_output = script_output("cat /etc/os-release");
    my $config = Config::Tiny->read_string($os_release_output);
    record_info("cat /etc/os-release", "$os_release_output");

    my $name = $config->{_}->{NAME};
    my $version = $config->{_}->{VERSION};
    my $version_id = $config->{_}->{VERSION_ID};
    $name =~ s/"//g;
    $version =~ s/"//g;
    $version_id =~ s/"//g;

    my ($major_version, $minor_version) = split(/\./, $version_id);
    $minor_version //= 0;

    return {
        name => $name,
        version => $version,
        version_id => $version_id,
        major_version => $major_version,
        minor_version => $minor_version
    };
}

sub remove_scc_addons {
    select_serial_terminal;

    record_info("SUSEConnect --status", script_output("SUSEConnect --status"));
    record_info("SUSEConnect --list-extensions", script_output("SUSEConnect --list-extensions"));

    my @scc_addons_to_remove = split(/,/, get_var("SCC_ADDONS_TO_REMOVE", "sle-module-public-cloud/12/x86_64,SLES-LTSS/12.5/x86_64"));

    for my $addon (@scc_addons_to_remove) {
        # Parse the identifier: expected format is module/version/arch (e.g., sle-module-public-cloud/12/x86_64)
        if ($addon =~ /^(.+)\/([^\/]+)\/([^\/]+)$/) {
            my ($module_name, $version, $arch) = ($1, $2, $3);

            # Call remove_suseconnect_product with the parsed values
            remove_suseconnect_product(
                $module_name,
                $version,
                $arch
            );
        } else {
            record_info("Warning", "Invalid addon identifier format: $addon. Expected format: module/version/arch");
        }
    }
}

sub install_suse_migration_services {
    select_serial_terminal;

    my $os_release = extract_os_release();

    my $sms_repo_name = "Migration";

    zypper_call("ar $suse_migration_services_repo $sms_repo_name");
    zypper_call("--gpg-auto-import-keys ref");
    zypper_call("in suse-migration-sle15-activation");
    zypper_call("rr $sms_repo_name");
    remove_scc_addons();
}

sub validate_product_upgraded {
    my (%args) = @_;
    $args{previous_version} //= "";
    $args{expected_version} //= $upgrade_expected_version;

    select_serial_terminal;

    my $os_release = extract_os_release();

    assert_equals("SLES", $os_release->{name}, 'Wrong product NAME in /etc/os-release');
    assert_not_equals($args{previous_version}, $os_release->{version}, "Expected upgrade from $args{previous_version} to $args{expected_version}");
    assert_equals($args{expected_version}, $os_release->{version}, 'Wrong product VERSION in /etc/os-release');
    assert_not_equals($args{expected_version}, $os_release->{version}, 'Wrong product VERSION in /etc/os-release'); # TODO: remove, is test
}

sub run {
    my ($self) = @_;
    my $original_version = extract_os_release()->{version};

    install_suse_migration_services();

    power_action 'reboot';

    assert_screen("suse-migration-services-running", timeout => 300);
    assert_screen("grub2", timeout => 900);

    validate_product_upgraded(previous_version => $original_version, expected_version => $upgrade_expected_version);
}

1;
