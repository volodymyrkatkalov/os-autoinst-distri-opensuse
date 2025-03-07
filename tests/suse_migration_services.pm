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


sub get_modules {
    select_serial_terminal;

    my $sc_list_output = script_output("SUSEConnect -l | sed -e 's/\\x1b\\[[0-9;]*m//g'", type_command => 1);
    record_info("Raw SUSEConnect -l Output", $sc_list_output);

    my @lines = split /\n/, $sc_list_output;

    my @filtered_lines;
    for my $line (@lines) {
        last if $line =~ /^REMARKS$/;
        next if $line =~ /^AVAILABLE EXTENSIONS AND MODULES$/;
        next if $line =~ /^\s*$/;
        $line =~ s/^\s+//;
        push @filtered_lines, $line;
    }

    my $processed_output = join("\n", @filtered_lines);

    my @products = ();

    for (my $i = 0; $i < @filtered_lines; $i += 2) {
        my $name_line = $filtered_lines[$i];
        my $command_line = $filtered_lines[$i + 1];

        my $current_product = {};

        if ($name_line =~ /^(.*\S)\s+\(Activated\)$/) {
            $current_product->{name} = $1;
            $current_product->{status} = "Activated";
        } elsif ($name_line =~ /^(.*\S)$/) {
            $current_product->{name} = $1;
            $current_product->{status} = "Not activated";
        }

        if ($command_line =~ /(?:Activate|Deactivate) with: suseconnect\s+-d?\s+-p\s+(\S+)/) {
            $current_product->{identifier} = $1;
            my ($module, $version, $arch) = split(/\//, $1);
            $current_product->{module} = $module;
            $current_product->{version} = $version;
            $current_product->{arch} = $arch;
        }

        push @products, $current_product if keys %$current_product;
    }

    record_info("Parsed Modules", Dumper(\@products));
    return \@products;
}

sub deactivate_modules {
    my (%args) = @_;
    $args{white_list} //= [];
    $args{black_list} //= ["SLES"];

    my $products = get_modules();

    my %white_list = map { $_ => 1 } @{$args{white_list}};
    my %black_list = map { $_ => 1 } @{$args{black_list}};

    foreach my $product (@$products) {
        my $module = $product->{module};
        my $version = $product->{version};
        my $arch = $product->{arch};
        my $identifier = $product->{identifier};

        next if exists $black_list{$module};

        if ($product->{status} eq "Activated") {
            # If white_list is empty, deactivate all except blacklisted
            # If white_list is populated, only deactivate those in white_list
            if (@{$args{white_list}} == 0 || exists $white_list{$module}) {
                record_info("Deactivating", "Deactivating product: $identifier");
                remove_suseconnect_product($module, $version, $arch);
            } else {
                record_info("Skipping (not in white_list)", "Skipping product: $identifier");
            }
        }
    }
}

sub install_suse_migration_services {
    select_serial_terminal;

    my $os_release = extract_os_release();

    my $sms_repo_name = "Migration";
    my $sms_python3_deps_module = "sle-module-public-cloud";
    my $arch = script_output("uname -m");

    add_suseconnect_product($sms_python3_deps_module, $os_release->{major_version}, $arch);
    zypper_call("ar $suse_migration_services_repo $sms_repo_name");
    zypper_call("--gpg-auto-import-keys ref");
    zypper_call("in suse-migration-sle15-activation");
    zypper_call("rr $sms_repo_name");
    # deactivate_modules(white_list => [$sms_python3_deps_module, "SLES-LTSS"]);
    deactivate_modules();
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
}

sub run {
    my ($self) = @_;
    my $original_version = extract_os_release()->{version};

    install_suse_migration_services();

    power_action 'reboot';

    assert_screen("suse-migration-services-running", timeout=>300);
    assert_screen("sles-boot", timeout=>900);

    validate_product_upgraded(previous_version => $original_version, expected_version => $upgrade_expected_version);
}

1;
