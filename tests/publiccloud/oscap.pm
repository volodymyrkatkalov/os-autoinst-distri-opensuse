# SUSE's openQA tests
#
# Copyright 2021 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Summary: Run basic smoketest on publiccloud test instance
# Maintainer: QE-C team <qa-c@suse.de>

use base 'consoletest';
use testapi;
use serial_terminal 'select_serial_terminal';
use utils;
use version_utils;

my $required_packages = ['openscap-utils', 'scap-security-guide'];

sub display_oscap_information {
    my ($self, $f_ssg_ds) = @_;
    #Displays OSCAP packages information
    # Record the pkgs' version for reference
    my $out = script_output("zypper se -si " . join(' ', @$required_packages));
    record_info("Pkg_ver", "openscap security guide packages' version:\n $out");
    # Check the ds file information for reference
    $out = script_output("oscap info $f_ssg_ds", quiet => 1);
    record_info("oscap info", "\"# oscap info $f_ssg_ds\" returns:\n $out");
    # Check the oscap version information for reference
    $out = script_output("oscap -V");
    record_info("oscap version", "\"# oscap -V\" returns:\n $out");
}

sub download_scap_content {
    my ($self, $oscap_dir, $xml_remote_file) = @_;

    # Extract filename and replace / with -
    (my $xml_file = $xml_remote_file) =~ s|.*/||;
    $xml_file =~ s/\//-/g;

    my $gz_url = "$xml_remote_file.gz";

    assert_script_run("mkdir -p $oscap_dir");

    assert_script_run(
        "curl -s $gz_url | gunzip -c > $oscap_dir/$xml_file"
    );

    record_info("SCAP download", "Downloaded OVAL file to $oscap_dir/$xml_file");
}

sub generate_scap_report {
    my ($self, $oscap_dir, $f_ssg_ds, $oscap_profile, $scap_report) = @_;

    my $report_arg = "";

    if ($scap_report && $scap_report ne "skip") {
        $report_arg = "--report $scap_report";
    }

    my $cmd = "oscap xccdf eval $report_arg --local-files $oscap_dir --profile $oscap_profile $f_ssg_ds";

    record_info("Running OSCAP", $cmd);
    my $ret = script_run($cmd, timeout => 1800);

    if ($ret != 0) {
        record_info("OSCAP failed", "Return code: $ret");
        die "oscap evaluation failed";
    }

    record_info("OSCAP success", "Report generated successfully");

    if ($scap_report && $scap_report ne "skip") {
        upload_logs($scap_report);
    }
}

sub run_tests_for_unhardened {
    my ($self, $instance, $f_ssg_ds, $xml_remote_file, $scap_report) = @_;

    $instance->zypper_call_remote("in " . join(' ', @$required_packages));
    $self->display_oscap_information($f_ssg_ds);

    my $oscap_dir = "/tmp/oscap";
    assert_script_run "mkdir -p $oscap_dir";
    my $oscap_profile = is_sles4sap() ? "pcs-hardening-sap" : "pcs-hardening";

    $self->download_scap_content($oscap_dir, $xml_remote_file);
    $self->generate_scap_report($oscap_dir, $f_ssg_ds, $oscap_profile, $scap_report);
}

sub run {
    my ($self, $args) = @_;

    my $instance = $args->{my_instance};

    select_serial_terminal;

    my $remote = $instance->username . '@' . $instance->public_ip;
    my ($version, $sp, $host_distri) = get_os_release;
    my $f_ssg_ds = "/usr/share/xml/scap/ssg/content/ssg-sle" . $version . "-ds.xml";
    my $xml_remote_file = "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise." . $version . ".xml";
    my $scap_report = get_var('SCAP_REPORT', 'skip');

    $self->run_tests_for_unhardened($instance, $f_ssg_ds, $xml_remote_file, $scap_report);
}

1;
