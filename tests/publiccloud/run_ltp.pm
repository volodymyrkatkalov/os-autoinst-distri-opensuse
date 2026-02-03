# SUSE's openQA tests
#
# Copyright 2018-2025 SUSE LLC
# SPDX-License-Identifier: FSFAP

# Package: perl-base ltp
# Summary: Use perl script to run LTP on public cloud
#
# Maintainer: QE-C team <qa-c@suse.de>

use Mojo::Base 'publiccloud::basetest';
use testapi;
use utils;
use repo_tools 'generate_version';
use Mojo::File;
use Mojo::JSON;
use Mojo::UserAgent;
use LTP::utils qw(get_ltproot prepare_whitelist_environment);
use LTP::install qw(get_required_build_dependencies get_maybe_build_dependencies get_submodules_to_rebuild);
use LTP::WhiteList;
use publiccloud::utils;
use publiccloud::ssh_interactive 'select_host_console';
use JSON qw(decode_json);
use Data::Dumper;
use version_utils;
use Utils::Architectures qw(is_aarch64);

my $kirk_virtualenv = 'kirk-virtualenv';
our $root_dir = '/root';
our $ltp_timeout = get_var('LTP_TIMEOUT', 12600);

my $EC2_CW_LOGS = [
    {
        log_group => '/ec2/logs/messages',
        filename => 'ec2__logs__messages.log',
    },
    {
        log_group => '/ec2/logs/dmesg',
        filename => 'ec2__logs__dmesg.log',
    }
];

sub should_fully_build_ltp_from_git {
    return get_var('PUBLIC_CLOUD_LTP_GIT_FULL_BUILD', 0);    # 1 if env var is set, otherwise 0
}

sub should_partially_build_ltp_from_git {
    return get_var('PUBLIC_CLOUD_LTP_GIT_BUILD', 0);    # 1 if env var is set, otherwise 0
}

sub should_partially_build_ltp_from_git_modules_install {
    return get_var('PUBLIC_CLOUD_LTP_BUILD_MODULES', 0);    # 1 if env var is set, otherwise 0
}

sub install_build_deps {
    my ($self, $instance) = @_;

    zypper_call_remote($instance, cmd => "install --no-recommends " . join(' ', get_required_build_dependencies()));
    zypper_install_available_remote($instance);
}

sub prepare_ltp_git {
    my ($self, $instance, $ltp_dir, $ltp_prefix) = @_;

    my $repo_url = get_var('LTP_GIT_URL', 'https://github.com/linux-test-project/ltp');
    my $repo_branch = get_var('LTP_RELEASE', 'master');

    my $configure = "./configure --prefix=$ltp_prefix";
    my $extra_flags = get_var('LTP_EXTRA_CONF_FLAGS', '');

    my $ltp_build_timeout = 5 * 60;

    $instance->ssh_assert_script_run("rm -rf $ltp_dir");
    $instance->ssh_assert_script_run("git clone --depth 1 -b $repo_branch $repo_url $ltp_dir");
    $instance->ssh_assert_script_run(
        cmd => "cd $ltp_dir && make autotools && $configure $extra_flags",
        timeout => $ltp_build_timeout
    );
}

sub fully_build_ltp_from_git {
    my ($self, $instance, $ltp_dir, $ltp_prefix) = @_;

    my $start = time();
    my $ltp_build_timeout = 20 * 60;

    $self->install_build_deps($instance);
    $self->prepare_ltp_git($instance, $ltp_dir, $ltp_prefix);
    $instance->ssh_assert_script_run(
        cmd => "cd $ltp_dir && make -j\$(getconf _NPROCESSORS_ONLN) && sudo make install",
        timeout => $ltp_build_timeout
    );

    record_info("LTP Full Build Time", "Time taken to build from source: " . (time() - $start) . " seconds");
}

sub partially_build_ltp_from_git {
    my ($self, $instance, $ltp_dir, $ltp_prefix) = @_;

    my $start = time();
    my $ltp_subdir_build_timeout = 5 * 60;

    $self->install_build_deps($instance);
    $self->prepare_ltp_git($instance, $ltp_dir, $ltp_prefix);

    foreach my $subdir (get_submodules_to_rebuild()) {
        $instance->ssh_assert_script_run(
            cmd => "cd $ltp_dir/testcases/$subdir && make -j\$(getconf _NPROCESSORS_ONLN) && sudo make install",
            timeout => $ltp_subdir_build_timeout
        );
    }
    record_info("LTP Partial Build Time", "Time taken build from source: " . (time() - $start) . " seconds");
}

sub partially_build_ltp_from_git_modules_install {
    my ($self, $instance, $ltp_dir, $ltp_prefix) = @_;

    my $start = time();
    my $ltp_subdir_build_timeout = 5 * 60;

    $self->install_build_deps($instance);
    $self->prepare_ltp_git($instance, $ltp_dir, $ltp_prefix);
    $instance->ssh_assert_script_run(
        cmd => "sudo make -C $ltp_dir -j\$(getconf _NPROCESSORS_ONLN) modules-install",
        timeout => $ltp_subdir_build_timeout
    );
    record_info("LTP Partial Build Time", "Time taken build from source: " . (time() - $start) . " seconds");
}

sub get_ltp_rpm
{
    my ($url) = @_;
    my $ua = Mojo::UserAgent->new();
    my $links = $ua->get($url)->res->dom->find('a')->map(attr => 'href');
    for my $link (grep(/^ltp-20.*rpm$/, @{$links})) {
        return $link;
    }
    die('Could not find LTP package in ' . $url);
}

sub instance_log_args
{
    my ($provider, $instance) = @_;
    my $region = $provider->{provider_client}->region;
    $region .= "-" . $provider->{provider_client}->availability_zone if is_gce();

    return sprintf('"%s" "%s" "%s" "%s"',
        get_required_var('PUBLIC_CLOUD_PROVIDER'),
        $instance->instance_id,
        $instance->public_ip,
        $region);
}

sub upload_ltp_logs
{
    my $self = shift;
    my $ltp_testsuite = $self->{ltp_command};
    my @commands = split(/\s+/, $ltp_testsuite);
    my $log_file = Mojo::File::path('ulogs/results.json');

    record_info('LTP Logs', 'upload');
    upload_logs("/tmp/kirk.\$USER/latest/results.json", log_name => $log_file->basename, failok => 1);
    upload_logs("/tmp/kirk.\$USER/latest/debug.log", log_name => 'debug.txt', failok => 1);

    return unless -e $log_file->to_string;

    local @INC = ($ENV{OPENQA_LIBPATH} // testapi::OPENQA_LIBPATH, @INC);
    eval {
        require OpenQA::Parser::Format::LTP;

        my $ltp_log = Mojo::JSON::decode_json($log_file->slurp());
        my $parser = OpenQA::Parser::Format::LTP->new()->load($log_file->to_string);
        my %ltp_log_results = map { $_->{test_fqn} => $_->{test} } @{$ltp_log->{results}};
        my $whitelist = LTP::WhiteList->new();

        for my $result (@{$parser->results()}) {
            foreach my $command (@commands) {
                if ($whitelist->override_known_failures(
                        $self,
                        {%{$self->{ltp_env}}, retval => $ltp_log_results{$result->{test_fqn}}->{retval}},
                        $command,
                        $result->{test_fqn}
                )) {
                    $result->{result} = 'softfail';
                    last;
                }
            }
        }

        $parser->write_output(bmwqemu::result_dir());
        $parser->write_test_result(bmwqemu::result_dir());

        $parser->tests->each(sub {
                $autotest::current_test->register_extra_test_results([$_->to_openqa]);
        });
    };
    die $@ if $@;
}

sub dump_kernel_config
{
    my ($self, $instance) = @_;

    record_info("uname -a", $instance->ssh_script_output(cmd => "uname -a"));

    my $uname_r = $instance->ssh_script_output(cmd => "uname -r");
    chomp $uname_r;

    record_info("KERNEL CONFIG", $instance->ssh_script_output(cmd => "cat /boot/config-$uname_r"));
    record_info("ver_linux", $instance->ssh_script_output("/opt/ltp/ver_linux"));
}

sub disable_and_stop_ec2_cloudwatch_agent {
    my ($self, $instance) = @_;

    chomp(my $enabled = $instance->ssh_script_output(
            "sudo systemctl is-enabled amazon-cloudwatch-agent",
            proceed_on_failure => 1
    ));

    $instance->ssh_assert_script_run(
        "sudo systemctl disable --now amazon-cloudwatch-agent"
    ) if ($enabled eq "enabled");

    chomp(my $active = $instance->ssh_script_output(
            "sudo systemctl is-active amazon-cloudwatch-agent",
            proceed_on_failure => 1
    ));

    $instance->ssh_assert_script_run(
        "sudo systemctl stop amazon-cloudwatch-agent"
    ) if ($active eq "active");

    $instance->retry_ssh_command(
        cmd => "! sudo systemctl is-active amazon-cloudwatch-agent",
        timeout => 420,
        retry => 6,
        delay => 60
    );

    sleep 60;    # wait for CloudWatch agent to flush logs
}
sub download_ec2_cloudwatch_logs {
    my ($self, $instance) = @_;

    my $instance_id = $instance->instance_id;

    $self->disable_and_stop_ec2_cloudwatch_agent($instance);

    for my $entry (@$EC2_CW_LOGS) {

        my $log_group = $entry->{log_group};
        my $log_filename = $entry->{filename};
        my $log_stream = $instance_id;

        my $next_token;
        my $prev_token = "";

        # check if log stream exists first, if not skip to next log group
        my $describe_cmd =
          "aws logs describe-log-streams " .
          "--log-group-name '$log_group' " .
          "--log-stream-name-prefix '$log_stream' " .
          "--query 'logStreams[?logStreamName==`$log_stream`].logStreamName' " .
          "--output text";
        my $existing_log_stream = script_output($describe_cmd, timeout => 300, proceed_on_failure => 1);
        chomp $existing_log_stream;
        unless ($existing_log_stream && $existing_log_stream eq $log_stream) {
            record_info("EC2 CloudWatch Logs", "Log stream '$log_stream' does not exist in log group '$log_group'. Skipping download for this log group.");
            next;
        }

        # truncate file first
        assert_script_run(": > '$log_filename'");

        my $end_time = int(time() * 1000);

        while (1) {

            my $cmd =
              "aws logs get-log-events " .
              "--log-group-name '$log_group' " .
              "--log-stream-name '$log_stream' " .
              "--start-from-head ";

            $cmd .= "--next-token '$next_token' " if $next_token;

            # 1) append messages
            assert_script_run(
                "$cmd --end-time $end_time --query 'events[*].[timestamp,message]' --output text >> '$log_filename'",
                timeout => 300
            );

            # 2) fetch nextForwardToken only
            my $token_cmd =
              "$cmd --end-time $end_time --query 'nextForwardToken' --output text";

            my $new_token = script_output($token_cmd, timeout => 300);

            last if !$new_token || $new_token eq $prev_token;

            $prev_token = $new_token;
            $next_token = $new_token;
        }

        upload_logs($log_filename);

        # delete log stream + contents
        assert_script_run(
            "aws logs delete-log-stream " .
              "--log-group-name '$log_group' " .
              "--log-stream-name '$log_stream'"
        );
    }
}

sub install_dmesg_capture_to_log
{
    my ($self, $instance) = @_;

    my $dmesg_capture_service_filename = 'dmesg-capture.service';
    assert_script_run("curl " . data_url("publiccloud/$dmesg_capture_service_filename") . ' -o ' . $dmesg_capture_service_filename);
    $instance->scp($dmesg_capture_service_filename, 'remote:/tmp/' . $dmesg_capture_service_filename, 9999);
    $instance->ssh_assert_script_run("sudo mv /tmp/$dmesg_capture_service_filename /etc/systemd/system/");
    $instance->ssh_assert_script_run("sudo chown root:root /etc/systemd/system/$dmesg_capture_service_filename");
    $instance->ssh_assert_script_run("sudo chmod 644 /etc/systemd/system/$dmesg_capture_service_filename");

    $instance->ssh_assert_script_run(
        "sudo systemctl daemon-reload && " .
          "sudo systemctl enable --now $dmesg_capture_service_filename"
    );

    my $dmesg_capture_logrotate_filename = 'dmesg-capture-logrotate.conf';
    my $dmesg_capture_logrotate_target_filepath = '/etc/logrotate.d/dmesg';
    assert_script_run("curl " . data_url("publiccloud/$dmesg_capture_logrotate_filename") . ' -o ' . $dmesg_capture_logrotate_filename);
    $instance->scp($dmesg_capture_logrotate_filename, 'remote:/tmp/' . $dmesg_capture_logrotate_filename, 9999);
    $instance->ssh_assert_script_run("sudo mv /tmp/$dmesg_capture_logrotate_filename $dmesg_capture_logrotate_target_filepath");
    $instance->ssh_assert_script_run("sudo chown root:root $dmesg_capture_logrotate_target_filepath");
    $instance->ssh_assert_script_run("sudo chmod 644 $dmesg_capture_logrotate_target_filepath");
    $instance->ssh_assert_script_run("sudo logrotate -d $dmesg_capture_logrotate_target_filepath");
}

sub install_ec2_cloudwatch_agent
{
    my ($self, $instance) = @_;

    $self->install_dmesg_capture_to_log($instance);

    $instance->ssh_assert_script_run(
        "sudo mkdir -p /etc/systemd/journald.conf.d && " .
          "echo -e '[Journal]\\nStorage=persistent' | sudo tee /etc/systemd/journald.conf.d/persistent.conf && " .
          "sudo systemctl restart systemd-journald"
    );

    my $rpm_arch = "amd64";
    $rpm_arch = "arm64" if is_aarch64();

    my $rpm_url = "https://amazoncloudwatch-agent.s3.amazonaws.com/suse/" . $rpm_arch . "/latest/amazon-cloudwatch-agent.rpm";
    my $rpm_filename = "amazon-cloudwatch-agent.rpm";
    my $public_key = "https://amazoncloudwatch-agent.s3.amazonaws.com/assets/amazon-cloudwatch-agent.gpg";
    my $public_key_filename = "amazon-cloudwatch-agent.gpg";
    my $fingerprint = "9376 16F3 450B 7D80 6CBD 9725 D581 6730 3B78 9C72";
    my $fingerprint_merged = $fingerprint;
    $fingerprint_merged =~ s/\s+//g;

    $instance->ssh_assert_script_run("curl -L $public_key -o $public_key_filename");
    my $gpg_import_output = $instance->ssh_script_output("sudo gpg --import $public_key_filename");
    my $key_id = $gpg_import_output =~ /key\s+([0-9A-F]+):/ ? $1 : die("Failed to extract key ID from gpg output: " . $gpg_import_output);
    my $imported_fingerprint = $instance->ssh_script_output("sudo gpg --fingerprint --with-colons $key_id");
    die("Failed to import GPG key or fingerprint does not match expected value. Output: " . $imported_fingerprint) if ($imported_fingerprint !~ /$fingerprint_merged/);

    $instance->ssh_assert_script_run("curl -LO $rpm_url.sig");
    $instance->ssh_assert_script_run("curl -LO $rpm_url");

    my $verification_output = $instance->ssh_script_output("sudo gpg --verify $rpm_filename.sig $rpm_filename");
    die("RPM signature verification failed for $rpm_filename: " . $verification_output) if ($verification_output !~ /Good signature/);

    $instance->ssh_assert_script_run("sudo rpm -Uvh amazon-cloudwatch-agent.rpm");

    my $cloudwatch_config_filename = 'cloudwatch_config.json';
    assert_script_run("curl " . data_url('publiccloud/cloudwatch_config.json') . ' -o ' . $cloudwatch_config_filename);
    $instance->scp($cloudwatch_config_filename, 'remote:/tmp/' . $cloudwatch_config_filename, 9999);

    $instance->ssh_assert_script_run(cmd => "sudo mv /tmp/$cloudwatch_config_filename /opt/aws/amazon-cloudwatch-agent/etc/");

    $instance->ssh_assert_script_run(
        "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl " .
          "-a fetch-config " .
          "-m ec2 " .
          "-c file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch_config.json " .
          "-s"
    );

    $instance->ssh_assert_script_run(
        "sudo systemctl enable --now amazon-cloudwatch-agent"
    );

    record_info("EC2 CloudWatch Agent logs", $instance->ssh_script_output("sudo journalctl -u amazon-cloudwatch-agent -n 200"));

    record_info("EC2 CloudWatch Agent Status", $instance->ssh_script_output("sudo systemctl status amazon-cloudwatch-agent"));
    $instance->ssh_assert_script_run("sudo systemctl is-active amazon-cloudwatch-agent");
}

sub snapshot_ec2_serial_console
{
    my ($self, $instance) = @_;

    my $instance_id = $instance->instance_id;

    my $timestamp = time();
    my $output_file = "ec2__serial_console__${timestamp}.log";

    script_run("aws ec2 get-console-output --instance-id '$instance_id' --query Output --output text > '$output_file'", timeout => 300);
    upload_logs($output_file);
}

sub run {
    my ($self, $args) = @_;
    my $qam = get_var('PUBLIC_CLOUD_QAM', 0);
    my $arch = check_var('PUBLIC_CLOUD_ARCH', 'arm64') ? 'aarch64' : 'x86_64';
    my $ltp_pkg = get_var('LTP_PKG', 'ltp-stable');
    my $ltp_repo_name = "ltp_repo";
    my $ltp_repo_url = get_var('LTP_REPO', 'https://download.opensuse.org/repositories/benchmark:/ltp:/stable/' . generate_version("_") . '/');
    my $ltp_command = get_var('LTP_COMMAND_FILE', 'publiccloud');
    $self->{ltp_command} = $ltp_command;
    my @commands = split(/\s+/, $ltp_command);

    select_host_console();

    ($args->{my_provider}, $args->{my_instance}) = $self->prepare_instance($args);

    my $instance = $args->{my_instance};
    my $provider = $args->{my_provider};

    $self->prepare_scripts();
    $self->register_instance($instance, $qam);

    my $ltp_dir = '/tmp/ltp';
    my $ltp_prefix = '/opt/ltp';

    $self->install_ec2_cloudwatch_agent($instance) if (is_ec2());

    if (should_fully_build_ltp_from_git()) {
        $self->fully_build_ltp_from_git($instance, $ltp_dir, $ltp_prefix);
    } else {
        $self->install_ltp($instance, $ltp_repo_name, $ltp_repo_url, $ltp_pkg);
        $self->partially_build_ltp_from_git_modules_install($instance, $ltp_dir, $ltp_prefix) if should_partially_build_ltp_from_git_modules_install();
        $self->partially_build_ltp_from_git($instance, $ltp_dir, $ltp_prefix) if should_partially_build_ltp_from_git();
    }

    $self->gen_ltp_env($instance, $ltp_pkg);

    my $skip_tests = $self->prepare_skip_tests(\@commands);

    $self->prepare_kirk($instance);

    $self->printk_loglevel($instance);

    my $reset_cmd = $root_dir . '/restart_instance.sh ' . instance_log_args($provider, $instance);

    my $env = get_var('LTP_PC_RUNLTP_ENV');
    if (is_ec2()) {
        $self->snapshot_ec2_serial_console($instance);
    } else {
        my $log_start_cmd = $root_dir . '/log_instance.sh start ' . instance_log_args($provider, $instance);
        $self->prepare_logging($log_start_cmd);
    }

    my $cmd_run_ltp = $self->prepare_ltp_cmd($instance, $provider, $reset_cmd, $ltp_command, $skip_tests, $env);

    $self->dump_kernel_config($instance);
    record_info('LTP START', 'Command launch');
    $self->snapshot_ec2_serial_console($instance) if (is_ec2());
    # $ltp_timeout is also used for --suite-timeout so we need give kirk some time to try to kill itself before trying to kill it
    my $kirk_exit_code = script_run($cmd_run_ltp, timeout => $ltp_timeout + 60);
    record_info('LTP END', 'krik finished with ' . $kirk_exit_code);
    die('kirk failed') if ($kirk_exit_code);
}

sub prepare_instance {
    my ($self, $args) = @_;
    unless ($args->{my_provider} && $args->{my_instance}) {
        $args->{my_provider} = $self->provider_factory();
        $args->{my_instance} = $args->{my_provider}->create_instance();
        $args->{my_instance}->wait_for_guestregister() if (is_ondemand());
    }
    return ($args->{my_provider}, $args->{my_instance});
}

sub prepare_scripts {
    assert_script_run("cd $root_dir");
    assert_script_run('curl ' . data_url('publiccloud/restart_instance.sh') . ' -o restart_instance.sh');
    assert_script_run('curl ' . data_url('publiccloud/log_instance.sh') . ' -o log_instance.sh');
    assert_script_run('chmod +x restart_instance.sh');
    assert_script_run('chmod +x log_instance.sh');
}

sub register_instance {
    my ($self, $instance, $qam) = @_;
    registercloudguest($instance) if (is_byos() && !$qam);
    register_openstack($instance) if is_openstack;
}

sub install_ltp {
    my ($self, $instance, $ltp_repo_name, $ltp_repo_url, $ltp_package_name) = @_;

    zypper_add_repo_remote($instance, $ltp_repo_name, $ltp_repo_url);
    zypper_call_remote($instance, cmd => "install --no-recommends " . $ltp_package_name);
}

sub prepare_skip_tests {
    my ($self, $commands) = @_;
    my $ltp_exclude = get_var('LTP_COMMAND_EXCLUDE', '');
    # Use lib/LTP/WhiteList module to exclude tests
    my $issues = get_var('LTP_KNOWN_ISSUES', '');
    my $skip_tests;
    if ($issues) {
        my $whitelist = LTP::WhiteList->new($issues);
        my @skipped;
        foreach my $command (@$commands) {
            my @skipped_for_command = $whitelist->list_skipped_tests($self->{ltp_env}, $command);
            push @skipped, @skipped_for_command;
        }
        if (@skipped) {
            $skip_tests = '^(' . join("|", @skipped) . ')$';
            $skip_tests .= '|' . $ltp_exclude if $ltp_exclude;
        }
        record_info("Exclude", "Excluding tests: $skip_tests");
    } elsif ($ltp_exclude) {
        $skip_tests = $ltp_exclude;
        record_info("Exclude", "Excluding only 'LTP_COMMAND_EXCLUDE' tests: $skip_tests");
    } else {
        record_info("Exclude", "None");
    }
    return $skip_tests;
}

sub prepare_kirk {
    my ($self, $instance) = @_;
    my $kirk_repo = get_var("LTP_RUN_NG_REPO", "https://github.com/linux-test-project/kirk.git");
    my $kirk_branch = get_var("LTP_RUN_NG_BRANCH", "master");
    record_info('LTP RUNNER REPO', "Repo: " . $kirk_repo . "\nBranch: " . $kirk_branch);
    script_retry("git clone -q --single-branch -b $kirk_branch --depth 1 $kirk_repo", retry => 5, delay => 60, timeout => 300);
    $instance->ssh_assert_script_run(cmd => 'sudo CREATE_ENTRIES=1 ' . get_ltproot() . '/IDcheck.sh', timeout => 300);
    record_info('Kernel info', $instance->ssh_script_output(cmd => q(rpm -qa 'kernel*' --qf '%{NAME}\n' | sort | uniq | xargs rpm -qi)));
    if (get_var('PUBLIC_CLOUD_INSTANCE_TYPE') =~ /-metal$/) {
        record_info('VM type', $instance->ssh_script_output(cmd => '! systemd-detect-virt')) unless is_gce;
    } else {
        my $output = $instance->ssh_script_output(cmd => 'systemd-detect-virt', proceed_on_failure => 1);
        record_info('VM type', $output);

        if (($output eq "none") && is_gce && is_aarch64 && (is_sle_micro("=6.0") || is_sle_micro("=6.1"))) {
            record_soft_failure("bsc#1256376 - systemd-detect-virt none on GCE SLE Micro 6.0 aarch64") if is_sle_micro('=6.0');
            record_soft_failure("bsc#1256377 - systemd-detect-virt none on GCE SLE Micro 6.1 aarch64") if is_sle_micro('=6.1');
        } else {
            $instance->ssh_assert_script_run('systemd-detect-virt');
        }
    }
    assert_script_run("cd kirk");
    my $ghash = script_output("git rev-parse HEAD", proceed_on_failure => 1);
    set_var("LTP_RUN_NG_GIT_HASH", $ghash);
    record_info("KIRK_GIT_HASH", "$ghash");
    my $venv = install_in_venv($kirk_virtualenv, pip_packages => "asyncssh msgpack");
    venv_activate($venv);
}

sub printk_loglevel {
    my ($self, $instance) = @_;
    # this will print /all/ kernel messages to the console. So in case kernel panic we will have some data to analyse
    $instance->ssh_assert_script_run(cmd => "echo 1 | sudo tee /sys/module/printk/parameters/ignore_loglevel");
}

sub prepare_logging {
    my ($self, $log_start_cmd) = @_;
    assert_script_run($log_start_cmd);
}

sub prepare_ltp_cmd {
    my ($self, $instance, $provider, $reset_cmd, $ltp_command, $skip_tests, $env) = @_;
    my $exec_timeout = get_var('LTP_EXEC_TIMEOUT', 1200);

    my $sut = ':user=' . $instance->username;
    $sut .= ':sudo=1';
    $sut .= ':key_file=$(realpath ' . $instance->provider->ssh_key . ')';
    $sut .= ':host=' . $instance->public_ip;
    $sut .= ':reset_cmd=\'' . $reset_cmd . '\'';

    my $python_exec = get_python_exec();
    my $cmd = "$python_exec kirk ";
    $cmd .= '--verbose ';
    $cmd .= '--exec-timeout=' . $exec_timeout . ' ';
    $cmd .= '--suite-timeout=' . $ltp_timeout . ' ';
    $cmd .= '--run-suite ' . $ltp_command . ' ';
    $cmd .= '--skip-tests \'' . $skip_tests . '\' ' if $skip_tests;
    $cmd .= '--sut default:com=ssh ';
    $cmd .= '--com=ssh' . $sut . ' ';
    $cmd .= '--env ' . $env . ' ' if ($env);
    return $cmd;
}

sub cleanup {
    my ($self) = @_;

    # Ensure that the ltp script gets killed
    type_string('', terminate_with => 'ETX');
    $self->upload_ltp_logs();

    unless ($self->{run_args} && $self->{run_args}->{my_instance}) {
        die('cleanup: Either $self->{run_args} or $self->{run_args}->{my_instance} is not available. Maybe the test died before the instance has been created?');
    }

    if (is_ec2()) {
        $self->snapshot_ec2_serial_console($self->{run_args}->{my_instance});
        $self->download_ec2_cloudwatch_logs($self->{run_args}->{my_instance});
    }
    elsif (script_run("test -f $root_dir/log_instance.sh") == 0) {
        my $log_instance_stop_command = $root_dir . '/log_instance.sh stop ' . instance_log_args($self->{run_args}->{my_provider}, $self->{run_args}->{my_instance});
        script_run($log_instance_stop_command, timeout => 600);

        script_run("(cd /tmp/log_instance && tar -zcf $root_dir/instance_log.tar.gz *)");
        upload_logs("$root_dir/instance_log.tar.gz", failok => 1);
    }

    return 1;
}

sub gen_ltp_env {
    my ($self, $instance, $ltp_pkg) = @_;
    my $ltp_version = get_var('LTP_RELEASE', 'master');
    unless (should_partially_build_ltp_from_git() || should_fully_build_ltp_from_git()) {
        $ltp_version = $instance->ssh_script_output(cmd => qq(rpm -q --qf '%{VERSION}\n' $ltp_pkg));
    }
    $self->{ltp_env} = prepare_whitelist_environment();
    $self->{ltp_env}->{arch} = get_var('PUBLIC_CLOUD_ARCH', get_required_var("ARCH"));
    $self->{ltp_env}->{kernel} = $instance->ssh_script_output(cmd => 'uname -r');
    $self->{ltp_env}->{ltp_version} = $ltp_version;

    record_info("LTP Environment", Dumper($self->{ltp_env}));

    return $self->{ltp_env};
}

=head2 zypper_install_available_remote

zypper_install_available_remote($instance)

This function checks which packages from the provided list are available for installation on the remote instance.
If any packages are available, it installs them using zypper_call_remote.

=cut

sub zypper_install_available_remote {
    my ($instance) = @_;
    my $available = get_available_packages_remote($instance, [get_maybe_build_dependencies()]);
    return unless ($available && $available =~ /\S/);
    zypper_call_remote($instance, "install --no-recommends " . $available);
}

1;

=head1 Discussion

Test module to run LTP test on publiccloud. The test run on a local qemu instance
and connect to the CSP instance using SSH. This is done via the kirk.
