# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Summary: redis tests
# - install redis and start redis-server
# - connect to redis client and perform few CRUD ops
# - load a test db from the data dir
# - start another redis instance with a different port
# - make new instance a replica of the earlier instance
#
# Maintainer: QE-Core <qe-core@suse.de>

use base 'consoletest';
use strict;
use warnings;
use testapi;
use serial_terminal 'select_serial_terminal';
use utils qw(zypper_call script_retry validate_script_output_retry);
use registration qw(add_suseconnect_product get_addon_fullname);

my $default_redis_version = "redis";
my @redis_versions = ($default_redis_version, "redis7");
my $default_redis_port = "6379";
my $default_redis_replica_port = "6380";
my $killall_redis_server_cmd = "killall redis-server";
my $remove_test_db_file_cmd = "rm -f movies.redis";

sub get_redis_version {
    my $output = script_output('redis-server --version');
    my $version = "";

    if ($output =~ /v=(.+?)\s/) {
        $version = $1;    # Capture the first match
    }

    die "Failed to extract Redis version!" if $version eq "";

    return $version;
}

sub test_ping {
    my (%args) = @_;
    $args{port} //= $default_redis_port;
    my $redis_cli_cmd = "redis-cli -p $args{port}";

    script_retry("$redis_cli_cmd ping", delay => 5, retry => 12);
    validate_script_output_retry("$redis_cli_cmd ping", sub { m/PONG/ }, delay => 5, retry => 12);
}

sub test_crud {
    my (%args) = @_;
    $args{port} //= $default_redis_port;
    my $redis_cli_cmd = "redis-cli -p $args{port}";

    # Perform CRUD operations
    validate_script_output("$redis_cli_cmd set foo bar", sub { m/OK/ });
    validate_script_output("$redis_cli_cmd get foo", sub { m/bar/ });
    validate_script_output("$redis_cli_cmd pfselftest", sub { m/OK/ });
    validate_script_output("$redis_cli_cmd flushdb", sub { m/OK/ });
    validate_script_output("$redis_cli_cmd get foo", sub { !m/bar/ });
}

sub load_test_db_and_validate {
    my (%args) = @_;
    $args{port} //= $default_redis_port;
    my $redis_cli_cmd = "redis-cli -p $args{port}";

    # Load test DB and validate data
    assert_script_run 'curl -O ' . data_url('console/movies.redis');
    assert_script_run("$redis_cli_cmd < ./movies.redis");
    validate_script_output("$redis_cli_cmd HMGET \"movie:343\" title", sub { m/Spider-Man/ });
}

sub verify_replication_status {
    my (%args) = @_;
    $args{port} //= $default_redis_port;
    $args{replica_port} //= $default_redis_replica_port;

    my $redis_cli_cmd = "redis-cli -p $args{port}";
    my $redis_replica_cli_cmd = "redis-cli -p $args{replica_port}";

    # Verify replication status
    validate_script_output_retry("$redis_cli_cmd info replication", sub { m/connected_slaves:1/ }, delay => 5, retry => 12);
    validate_script_output("$redis_replica_cli_cmd info replication", sub { m/role:slave/ });
    validate_script_output_retry("$redis_replica_cli_cmd info replication", sub { m/master_link_status:up/ }, delay => 5, retry => 12);
}

sub configure_and_test_master {
    my (%args) = @_;
    $args{port} //= $default_redis_port;

    test_ping(port => $args{port});
    test_crud(port => $args{port});
    load_test_db_and_validate(port => $args{port});
}

sub configure_and_test_replica {
    my (%args) = @_;
    $args{port} //= $default_redis_port;
    $args{replica_port} //= $default_redis_replica_port;

    my $redis_replica_cli_cmd = "redis-cli -p $args{replica_port}";

    test_ping(port => $args{replica_port});

    # Configure replication
    assert_script_run("$redis_replica_cli_cmd replicaof localhost $args{port}");

    verify_replication_status();

    # Validate data from the replica
    validate_script_output("$redis_replica_cli_cmd HMGET \"movie:343\" title", sub { m/Spider-Man/ });
}

sub cleanup_redis {
    my (%args) = @_;
    $args{redis_version} //= $default_redis_version;
    $args{port} //= $default_redis_port;
    $args{replica_port} //= $default_redis_replica_port;

    my $redis_cli_cmd_prefix = "redis-cli -p ";
    my $redis_cli_cmd_postfix = " flushall";

    my $redis_cli_cmd = $redis_cli_cmd_prefix . $args{port} . $redis_cli_cmd_postfix;
    my $redis_replica_cli_cmd = $redis_cli_cmd_prefix . $args{replica_port} . $redis_cli_cmd_postfix;

    # Clean up after testing
    assert_script_run($redis_cli_cmd);
    assert_script_run($redis_replica_cli_cmd);

    assert_script_run($killall_redis_server_cmd);
    assert_script_run($remove_test_db_file_cmd);
    assert_script_run("rm ./dump.rdb || true");
    zypper_call('rm -u ' . $args{redis_version});
}

sub log_location {
    my (%args) = @_;
    $args{redis_version} //= $default_redis_version;
    $args{port} //= $default_redis_port;
    my $logfile_prefix = "/var/log/redis/redis-server_" . $args{redis_version} . "_";
    my $logfile_postfix = ".log";

    return $logfile_prefix . $args{port} . $logfile_postfix;
}

sub upload_logs {
    my (%args) = @_;
    $args{redis_version} //= $default_redis_version;
    $args{port} //= $default_redis_port;
    $args{replica_port} //= $default_redis_replica_port;

    my $logfile = log_location(redis_version => $args{redis_version}, port => $args{port});
    my $replica_logfile = log_location(redis_version => $args{redis_version}, port => $args{replica_port});

    # Upload logs
    upload_logs($logfile) if -e $logfile;
    upload_logs($replica_logfile) if -e $replica_logfile;
}

sub test_redis {
    my (%args) = @_;
    $args{redis_version} //= $default_redis_version;
    $args{port} //= $default_redis_port;
    $args{replica_port} //= $default_redis_replica_port;

    zypper_call('in --force-resolution --solver-focus Update ' . $args{redis_version});

    my $version = get_redis_version();

    record_info("Testing " . $args{redis_version} . " v=" . $version);

    my $logfile = log_location(redis_version => $args{redis_version}, port => $args{port});
    my $replica_logfile = log_location(redis_version => $args{redis_version}, port => $args{replica_port});

    my $redis_server_cmd_prefix = "redis-server --daemonize yes --port ";
    my $redis_server_cmd = $redis_server_cmd_prefix . $args{port} . " --logfile " . $logfile;
    my $redis_server_replica_cmd = $redis_server_cmd_prefix . $args{replica_port} . " --logfile " . $replica_logfile;

    # Start the primary redis server
    assert_script_run($redis_server_cmd);
    configure_and_test_master(port => $args{port});


    # Start the replica redis server
    assert_script_run($redis_server_replica_cmd);
    configure_and_test_replica(port => $args{port}, replica_port => $args{replica_port});

    cleanup_redis(redis_version => $args{redis_version}, port => $args{port}, replica_port => $args{replica_port});

    upload_logs(redis_version => $args{redis_version}, port => $args{port}, replica_port => $args{replica_port});
}

sub run {
    my $self = shift;
    select_serial_terminal;

    foreach my $redis_version (@redis_versions) {
        test_redis(redis_version => $redis_version);
    }
}

sub post_fail_hook {
    my $self = shift;
    my $proceed_on_fail_cmd = " || true";
    script_run($killall_redis_server_cmd . $proceed_on_fail_cmd);
    script_run($remove_test_db_file_cmd . $proceed_on_fail_cmd);
    foreach my $redis_version (@redis_versions) {
        upload_logs(redis_version => $redis_version, port => $default_redis_port, replica_port => $default_redis_replica_port);
    }
    $self->SUPER::post_fail_hook;
}

sub post_run_hook {
    my $self = shift;
    $self->SUPER::post_run_hook;
}

1;
