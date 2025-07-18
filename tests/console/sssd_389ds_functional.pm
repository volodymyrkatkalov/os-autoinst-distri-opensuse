# Copyright 2021 SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Summary: sssd test with 389-ds as provider
#
# Set up 389-ds in container and run test cases below:
# 1. nss_sss test: look up user identity with id: uid and gid
# 2. pam_sss test: ssh login localhost as remote user.
# 3. write permission test: change remote user password with passwd
# 4. sssd-sudo test: Sudo run command as another remote user with sudoers rules defined in server
# 5. offline test: shutdown server, run test cases above again
#
# Detailed testcases: https://bugzilla.suse.com/tr_show_case.cgi?case_id=1768710
#
# Maintainer: Tony Yuan <tyuan@suse.com>

package sssd_389ds_functional;
use base 'consoletest';
use testapi;
use serial_terminal 'select_serial_terminal';
use strict;
use warnings;
use utils;
use version_utils;
use registration 'add_suseconnect_product';

sub run {
    select_serial_terminal;

    # Install runtime dependencies
    zypper_call("in sudo nscd") unless (is_tumbleweed || is_sle('>=16'));

    my $docker = "podman";
    if (is_sle('<16')) {
        $docker = "docker" if is_sle("<15-SP5");
        is_sle('<15') ? add_suseconnect_product("sle-module-containers", 12) : add_suseconnect_product("sle-module-containers");
    }
    zypper_call("in sssd sssd-ldap openldap2-client $docker");

    #For released sle versions use sle15sp4 base image by default. For developing sle use corresponding image in registry.suse.de
    my $pkgs = "awk systemd systemd-sysvinit 389-ds openssl";
    my $tag = "";
    if (is_opensuse) {
        $tag = (is_tumbleweed) ? "registry.opensuse.org/opensuse/tumbleweed" : "registry.opensuse.org/opensuse/leap";
    }
    else {
        # Use the latest SLE GA bci iamge, see https://progress.opensuse.org/issues/182780
        $tag = 'registry.suse.com/suse/sle15:15.7';
    }
    systemctl("enable --now $docker") if ($docker eq "docker");
    #build image, create container, setup 389-ds database and import testing data
    assert_script_run("mkdir /tmp/sssd && cd /tmp/sssd");

    my @artifacts = qw(
      user_389.ldif
      access.ldif
      instance_389.inf
      sssd.conf
      nsswitch.conf
      config
    );

    push(@artifacts, "Dockerfile_$docker");    # qw doesn't do interpolation.

    # Download all the artifacts to current dir, permissions will be handled by install commands below.
    my $data_url = sprintf("sssd/398-ds/{%s}", join(',', @artifacts));
    assert_script_run("curl --remote-name-all " . data_url($data_url));

    # The workaround can be removed once the bug is fixed
    # Or keep it if it is by design
    if (is_sle('>=16')) {
        record_info('bsc#1246214');
        script_run('rm -f /usr/share/containers/mounts.conf');
    }

    assert_script_run(qq($docker build -t ds389_image --build-arg tag="$tag" --build-arg pkgs="$pkgs" -f Dockerfile_$docker .), timeout => 600);

    # Cleanup the container in case a previous run did not cleanup properly, no need to assert
    script_run(qq($docker rm -f ds389_container));

    my $container_run_389_ds = "$docker run -itd --shm-size=256m --name ds389_container --hostname ldapserver";

    if ($docker eq "docker") {
        $container_run_389_ds .= " --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw --restart=always";
    }

    assert_script_run("$container_run_389_ds ds389_image");
    # wait up to 60 seconds for container running
    my $retries = 60;
    while ($retries--) {
        last if script_output("$docker inspect -f '{{.State.Running}}' ds389_container") =~ /true/;
        sleep 1;
    }
    die "Cannot start container" unless $retries;

    assert_script_run("$docker exec ds389_container chown dirsrv:dirsrv /var/lib/dirsrv");
    assert_script_run("$docker exec ds389_container sed -n '/ldapserver/p' /etc/hosts >> /etc/hosts");
    assert_script_run("$docker exec ds389_container dscreate from-file /tmp/instance_389.inf");
    assert_script_run('ldapadd -x -H ldap://ldapserver -D "cn=Directory Manager" -w opensuse -f user_389.ldif');
    assert_script_run('ldapadd -x -H ldap://ldapserver -D "cn=Directory Manager" -w opensuse -f access.ldif');

    # Configure sssd on the host side
    assert_script_run('mkdir -p /etc/sssd/');
    assert_script_run("$docker cp ds389_container:/etc/dirsrv/slapd-frist389/ca.crt /etc/sssd/ldapserver.crt");

    # nssswitch must be readable by all users
    assert_script_run("install --mode 0644 -D ./nsswitch.conf /etc/nsswitch.conf");
    assert_script_run("install --mode 0600 -D ./sssd.conf /etc/sssd/sssd.conf");
    assert_script_run("install --mode 0600 -D ./config ~/.ssh/config");

    systemctl("disable --now nscd.service") unless (is_sle('>=16') || is_tumbleweed);
    systemctl("enable --now sssd.service");

    #execute test cases
    #get remote user indentity
    validate_script_output("id alice", sub { m/uid=9998\(alice\)/ });
    #remote user authentification test
    assert_script_run("pam-config -a --sss --mkhomedir");

    select_console 'root-console';

    user_test();
    #Change password of remote user
    enter_cmd('ssh -oStrictHostKeyChecking=no alice@localhost', wait_still_screen => 5);
    enter_cmd('open5use', wait_still_screen => 5);
    enter_cmd('echo -e "open5use\nn0vell88\nn0vell88" | passwd', wait_still_screen => 1);
    enter_cmd('exit', wait_still_screen => 1);
    #verify password changed in remote 389-ds.
    validate_script_output('ldapwhoami -x -H ldap://ldapserver -D uid=alice,ou=users,dc=sssdtest,dc=com -w n0vell88', sub { m/alice/ });
    #Sudo run a command as another user
    assert_script_run("echo 'Defaults !targetpw' >/etc/sudoers.d/notargetpw");
    enter_cmd('ssh -oStrictHostKeyChecking=no mary@localhost', wait_still_screen => 5);
    enter_cmd('open5use', wait_still_screen => 5);
    enter_cmd('echo open5use|sudo -S -l > /tmp/sudouser', wait_still_screen => 1);
    enter_cmd('exit', wait_still_screen => 1);
    validate_script_output('cat /tmp/sudouser', sub { m#/usr/bin/cat# });
    assert_script_run(qq(su -c 'echo "file read only by owner alice" > hello && chmod 600 hello' -l alice));
    sudo_user_test();
    #Change back password of remote user
    enter_cmd('ssh -oStrictHostKeyChecking=no alice@localhost', wait_still_screen => 5);
    enter_cmd('n0vell88', wait_still_screen => 5);
    enter_cmd('echo -e "n0vell88\nopen5use\nopen5use" | passwd', wait_still_screen => 1);
    enter_cmd('exit', wait_still_screen => 1);
    enter_cmd('ssh -oStrictHostKeyChecking=no alice@localhost', wait_still_screen => 5);
    enter_cmd('open5use', wait_still_screen => 5);
    enter_cmd('echo "Password changed back!" > /tmp/passwdback', wait_still_screen => 1);
    enter_cmd('exit', wait_still_screen => 1);
    validate_script_output('cat /tmp/passwdback', sub { m/Password changed back/ });

    #offline identity lookup and authentification
    assert_script_run("$docker stop ds389_container");
    #offline cached remote user indentity lookup
    validate_script_output("id alice", sub { m/uid=9998\(alice\)/ });
    #offline remote user authentification test
    user_test();
    #offline sudo run a command as another user
    sudo_user_test();
}

sub user_test {
    enter_cmd('ssh -oStrictHostKeyChecking=no mary@localhost', wait_still_screen => 5);
    enter_cmd('open5use', wait_still_screen => 5);
    enter_cmd('whoami > /tmp/mary', wait_still_screen => 1);
    enter_cmd('exit', wait_still_screen => 1);
    validate_script_output('cat /tmp/mary', sub { m/mary/ });
}

sub sudo_user_test {
    enter_cmd('ssh -oStrictHostKeyChecking=no mary@localhost', wait_still_screen => 5);
    enter_cmd('open5use', wait_still_screen => 5);
    enter_cmd('echo open5use|sudo -S -u alice /usr/bin/cat /home/alice/hello > /tmp/readonly', wait_still_screen => 5);
    enter_cmd('exit', wait_still_screen => 1);
    validate_script_output('cat /tmp/readonly', sub { m/file read only by owner alice/ });
}
sub test_flags {
    return {always_rollback => 1};
}

1;
