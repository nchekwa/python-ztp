#!/bin/sh
serial_number=$(echo "show system information | display xml" | cli | grep serial-number | awk -F">" '{print $2}' | awk -F"<" '{print $1}')
family=$(echo "show system information | display xml" | cli | grep hardware-model | awk -F">" '{print $2}' | awk -F"<" '{print $1}' | awk -F"-" '{print $1}')

# Below function generates the initial configuration
#       user: root
#       password: Juniper123
#
#       user: napalm
#       password: NapalmJuniper123
#
# Generate own password:
# bash-> openssl passwd -6 -salt <salt> <text-password>
# Output format: # $6$somesalt$someveryverylongencryptedpasswd

generate_basic_config()
{
    # Below is the basic configuration common for Juniper
    cat <<EOF > /tmp/juniper.config
    system {
        host-name "Leaf-31";
        root-authentication {
            encrypted-password "\$6\$FeMUNElz\$simgBrbhenZVQ2JGGMRgtyYydjsAPf5cdZmK3KGSzV.kKGk9IC6PwSF246Kiqd1Zwl0NsCp.wBrWsdp2/5eTa/";
        }
        login {
            user napalm {
                uid 2000;
                class super-user;
                authentication {
                    encrypted-password "\$6\$fsh/wyMa\$ZdxtKAPru5xaYS0GjqXn3Ri.48xj4rAJ4vrYoTckCSFKA2/oWf3GqI8vLWzfYsX5JgBzBC5paFyRrSSpz2S4d1"; 
                }
            }
        }
        services {
            ssh {
                root-login allow;
            }
            telnet;
            netconf {
                ssh;
            }
        }
        syslog {
            user * {
                any emergency;
            }
            file messages {
                any notice;
                authorization info;
            }
            file interactive-commands {
                interactive-commands any;
            }
        }
        extensions {
            providers {
                juniper {
                    license-type juniper deployment-scope commercial;
                }
                chef {
                    license-type juniper deployment-scope commercial;
                }
            }
        }
        commit {
            factory-settings {
                reset-virtual-chassis-configuration;
                reset-chassis-lcd-menu;
            }
        }
    }
    chassis {
        auto-image-upgrade;
    }
    protocols {
        lldp {
            interface all;
        }
        igmp-snooping {
            vlan default;
        }
    }
    forwarding-options {
        storm-control-profiles default {
            all;
        }
    }
    interfaces {
        em0 {
            unit 0 {
                family inet {
                    address 10.240.40.31/22;
                }
            }
        }
    }
EOF
}

if [ "$family" = "vqfx" ]; then
cat <<EOF >> /tmp/juniper.config
    interfaces {
        protect: em1 {
            unit 0 {
                family inet {
                    address 169.254.0.2/24;
                }
            }
        }
    }
    commit {
        factory-settings {
            reset-virtual-chassis-configuration;
            reset-chassis-lcd-menu;
        }
    }
EOF
fi

add_dual_re_specific_config()
{
    # Dual RE case, add commit synchronize
    cat <<EOF >> /tmp/juniper.config
    system {
        commit synchronize;
    }
    chassis {
        redundancy {
            graceful-switchover;
        }
    }
    routing-options {
        nonstop-routing;
    }
    groups {
        re0 {
            system {
                host-name "Leaf-31";
            }
        }
        re1 {
            system {
                host-name "Leaf-31";
            }
        }
    }
    apply-groups [ re0 re1 ];

EOF
}

execute_script()
{
    cli <<EOF
    configure
    delete interface em0 unit 0 
    load merge /tmp/juniper.config relative
    commit and-quit
EOF
}

execute_script_re2()
{
    cli <<EOF
    configure
    delete interface em0 unit 0 
    load merge /tmp/juniper.config relative
    set groups re1 interfaces fxp0 disable
    commit synchronize and-quit
EOF
}

# Actual execution happens here

if [ "$family" = "mx" ]; then
    res=$(echo "show chassis routing-engine" | cli | grep "Routing Engine status" | wc -l | xargs)

    if [ "$res" = "2" ]; then
        # MX dual RE case only we will add the "commit synchronize"
        
        generate_basic_config
        add_dual_re_specific_config
        execute_script_re2
    else
        # MX with single RE

        generate_basic_config
        execute_script
    fi
else
    # Other than MX family

    generate_basic_config
    execute_script
fi