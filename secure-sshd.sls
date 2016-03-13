## Install openssh-server package if it is not installed
## with version not less than 6.6

Openssh-Package:
  pkg.installed:
    - pkgs:
      - openssh-server: '>=6.5'

## Modify sshd-keygen service in order to generate
## only RSA and ED25519 Keys

Edit-sysconfig-sshd:
  file.replace:
    - name: /etc/sysconfig/sshd
    - pattern: 'AUTOCREATE_SERVER_KEYS="RSA ECDSA ED25519"'
    - repl: 'AUTOCREATE_SERVER_KEYS="RSA ED25519"'

## Delete ECDSA host keys

Delete-ECDSA-Keyfiles:
  file.absent:
    - names:
      - /etc/ssh/ssh_host_ecdsa_key
      - /etc/ssh/ssh_host_ecdsa_key.pub

# Filter out good moduli only. If paranoid, disable this section and enable the
# next two. Be warned however, generating moduli takes many hours!
Filter-Good-Moduli:
  cmd.run:
    - name: >
        awk '$5 > 2000' /etc/ssh/moduli > "/tmp/moduli";
        mv /tmp/moduli /etc/ssh/moduli
    - onlyif: awk '$5 < 2000' /etc/ssh/moduli | wc -l | grep -v -w 0
    ## Delete Moduli file if it has weak keys
    ## Then, generate good moduli file if absent

# Delete-bad-Moduli:
  #     file.absent:
    #       - name: /etc/ssh/moduli
    #       - onlyif: awk '$5 < 2000' /etc/ssh/moduli | wc -l | grep -v -w 0
    #
# Generate-Good-Moduli:
  #     cmd.run:
    #       - name: >
    #       ssh-keygen -G /etc/ssh/moduli.all -b 4096;
    #       ssh-keygen -T /etc/ssh/moduli.safe -f /etc/ssh/moduli.all;
    #       mv /etc/ssh/moduli.safe /etc/ssh/moduli;
    #       rm /etc/ssh/moduli.all
    #       - creates: /etc/ssh/moduli


## Modify the main config file and add KeyAlgorithms, Ciphers and MACs

Config-Changes:
  augeas.change:
    - lens: Sshd
    - context: /files/etc/ssh/sshd_config
  - changes:
    - set KexAlgorithms 'curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256'
    - set Ciphers 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    - set MACs/1  "hmac-sha2-512-etm@openssh.com"
    - set MACs/2  "hmac-sha2-256-etm@openssh.com"
    - set MACs/3  "hmac-ripemd160-etm@openssh.com"
    - set MACs/4  "umac-128-etm@openssh.com"
    - set MACs/5  "hmac-sha2-512"
    - set MACs/6  "hmac-sha2-256"
    - set MACs/7  "hmac-ripemd160"
    - set MACs/8  "umac-128@openssh.com"
    - rm HostKey
    - set HostKey[1] "/etc/ssh/ssh_host_ed25519_key"
    - set HostKey[2] "/etc/ssh/ssh_host_rsa_key"
  #  - onchanges_in:
    #       - file: Delete-bad-RSA-Key

## First deletes weak RSA key, second generates good one
## if RSA is absent, third sets the right permissions
## and mode.
## the 3 states will not be executed if there is no change
## in configuration file

Delete-bad-RSA-Key:
  file.absent:
    - names:
      - /etc/ssh/ssh_host_rsa_key.pub
      - /etc/ssh/ssh_host_rsa_key
      - onlyif: ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key| awk '$1 <  4096' | grep RSA

Generate-good-RSA-key:
  cmd.run:
    - name: ssh-keygen -t rsa -b 4096 -N '' -f /etc/ssh/ssh_host_rsa_key < /dev/null
    - creates: /etc/ssh/ssh_host_rsa_key

RSA-key-Permissions:
  file.managed:
    - name: /etc/ssh/ssh_host_rsa_key
    - user: root
    - group: root
    - mode: 600

## Restart sshd only if there is a change in configuration file

sshd-restart:
  module.run:
    - name: service.restart
    - m_name: sshd
  - onchanges:
    - augeas: Config-Changes

