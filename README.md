# What is it
Salt recipe to automatically secure sshd hard enough to piss off the NSA!

# Installation
This salt recipe only supports rhel/centos 7 style operating systems. Pull requests to support more OSs are welcome. The reason for not supporting older rhel OSs, is that sshd version 6.5 or better is required

## Install SaltStack
```
yum install -y epel-release
yum install -y salt-minion python-augeas
```

## Clone the repo
```
cd /tmp && git clone https://github.com/cloud9ers/secure-sshd-salt.git
mkdir -p /srv/salt/
cp secure-sshd-salt/secure-sshd-salt.sls /srv/salt
```
## Run it
The following is just one way to run this salt state. I recommend doing it this way, because this mode of operation does not need a salt master (server). If however, you are already running a salt master server, feel free to integrate with your other states
```
salt-call --local state.sls ssh
```

Note: Pull requests to support other operating systems are very welcome, as are PRs to improve the implementation. Use this at your own risk. It has not been meticulously tested.

## Credits
Credits for the original work to improve sshd configuration security is due to  https://stribika.github.io/2015/01/04/secure-secure-shell.html
