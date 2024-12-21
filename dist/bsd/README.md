# Installing on BSD

Tested on FreeBSD 14.1 and DrafonFly BSD 6.4

## Building
```sh
cd byedpi/
make
sudo make install
```

## System Service

You can configure the program to run as system service.

### As system service:

```sh
sudo cp byedpi /usr/local/etc/init.d
sudo sysrc byedpi_enable="YES"
```

You should see the service now marked as "active":
```sh
sudo service byedpi status
```
