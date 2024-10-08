# Installing on Linux

## Building
```sh
cd byedpi/
make
sudo make install
```

## Systemd Service (optional)

You can configure the program to run as systemd service, user- or system-wide (only one at a time).

### As user service:

```sh
cp byedpi.service ~/.config/systemd/user/
cp byedpi.conf ~/.config/
systemctl --user enable --now byedpi.service
```

You should see the service now marked as "active":
```sh
systemctl --user status byedpi.service
```

### As system service:

```sh
sudo cp byedpi.service /etc/systemd/system/
sudo cp byedpi.conf /etc/
sudo systemctl enable --now byedpi.service
```

You should see the service now marked as "active":
```sh
systemctl status byedpi.service
```
