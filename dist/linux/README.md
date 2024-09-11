# Installing on Linux

## Building
```sh
cd byedpi/
make
sudo make install
```

## Systemd Service (optional)

Copy and enable the service:

```sh
cp byedpi.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable byedpi.service
systemctl --user start byedpi.service
```

You should see the service now marked as "active":
```sh
systemctl --user status byedpi.service
```
