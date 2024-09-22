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

Optionally, create a config file at `/etc/default/byedpi` with command line
arguments:

```sh
# Options to pass to `ciadpi`
BYEDPI_OPTS="--split 1 --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s"
```

You should see the service now marked as "active":
```sh
systemctl --user status byedpi.service
```
