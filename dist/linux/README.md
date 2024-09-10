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
cp byedpi.service /etc/systemd/system/byedpi.service
sudo systemctl daemon-reload
sudo systemctl enable byedpi.service
sudo systemctl start byedpi.service
```

You should see the service now marked as "active":
```sh
sudo systemctl status byedpi.service
```