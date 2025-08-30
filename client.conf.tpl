[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {{.ServerPublicKey}}
Endpoint = {{.ServerIP}}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
