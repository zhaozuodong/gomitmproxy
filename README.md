# gomitmproxy
实现中间人代理服务，支持http(s)/socks5协议代理服务，同时支持设置外部代理。
可将tls中间人解密body数据上传kafka等消息中间件。

## 参数
```
  -addr string
        host:port of the proxy (default ":8890")
  -allow-tls-urls string
        allow requests using tls protocol
  -auth-password string
        proxy auth password
  -auth-username string
        proxy auth username
  -cert string
        filepath to the CA certificate used to sign MITM certificates
  -downstream-proxy-url string
        URL of downstream proxy
  -generate-ca-cert
        generate CA certificate and private key for MITM
  -kafka-brokers string
        kafka brokers eg. localhost:9092,localhost:9092,localhost:9092
  -kafka-topic string
        kafka topic
  -key string
        filepath to the private key of the CA used to sign MITM certificates
  -organization string
        organization name for MITM certificates (default "Go Mitmproxy Proxy")
  -skip-tls-verify
        skip TLS server verification; insecure
  -socks-addr string
        socks5 proxy (default ":8892")
  -tls-addr string
        host:port of the proxy over TLS (default ":8891")
  -use-local-ca-cert
        use local CA certificate and private key for MITM (~/.config/gomitmproxy)
  -v int
        log level
  -validity duration
        window of time that MITM certificates are valid (default 1h0m0s)
```


## 开始
```
git clone https://github.com/zhaozuodong/gomitmproxy.git
cd gomitmproxy
go build -o gomitmproxy cmd/main.go
./gomitmporxy -v 1 -cert="your-cert-path" -key="your-cert-key-path" -auth-username="your auth username" -auth-password="your auth password" -downstream-proxy-url="your-external-Proxy"
```

