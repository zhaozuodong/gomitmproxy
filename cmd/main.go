package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/zhaozuodong/gomitmproxy"
	mlog "github.com/zhaozuodong/gomitmproxy/log"
	"github.com/zhaozuodong/gomitmproxy/middlewares"
	"github.com/zhaozuodong/gomitmproxy/mitm"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

var (
	addr          = flag.String("addr", ":8890", "host:port of the proxy")
	tlsAddr       = flag.String("tls-addr", ":8891", "host:port of the proxy over TLS")
	socksAddr     = flag.String("socks-addr", ":8892", "socks5 proxy")
	authUsername  = flag.String("auth-username", "", "proxy auth username")
	authPassword  = flag.String("auth-password", "", "proxy auth password")
	generateCA    = flag.Bool("generate-ca-cert", false, "generate CA certificate and private key for MITM")
	useLocalCA    = flag.Bool("use-local-ca-cert", false, "use local CA certificate and private key for MITM (~/.config/gomitmproxy)")
	cert          = flag.String("cert", "", "filepath to the CA certificate used to sign MITM certificates")
	key           = flag.String("key", "", "filepath to the private key of the CA used to sign MITM certificates")
	organization  = flag.String("organization", "Go Mitmproxy Proxy", "organization name for MITM certificates")
	validity      = flag.Duration("validity", time.Hour, "window of time that MITM certificates are valid")
	skipTLSVerify = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	dsProxyURL    = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
	level         = flag.Int("v", 0, "log level")

	// middlewares
	// kafka middleware
	kafkaBrokers = flag.String("kafka-brokers", "", "kafka brokers eg. localhost:9092,localhost:9092,localhost:9092")
	kafkaTopic   = flag.String("kafka-topic", "", "kafka topic")
	allowTlsUrls = flag.String("allow-tls-urls", "", "allow requests using tls protocol")
)

func main() {

	flag.Parse()
	mlog.SetLevel(*level)
	homeDir, _ := os.UserHomeDir()

	p := gomitmproxy.NewProxy()
	defer p.Close()

	p.Auth = &gomitmproxy.Auth{
		Username: *authUsername,
		Password: *authPassword,
	}

	if *allowTlsUrls != "" {
		p.AllowTlsUrls(strings.Split(*allowTlsUrls, ","))
	}

	// use middlewares
	if *kafkaBrokers != "" && *kafkaTopic != "" {
		p.Use(middlewares.NewKafkaMiddleware(*kafkaTopic, strings.Split(*kafkaBrokers, ","), p.GetAllowTlsUrls()))
	}

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("gomitmproxy: starting http proxy on %s, https proxy on %s, socks5 porxy on %s ", *addr, *tlsAddr, *socksAddr)

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *skipTLSVerify,
		},
	}
	p.SetRoundTripper(tr)

	if *dsProxyURL != "" {
		u, err := url.Parse(*dsProxyURL)
		if err != nil {
			log.Fatal(err)
		}
		p.SetDownstreamProxy(u)
		log.Printf("gomitmproxy: use downstream proxy: %s", *dsProxyURL)
	}

	var x509c *x509.Certificate
	var priv interface{}

	if *generateCA {
		var err error
		x509c, priv, err = mitm.NewAuthority("gomitmproxy.proxy", "Go Mitmproxy Authority", 30*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}
	} else if *cert != "" && *key != "" {
		tlsc, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	} else if *useLocalCA {
		certPath := filepath.Join(homeDir, ".config", "gomitmproxy")
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			log.Fatal(err)
		}
		certFile := filepath.Join(certPath, "mitmproxy-ca.cert")
		keyFile := filepath.Join(certPath, "mitmproxy-ca.key")
		log.Printf("gomitmproxy: use local ca cert: %s  %s", certFile, keyFile)
		tlsc, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey
		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	if x509c != nil && priv != nil {
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*validity)
		mc.SetOrganization(*organization)
		mc.SkipTLSVerify(*skipTLSVerify)

		p.SetMITM(mc)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *tlsAddr)
		if err != nil {
			log.Fatal(err)
		}

		go p.Serve(tls.NewListener(tl, mc.TLS()))
	}

	go p.Serve(l)
	go p.StartSocks5(*addr, *socksAddr)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	<-sigc

	log.Println("gomitmproxy: shutting down")
	os.Exit(0)
}
