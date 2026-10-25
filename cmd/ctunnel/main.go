// ctunnel is the management CLI: interactive menu, web panel and helper commands.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"ctunnel/pkg/catalog"
	"ctunnel/pkg/cli"
	"ctunnel/pkg/speedtest"
	"ctunnel/pkg/tunnel"
	"ctunnel/pkg/version"
	"ctunnel/pkg/webpanel"
)

func main() {
	if len(os.Args) < 2 {
		cli.RunInteractiveMenu()
		return
	}
	args := os.Args[2:]
	switch strings.ToLower(os.Args[1]) {
	case "menu":
		cli.RunInteractiveMenu()

	case "status", "list":
		cli.StatusTable()

	case "up", "restart", "down", "link":
		if len(args) != 1 {
			log.Fatalf("usage: ctunnel %s <name>", os.Args[1])
		}
		tunnelCommand(os.Args[1], args[0])

	case "apply-link":
		if len(args) != 1 {
			log.Fatal("usage: ctunnel apply-link 'ctunnel://...'")
		}
		applyLink(args[0])

	case "conntest":
		if len(args) != 1 {
			log.Fatal("usage: ctunnel conntest 'ctunnel-test://...'   (get the link with: ctunnel conntest-server on the iran server)")
		}
		if err := cli.RunConnTest(args[0]); err != nil {
			log.Fatal(err)
		}

	case "conntest-server":
		host := ""
		if len(args) > 0 {
			host = args[0]
		}
		cli.ConnTestServer(host)

	case "linktest":
		fs := flag.NewFlagSet("linktest", flag.ExitOnError)
		port := fs.Int("port", speedtest.DefaultSpeedPort, "responder port")
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			log.Fatal("usage: ctunnel linktest [-port N] <host>")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fmt.Print(speedtest.Format(speedtest.Run(ctx, net.JoinHostPort(fs.Arg(0), strconv.Itoa(*port)), 20)))

	case "speedtest-server":
		fs := flag.NewFlagSet("speedtest-server", flag.ExitOnError)
		port := fs.Int("port", speedtest.DefaultSpeedPort, "TCP port to listen on")
		_ = fs.Parse(args)
		addr, _, err := speedtest.StartServer(fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("link test responder listening on %s", addr)
		select {}

	case "catalog", "methods":
		for _, m := range catalog.Methods {
			fmt.Printf("%2d  %-13s %-10s %s\n", m.ID, m.Name, m.Family, m.Title)
		}

	case "panel":
		fs := flag.NewFlagSet("panel", flag.ExitOnError)
		port := fs.Int("port", 0, "listen port (default: the port saved in state.json)")
		_ = fs.Parse(args)
		st, err := catalog.LoadStore(cli.StoreDir)
		if err != nil {
			log.Fatal(err)
		}
		if *port == 0 {
			*port = st.PanelPort
		}
		srv := webpanel.NewServer(cli.StoreDir, fmt.Sprintf(":%d", *port))
		log.Printf("web panel on https://<server-ip>:%d", *port)
		log.Fatal(srv.ListenAndServeTLS())

	case "optimize":
		if err := tunnel.Optimize(); err != nil {
			log.Fatal(err)
		}

	case "version", "-v", "--version":
		fmt.Println("ctunnel", version.Version)

	default:
		fmt.Print(`Usage: ctunnel [command]

  (no command)                 interactive menu
  status                       tunnel table with state and traffic
  up|restart|down <name>       start, restart or stop a tunnel
  link <name>                  print the setup link for the other server
  apply-link 'ctunnel://...'   create and start the tunnel from a link
  conntest-server [ip]         iran side of the connection test: prints a link
  conntest 'ctunnel-test://…'  kharej side: which methods pass, speed, recommendation
  linktest [-port N] <host>    latency, loss and speed to <host>
  speedtest-server [-port N]   responder for linktest (default 7711/tcp)
  panel [-port N]              run the web panel in the foreground
  optimize                     apply BBR and buffer tuning
  catalog                      list tunnel methods
  version
`)
	}
}

func tunnelCommand(cmd, name string) {
	st, err := catalog.LoadStore(cli.StoreDir)
	if err != nil {
		log.Fatal(err)
	}
	tc, ok := st.Find(name)
	if !ok {
		log.Fatalf("tunnel %q not found", name)
	}
	switch cmd {
	case "up", "restart":
		err = tunnel.Apply(tc)
	case "down":
		_, err = tunnel.Run("systemctl", "stop", tunnel.Unit(tc))
	case "link":
		var link string
		link, err = catalog.EncodeSetupLink(tc)
		fmt.Println(link)
		if mk := tunnel.MikroTik(tc); mk != "" {
			fmt.Println("\n# MikroTik peer (RouterOS 7):\n" + mk)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

func applyLink(link string) {
	tc, err := catalog.DecodeSetupLink(link)
	if err != nil {
		log.Fatal(err)
	}
	st, err := catalog.LoadStore(cli.StoreDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := tunnel.Import(st, &tc); err != nil {
		log.Fatal(err)
	}
	if err := tunnel.Apply(tc); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("tunnel %s (%s) up: %s -> %s\n", tc.Name, tc.Method, tc.TunLocal4, tc.TunRemote4)
}
